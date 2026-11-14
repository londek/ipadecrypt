#include "spawn.h"
#include "exc.h"
#include "fs.h"
#include "log.h"
#include "mach_compat.h"
#include "target.h"

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/arm/thread_status.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

// ----- SBS launch via dlopen ------------------------------------------------

typedef const void *cf_string_t;
typedef const void *cf_type_t;
static cf_string_t (*CFStringCreateWithCString_)(void *, const char *, unsigned) = NULL;
static void (*CFRelease_)(cf_type_t) = NULL;
static int (*SBSLaunch_)(cf_string_t, unsigned char) = NULL;

static int load_sbs(void) {
    static int tried = 0;
    if (tried) return SBSLaunch_ ? 0 : -1;
    tried = 1;
    void *cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_NOW);
    void *sbs = dlopen("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_NOW);
    if (!cf || !sbs) {
        dbg("SBS unavailable (cf=%p sbs=%p)", cf, sbs);
        return -1;
    }
    CFStringCreateWithCString_ = dlsym(cf, "CFStringCreateWithCString");
    CFRelease_                 = dlsym(cf, "CFRelease");
    SBSLaunch_                 = dlsym(sbs, "SBSLaunchApplicationWithIdentifier");
    if (!CFStringCreateWithCString_ || !CFRelease_ || !SBSLaunch_) {
        wrn("SBS missing symbols");
        return -1;
    }
    return 0;
}

static pid_t find_pid_by_path(const char *exec_path, int ms_budget) {
    for (int slept = 0; slept < ms_budget; slept += 50) {
        int n = proc_listallpids(NULL, 0);
        if (n <= 0) { usleep(50 * 1000); continue; }
        pid_t *buf = malloc(n * sizeof(pid_t));
        if (!buf) return 0;
        int got = proc_listallpids(buf, n * sizeof(pid_t)) / sizeof(pid_t);
        for (int i = 0; i < got; i++) {
            char p[4096];
            if (proc_pidpath(buf[i], p, sizeof(p)) > 0 && fs_path_equiv(p, exec_path)) {
                pid_t pid = buf[i];
                free(buf);
                return pid;
            }
        }
        free(buf);
        usleep(50 * 1000);
    }
    return 0;
}

extern int csops(pid_t, unsigned int, void *, size_t);

static void emit_csflags(pid_t pid) {
    uint32_t csflags = 0;
    if (csops(pid, 0, &csflags, sizeof(csflags)) != 0) {
        attrs_t a; attrs_init(&a);
        attrs_int(&a, "pid", pid);
        attrs_int(&a, "err", errno);
        emit(LOG_DEBUG, "target.csflags", &a, NULL);
        return;
    }
    uint8_t cdh[20] = {0};
    csops(pid, 5, cdh, sizeof(cdh));
    char cdh_hex[41];
    for (int i = 0; i < 20; i++) snprintf(cdh_hex + i * 2, 3, "%02x", cdh[i]);
    attrs_t a; attrs_init(&a);
    attrs_int(&a, "pid", pid);
    attrs_hex(&a, "csflags", csflags);
    attrs_int(&a, "platform", !!(csflags & 0x04000000u));
    attrs_str(&a, "cdhash", cdh_hex);
    emit(LOG_DEBUG, "target.csflags", &a, NULL);
}

// Flip CS_DEBUGGED on an SBS-launched target via a debugger attach, so the
// cross-task writes dyld_patch makes to the target's (signed) dyld __TEXT
// pages don't trip code-signing enforcement when dyld later executes them.
//
// On strict-CS jailbreaks (checkm8 / rootless iOS 15.x) SBS apps run with
// CS_HARD|CS_KILL and no CS_DEBUGGED. target_patch_bytes does
// mprotect(RW|COPY)+write, which COW-forks an UNSIGNED copy of the page;
// the moment dyld executes any instruction on that page (e.g.
// mremap_encrypted during normal dependent loading) the kernel kills the
// process: SIGKILL CODESIGNING, "(Instruction Abort) Permission fault".
//
// PT_ATTACHEXC runs cs_allow_invalid() in the kernel: sets CS_DEBUGGED and
// clears CS_KILL/CS_HARD. The flag is sticky, so we attach, reap the stop,
// Mach-freeze, then detach - the target stays frozen (suspend count) while
// CS_DEBUGGED persists for the rest of the decrypt. No-op effect on
// Dopamine (iOS 16), which bypasses AMFI wholesale; failure here is
// non-fatal (decryption proceeds without CS_DEBUGGED).
static void cs_mark_debugged(task_t task, pid_t pid) {
    // Only strict-CS jailbreaks need this. When CS_HARD/CS_KILL are set
    // (checkm8 / palera1n iOS 15.x) executing a COW-modified dyld page is a
    // fatal CODESIGNING kill unless CS_DEBUGGED is set first. AMFI-bypass
    // jailbreaks (Dopamine iOS 16) leave those bits clear, so patched pages
    // run fine and the attach is pure risk: an SBS target is not our child
    // (its PT_ATTACHEXC stop is never reaped via waitpid) and the detach can
    // break xpcproxy's launch hand-off, killing the target before it runs a
    // single instruction - with no crash report. So skip it when CS
    // enforcement is lax.
    uint32_t pre = 0;
    if (csops(pid, 0 /*CS_OPS_STATUS*/, &pre, sizeof(pre)) == 0 &&
        !(pre & (CS_HARD | CS_KILL))) {
        attrs_t a; attrs_init(&a);
        attrs_hex(&a, "csflags", pre);
        attrs_int(&a, "debugged", !!(pre & CS_DEBUGGED));
        emit(LOG_DEBUG, "target.cs_debugged", &a,
             "CS enforcement lax (csflags=0x%x); debugger attach not needed",
             pre);
        return;
    }

    if (ptrace(PT_ATTACHEXC, pid, 0, 0) != 0) {
        dbg("PT_ATTACHEXC(%d): %s (CS_DEBUGGED unset; dyld patches may "
            "SIGKILL on strict-CS jailbreaks)", pid, strerror(errno));
        return;
    }
    // Reap the attach-stop. PT_ATTACHEXC's *initial* stop is signal-
    // delivered (only later exceptions go Mach), so waitpid sees it - but
    // bound the wait (~1s) with WNOHANG so a jailbreak that delivers it
    // differently can never hang the helper. CS_DEBUGGED is already set the
    // instant PT_ATTACHEXC returns, so timing out here is still safe.
    for (int i = 0; i < 100; i++) {
        pid_t w = waitpid(pid, NULL, WUNTRACED | WNOHANG);
        if (w == pid) break;
        if (w < 0 && errno != EINTR) break;
        usleep(10 * 1000);
    }
    // Freeze at the Mach level while still ptrace-stopped, then detach.
    // The suspend count keeps the target frozen after PT_DETACH would
    // otherwise let it run; CS_DEBUGGED survives the detach.
    task_suspend(task);
    ptrace(PT_DETACH, pid, 0, 0);

    // Confirm the flag actually flipped (CS_DEBUGGED = 0x10000000). This is
    // the per-jailbreak ground truth: "set" => dyld patching is safe here;
    // "NOT set" + a strict-CS jb => expect SIGKILL CODESIGNING (Dopamine
    // bypasses AMFI so it works regardless).
    uint32_t csflags = 0;
    int debugged = csops(pid, 0 /*CS_OPS_STATUS*/, &csflags, sizeof(csflags)) == 0 &&
                   (csflags & CS_DEBUGGED);
    attrs_t a; attrs_init(&a);
    attrs_int(&a, "pid", pid);
    attrs_hex(&a, "csflags", csflags);
    attrs_int(&a, "debugged", debugged);
    emit(LOG_DEBUG, "target.cs_debugged", &a,
         "CS_DEBUGGED %s (pid=%d csflags=0x%x)",
         debugged ? "set" : "NOT-set", pid, csflags);
}

static int sbs_launch(const char *bundle_id, const char *exec_path,
                      pid_t *out_pid, task_t *out_task) {
    if (load_sbs() != 0) return -1;
    cf_string_t bid = CFStringCreateWithCString_(NULL, bundle_id, 0x08000100);
    if (!bid) return -1;
    int rc = SBSLaunch_(bid, 1);
    CFRelease_(bid);
    if (rc != 0) {
        dbg("SBSLaunch(%s)=%d", bundle_id, rc);
        return -1;
    }
    pid_t pid = find_pid_by_path(exec_path, 2000);
    if (pid == 0) { dbg("SBS launch produced no pid"); return -1; }
    task_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) {
        dbg("task_for_pid(%d) after SBS failed", pid);
        kill(pid, SIGKILL);
        return -1;
    }
    // Attach as debugger to flip CS_DEBUGGED (lets us patch dyld __TEXT
    // without a CODESIGNING kill on strict-CS jailbreaks). This also
    // Mach-suspends the task while stopped; SBS's suspended:1 relies on
    // xpcproxy's "not ready" signal, not an observable task_suspend, so we
    // freeze the task ourselves anyway for a stable address space.
    cs_mark_debugged(task, pid);
    task_suspend(task);
    *out_pid = pid;
    *out_task = task;
    emit_csflags(pid);
    return 0;
}

// ----- PT_TRACE_ME spawn ----------------------------------------------------

// Used for .appex bundles (SBS won't launch them by id) and as a
// fallback when SBS rejects a main app (e.g. cross-SDK reject on
// iOS 16 for iOS 18-SDK binaries). The caller (decrypt_bundle) vm_reads
// the main exec at the PT_ATTACHEXC stop and terminates without ever
// resuming, so we don't need to mark the target debugged  it never
// runs a single instruction past exec.
static int do_ptrace_spawn(const char *exec_path, pid_t *out_pid) {
    pid_t pid = fork();
    if (pid < 0) { er("fork: %s", strerror(errno)); return -1; }
    if (pid == 0) {
        if (ptrace(PT_TRACE_ME, 0, NULL, 0) != 0) _exit(127);
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) { dup2(dn, 0); dup2(dn, 1); dup2(dn, 2); close(dn); }
        char *argv[] = { (char *)exec_path, NULL };
        execve(exec_path, argv, environ);
        _exit(127);
    }
    int status;
    pid_t w;
    do { w = waitpid(pid, &status, WUNTRACED); } while (w < 0 && errno == EINTR);
    if (w < 0 || WIFEXITED(status) || WIFSIGNALED(status)) {
        er("child died during exec of %s (status=0x%x)", exec_path, status);
        return -1;
    }
    *out_pid = pid;
    return 0;
}

// ----- Main entry points -----------------------------------------------------

int spawn_find_main_name(const char *bundle, char *out, size_t cap) {
    char base[1024];
    strncpy(base, bundle, sizeof(base) - 1); base[sizeof(base) - 1] = '\0';
    char *slash = strrchr(base, '/');
    const char *name = slash ? slash + 1 : base;
    char cand[4096];
    snprintf(cand, sizeof(cand), "%s/%s", bundle, name);
    char *dot = strrchr(cand, '.');
    if (dot && (strcmp(dot, ".app") == 0 || strcmp(dot, ".appex") == 0)) *dot = '\0';
    if (fs_is_macho(cand)) {
        const char *bn = strrchr(cand, '/'); bn = bn ? bn + 1 : cand;
        strncpy(out, bn, cap - 1); out[cap - 1] = '\0';
        return 0;
    }
    DIR *d = opendir(bundle);
    if (!d) return -1;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        char p[4096]; snprintf(p, sizeof(p), "%s/%s", bundle, e->d_name);
        struct stat st;
        if (lstat(p, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        if (fs_is_macho(p)) {
            strncpy(out, e->d_name, cap - 1); out[cap - 1] = '\0';
            closedir(d);
            return 0;
        }
    }
    closedir(d);
    return -1;
}

int spawn_suspended(const char *bundle_id, const char *exec_path,
                    pid_t *out_pid, task_t *out_task, int *out_ptrace) {
    *out_ptrace = 0;
    fs_ensure_executable(exec_path);

    if (bundle_id && bundle_id[0]) {
        if (sbs_launch(bundle_id, exec_path, out_pid, out_task) == 0) {
            attrs_t a; attrs_init(&a);
            attrs_str(&a, "method", "sbs");
            attrs_str(&a, "bundle_id", bundle_id);
            attrs_int(&a, "pid", *out_pid);
            emit(LOG_INFO, "target.spawned", &a,
                 "spawned %s via SBS (pid=%d)", bundle_id, *out_pid);
            return 0;
        }
        attrs_t a; attrs_init(&a);
        attrs_str(&a, "bundle_id", bundle_id);
        emit(LOG_WARN, "target.spawn.fallback", &a,
             "SBS rejected %s, trying ptrace", bundle_id);
    }

    pid_t pid = 0;
    if (do_ptrace_spawn(exec_path, &pid) != 0) {
        attrs_t a; attrs_init(&a);
        attrs_str(&a, "exec", exec_path);
        emit(LOG_ERROR, "target.spawn.failed", &a,
             "ptrace spawn of %s failed", exec_path);
        return -1;
    }
    task_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        er("task_for_pid(%d) after PT_TRACE_ME: %d", pid, kr);
        kill(pid, SIGKILL);
        return -1;
    }
    *out_ptrace = 1;
    *out_pid = pid;
    *out_task = task;
    attrs_t a; attrs_init(&a);
    attrs_str(&a, "method", "ptrace");
    attrs_str(&a, "exec", exec_path);
    attrs_int(&a, "pid", pid);
    emit(LOG_INFO, "target.spawned", &a,
         "spawned %s via ptrace (pid=%d)", exec_path, pid);
    return 0;
}

// ----- run + suspend with fault recovery -------------------------------------

static int dyld_pac_strip_or_skip(task_t task,
                                  arm_thread_state64_t *fs,
                                  mach_msg_type_number_t fsc,
                                  mach_msg_header_t *exc_hdr,
                                  int *skips_done,
                                  int *pac_strips_done,
                                  uint64_t fault_va) {
    // T8030 user space is 47-bit; any bit above is PAC residue from a
    // failed BLRAA/BRAA/RETAB authentication. XPACI inverts the
    // auth-fail XOR and strips PAC, recovering the bare target VA.
    int is_pac_trap = (fs->__pc >> 47) != 0;
    if (is_pac_trap) {
        register uint64_t xpaci_in asm("x0") = (uint64_t)fs->__pc;
        __asm__ volatile(".inst 0xDAC143E0" : "+r"(xpaci_in));
        uint64_t stripped = xpaci_in;
        attrs_t a; attrs_init(&a);
        attrs_int(&a, "n", *pac_strips_done);
        attrs_hex(&a, "pc", (unsigned long long)fs->__pc);
        attrs_hex(&a, "stripped", (unsigned long long)stripped);
        attrs_hex(&a, "fault", (unsigned long long)fault_va);
        emit(LOG_DEBUG, "dyld.pac_stripped", &a, NULL);
        fs->__pc = stripped;
        if (thread_set_state(g_pending_exc_thread, ARM_THREAD_STATE64,
                (thread_state_t)fs, fsc) != KERN_SUCCESS) return -1;
        if (exc_reply_with_state(exc_hdr, fs) != MACH_MSG_SUCCESS) return -1;
        exc_clear_pending();
        (*pac_strips_done)++;
        (*skips_done)++;
        return 0;
    }
    // Non-PAC: NOP the faulting insn, advance PC.
    static const uint32_t nop_op = 0xd503201fu;
    char tag[64];
    snprintf(tag, sizeof(tag), "dyld_fault_skip_%d", *skips_done);
    target_patch_bytes(task, fs->__pc, &nop_op, sizeof(nop_op), tag);
    fs->__pc += 4;
    if (thread_set_state(g_pending_exc_thread, ARM_THREAD_STATE64,
            (thread_state_t)fs, fsc) != KERN_SUCCESS) return -1;
    if (exc_reply_with_state(exc_hdr, fs) != MACH_MSG_SUCCESS) return -1;
    exc_clear_pending();
    (*skips_done)++;
    attrs_t a; attrs_init(&a);
    attrs_int(&a, "n", *skips_done);
    attrs_hex(&a, "pc", (unsigned long long)(fs->__pc - 4));
    attrs_hex(&a, "fault", (unsigned long long)fault_va);
    emit(LOG_DEBUG, "dyld.fault_skip", &a, NULL);
    return 0;
}

void spawn_run_and_suspend(task_t task, mach_port_t exc_port, int ms) {
    exc_clear_pending();
    {
        attrs_t a; attrs_init(&a);
        attrs_int(&a, "ms", ms);
        emit(LOG_DEBUG, "dyld.resuming", &a, "resuming target (wait ≤%dms)", ms);
    }
    while (task_resume(task) == KERN_SUCCESS) { /* drain */ }

    struct { mach_msg_header_t hdr; char body[2048]; } msg;
    int waited = 0;
    int trapped = 0;
    int exc = 0, sig = 0;
    int64_t c0 = 0, c1 = 0;

    while (waited < ms) {
        memset(&msg, 0, sizeof(msg));
        mach_msg_return_t mr = mach_msg(&msg.hdr,
            MACH_RCV_MSG | MACH_RCV_TIMEOUT,
            0, sizeof(msg), exc_port, 200, MACH_PORT_NULL);
        if (mr == MACH_MSG_SUCCESS) {
            trapped = 1;
            exc_decode(&msg, msg.hdr.msgh_size, &exc, &c0, &c1, &sig, NULL);
            exc_clear_pending();
            g_pending_exc_hdr = msg.hdr;
            g_pending_exc_valid = 1;
            g_pending_exc_thread = exc_extract_thread(&msg, msg.hdr.msgh_size);
            exc_release_msg_ports(&msg, msg.hdr.msgh_size);
            break;
        }
        waited += 200;
    }

    if (trapped) {
        // Fault-skip + PAC-strip recovery loop. Only enabled when our
        // resolveSymbol force-weak patch fired (iOS 15+ cross-OS).
        int skips_done = 0, pac_strips_done = 0;
        uint64_t last_skip_pc = 0;
        while (g_dyld_force_weak_active && exc == EXC_BAD_ACCESS && skips_done < 64) {
            arm_thread_state64_t fs = {0};
            mach_msg_type_number_t fsc = ARM_THREAD_STATE64_COUNT;
            if (g_pending_exc_thread == MACH_PORT_NULL) break;
            if (thread_get_state(g_pending_exc_thread, ARM_THREAD_STATE64,
                    (thread_state_t)&fs, &fsc) != KERN_SUCCESS) break;
            if (fs.__pc == 0 || fs.__pc == last_skip_pc) break;
            last_skip_pc = fs.__pc;

            if (dyld_pac_strip_or_skip(task, &fs, fsc, &msg.hdr,
                                       &skips_done, &pac_strips_done,
                                       (uint64_t)c1) != 0) break;

            memset(&msg, 0, sizeof(msg));
            mach_msg_return_t mr2 = mach_msg(&msg.hdr,
                MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(msg),
                exc_port, 5000, MACH_PORT_NULL);
            if (mr2 != MACH_MSG_SUCCESS) { exc = 0; break; }
            exc_decode(&msg, msg.hdr.msgh_size, &exc, &c0, &c1, &sig, NULL);
            exc_clear_pending();
            g_pending_exc_hdr = msg.hdr;
            g_pending_exc_valid = 1;
            g_pending_exc_thread = exc_extract_thread(&msg, msg.hdr.msgh_size);
            exc_release_msg_ports(&msg, msg.hdr.msgh_size);
        }

        uint64_t fault_pc = 0;
        if (g_pending_exc_thread != MACH_PORT_NULL) {
            arm_thread_state64_t fs = {0};
            mach_msg_type_number_t fsc = ARM_THREAD_STATE64_COUNT;
            if (thread_get_state(g_pending_exc_thread, ARM_THREAD_STATE64,
                    (thread_state_t)&fs, &fsc) == KERN_SUCCESS) {
                fault_pc = (uint64_t)fs.__pc;
            }
        }

        attrs_t a; attrs_init(&a);
        attrs_str(&a, "exception", exc_tag(exc));
        attrs_hex(&a, "code0", (unsigned long long)c0);
        attrs_hex(&a, "code1", (unsigned long long)c1);
        attrs_int(&a, "signal", sig);
        attrs_hex(&a, "pc", (unsigned long long)fault_pc);
        attrs_int(&a, "fault_skips", skips_done);
        attrs_int(&a, "pac_strips", pac_strips_done);
        emit(LOG_INFO, "dyld.trapped", &a,
             "target trapped: %s (skips=%d pac_strips=%d)",
             exc_tag(exc), skips_done, pac_strips_done);

        // Leave brk unreplied so kernel keeps the thread paused with
        // full task memory mapped for vm_read.
    } else {
        emit(LOG_DEBUG, "dyld.settled", NULL, NULL);
    }
    task_suspend(task);
}
