// ipadecrypt-helper-arm64
//
// On-device FairPlay decrypter. Launches a target .app bundle suspended,
// reads its cryptoff pages via mach_vm_read_overwrite (kernel decrypts on
// page fault), and writes a decrypted IPA. Does the same for every
// PlugIns/*.appex and Extensions/*.appex in the bundle.
//
// CLI: ipadecrypt-helper-arm64 <bundle-id> <bundle-src> <out-ipa>
//   bundle-id  — CFBundleIdentifier of the main app, or "" to skip the main
//                app pass. Used for SpringBoard's SBSLaunch SPI which is the
//                only way to spawn cross-OS binaries on Dopamine.
//   bundle-src — absolute path to the installed .app on disk
//   out-ipa    — absolute path to write the decrypted IPA to
//
// Spawn-path selection (best-to-worst AMFI tolerance):
//   1. SBSLaunchApplicationWithIdentifier(bundle-id, suspended=1)
//      SpringBoard spawns the target for us. Its process is CS_PLATFORM_BINARY
//      so its posix_spawn satisfies AMFI's minOS check even for iOS-18/26
//      binaries on iOS-16. Only works when bundle-id is registered with
//      LaunchServices — main apps only; appexes return kSBSError(7).
//   2. posix_spawn(POSIX_SPAWN_START_SUSPENDED)
//      Works for same-OS binaries; Dopamine AMFI SIGKILLs cross-OS ones in
//      kernel before we get back the task port.
//   3. fork() + ptrace(PT_TRACE_ME) + execve()
//      Sets P_TRACED before exec; AMFI treats it as under-debug and skips the
//      minOS check. Resumes via PT_CONTINUE rather than task_resume.

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <dlfcn.h>
#include <signal.h>
#include <spawn.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/dyld_images.h>
#include <mach/mach.h>
#include <mach/vm_region.h>
#include <mach/exception_types.h>
#include <mach/thread_status.h>

// ----- SDK-missing SPI forward decls -----------------------------------

// mach_vm is "unsupported" in iOS SDK headers; syscalls exist at runtime.
typedef uint64_t mach_vm_address_t;
typedef uint64_t mach_vm_size_t;
extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t,
    mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
extern kern_return_t mach_vm_region(vm_map_t, mach_vm_address_t *,
    mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t,
    mach_msg_type_number_t *, mach_port_t *);

// libproc SPI — not in iOS SDK.
extern int proc_listallpids(void *, int);
extern int proc_pidpath(int, void *, uint32_t);

// ptrace — sys/ptrace.h is iOS-hidden. We only need these two requests.
#ifndef PT_TRACE_ME
#define PT_TRACE_ME 0
#endif
#ifndef PT_CONTINUE
#define PT_CONTINUE 7
#endif
extern int ptrace(int request, pid_t pid, void *addr, int data);

extern char **environ;

#ifndef LC_ENCRYPTION_INFO
#define LC_ENCRYPTION_INFO 0x21
#endif
#ifndef LC_ENCRYPTION_INFO_64
#define LC_ENCRYPTION_INFO_64 0x2C
#endif

// ----- logging ---------------------------------------------------------

static int g_verbose = 0;

#define LOG(...) do { if (g_verbose) fprintf(stderr, __VA_ARGS__); } while (0)
#define ERR(fmt, ...) fprintf(stderr, "[helper] ERROR: " fmt "\n", ##__VA_ARGS__)
#define EVT(fmt, ...) do { fprintf(stdout, "@evt " fmt "\n", ##__VA_ARGS__); fflush(stdout); } while (0)

// ----- Mach-O encryption info parsing ---------------------------------

typedef struct {
    off_t slice_offset;             // offset within file (thin: 0, fat: slice start)
    uint32_t cryptoff;              // offset from slice start to encrypted pages
    uint32_t cryptsize;
    uint32_t cputype, cpusubtype;
    off_t cryptid_file_offset;      // absolute byte offset of cryptid field in file
} encinfo_t;

static uint32_t bswap32(uint32_t x) {
    return ((x & 0xff) << 24) | ((x & 0xff00) << 8) |
           ((x & 0xff0000) >> 8) | ((x & 0xff000000) >> 24);
}

// Fill `out` for the first slice with LC_ENCRYPTION_INFO{_64} cryptid != 0.
// Returns 1 encrypted, 0 not encrypted / not Mach-O, -1 on error.
static int parse_slice(const uint8_t *slice, size_t slice_len, off_t slice_off, encinfo_t *out) {
    if (slice_len < sizeof(struct mach_header)) return 0;
    struct mach_header mh;
    memcpy(&mh, slice, sizeof(mh));

    int is_64;
    size_t hdr_sz;
    uint32_t ncmds, szcmds;
    if (mh.magic == MH_MAGIC_64) {
        struct mach_header_64 mh64;
        memcpy(&mh64, slice, sizeof(mh64));
        is_64 = 1;
        ncmds = mh64.ncmds; szcmds = mh64.sizeofcmds; hdr_sz = sizeof(mh64);
        out->cputype = mh64.cputype; out->cpusubtype = mh64.cpusubtype;
    } else if (mh.magic == MH_MAGIC) {
        is_64 = 0;
        ncmds = mh.ncmds; szcmds = mh.sizeofcmds; hdr_sz = sizeof(mh);
        out->cputype = mh.cputype; out->cpusubtype = mh.cpusubtype;
    } else {
        return 0;
    }
    if (hdr_sz + szcmds > slice_len) return -1;

    const uint8_t *lc_ptr = slice + hdr_sz;
    for (uint32_t i = 0; i < ncmds; i++) {
        struct load_command lc;
        memcpy(&lc, lc_ptr, sizeof(lc));
        if (lc.cmdsize == 0) return -1;
        if ((size_t)((lc_ptr - slice) + lc.cmdsize) > hdr_sz + szcmds) return -1;

        int want = (is_64 && lc.cmd == LC_ENCRYPTION_INFO_64) ||
                   (!is_64 && lc.cmd == LC_ENCRYPTION_INFO);
        if (want) {
            struct encryption_info_command eic;
            memcpy(&eic, lc_ptr, sizeof(eic));
            if (eic.cryptid == 0) return 0;
            out->slice_offset = slice_off;
            out->cryptoff = eic.cryptoff;
            out->cryptsize = eic.cryptsize;
            out->cryptid_file_offset = slice_off + (lc_ptr - slice) +
                offsetof(struct encryption_info_command, cryptid);
            return 1;
        }
        lc_ptr += lc.cmdsize;
    }
    return 0;
}

// Parse Mach-O (thin or fat) at path. Returns same as parse_slice.
static int parse_macho(const char *path, encinfo_t *out) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }
    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return -1;

    int rc = 0;
    const uint8_t *base = map;
    if ((size_t)st.st_size >= 4) {
        uint32_t magic; memcpy(&magic, base, 4);
        if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
            int swap = (magic == FAT_CIGAM);
            struct fat_header fh; memcpy(&fh, base, sizeof(fh));
            uint32_t nfat = swap ? bswap32(fh.nfat_arch) : fh.nfat_arch;
            for (uint32_t i = 0; i < nfat; i++) {
                struct fat_arch fa;
                memcpy(&fa, base + sizeof(struct fat_header) + i * sizeof(struct fat_arch),
                       sizeof(fa));
                uint32_t off = swap ? bswap32(fa.offset) : fa.offset;
                uint32_t sz = swap ? bswap32(fa.size) : fa.size;
                if ((size_t)(off + sz) > (size_t)st.st_size) { rc = -1; break; }
                rc = parse_slice(base + off, sz, off, out);
                if (rc == 1) break;
            }
        } else {
            rc = parse_slice(base, st.st_size, 0, out);
        }
    }
    munmap(map, st.st_size);
    return rc;
}

static int is_macho(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    uint32_t m = 0;
    ssize_t n = read(fd, &m, sizeof(m));
    close(fd);
    return n == sizeof(m) &&
        (m == MH_MAGIC || m == MH_MAGIC_64 || m == FAT_CIGAM || m == FAT_MAGIC);
}

// ----- filesystem helpers ---------------------------------------------

// mkdir -p for absolute paths.
static int mkdirs(const char *path) {
    char buf[4096];
    strncpy(buf, path, sizeof(buf) - 1); buf[sizeof(buf) - 1] = '\0';
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(buf, 0755);
            *p = '/';
        }
    }
    mkdir(buf, 0755);
    return 0;
}

static int rm_rf(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
        DIR *d = opendir(path);
        if (d) {
            struct dirent *e;
            while ((e = readdir(d))) {
                if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
                char sub[4096];
                snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name);
                rm_rf(sub);
            }
            closedir(d);
        }
        return rmdir(path);
    }
    return unlink(path);
}

static int copy_file(const char *src, const char *dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    struct stat st;
    if (fstat(in, &st) != 0) { close(in); return -1; }
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode & 0777);
    if (out < 0) { close(in); return -1; }
    char buf[64 * 1024];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        if (write(out, buf, n) != n) { close(in); close(out); return -1; }
    }
    close(in); close(out);
    return n < 0 ? -1 : 0;
}

static int copy_tree(const char *src, const char *dst) {
    struct stat st;
    if (lstat(src, &st) != 0) return -1;
    if (S_ISLNK(st.st_mode)) {
        char target[4096];
        ssize_t n = readlink(src, target, sizeof(target) - 1);
        if (n < 0) return -1;
        target[n] = '\0';
        return symlink(target, dst) == 0 ? 0 : -1;
    }
    if (S_ISDIR(st.st_mode)) {
        mkdir(dst, st.st_mode & 0777);
        DIR *d = opendir(src);
        if (!d) return -1;
        struct dirent *e;
        int rc = 0;
        while ((e = readdir(d))) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
            char s[4096], t[4096];
            snprintf(s, sizeof(s), "%s/%s", src, e->d_name);
            snprintf(t, sizeof(t), "%s/%s", dst, e->d_name);
            if (copy_tree(s, t) != 0) rc = -1;
        }
        closedir(d);
        return rc;
    }
    return copy_file(src, dst);
}

// ----- libjailbreak bridge (Dopamine trustcache) ----------------------

static int (*g_trust_file_by_path)(const char *) = NULL;

static void load_libjailbreak(void) {
    static int tried = 0;
    if (tried) return;
    tried = 1;
    void *h = dlopen("/var/jb/basebin/libjailbreak.dylib", RTLD_NOW);
    if (!h) {
        LOG("[helper] libjailbreak unavailable: %s\n", dlerror());
        return;
    }
    g_trust_file_by_path = dlsym(h, "jbclient_trust_file_by_path");
}

// Walk bundle, trust-cache every Mach-O. Cross-OS frameworks need this to
// survive AMFI library_validation when dyld maps them in the target.
static void trust_walk(const char *root) {
    load_libjailbreak();
    if (!g_trust_file_by_path) return;
    DIR *d = opendir(root);
    if (!d) return;
    struct dirent *e;
    int n = 0;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        char p[4096]; snprintf(p, sizeof(p), "%s/%s", root, e->d_name);
        struct stat st;
        if (lstat(p, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            trust_walk(p);
        } else if (S_ISREG(st.st_mode) && is_macho(p)) {
            if (g_trust_file_by_path(p) == 0) n++;
        }
    }
    closedir(d);
    if (n > 0) LOG("[helper] trusted %d file(s) under %s\n", n, root);
}

// ----- SBS launch (via dlopen to avoid build-time framework link) -----

// SDK Dockerfile drops System/Library/Frameworks. dlopen CoreFoundation +
// SpringBoardServices at runtime so we don't need -framework flags.

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
        LOG("[helper] SBS unavailable (cf=%p sbs=%p)\n", cf, sbs);
        return -1;
    }
    CFStringCreateWithCString_ = dlsym(cf, "CFStringCreateWithCString");
    CFRelease_ = dlsym(cf, "CFRelease");
    SBSLaunch_ = dlsym(sbs, "SBSLaunchApplicationWithIdentifier");
    if (!CFStringCreateWithCString_ || !CFRelease_ || !SBSLaunch_) {
        LOG("[helper] SBS missing symbols\n");
        return -1;
    }
    return 0;
}

// Tolerate proc_pidpath's /private prefix when comparing to input paths.
static int path_equiv(const char *a, const char *b) {
    if (strcmp(a, b) == 0) return 1;
    const char *pre = "/private";
    size_t plen = strlen(pre);
    if (strncmp(a, pre, plen) == 0 && strcmp(a + plen, b) == 0) return 1;
    if (strncmp(b, pre, plen) == 0 && strcmp(b + plen, a) == 0) return 1;
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
            if (proc_pidpath(buf[i], p, sizeof(p)) > 0 && path_equiv(p, exec_path)) {
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

// Ask SpringBoard to launch bundle_id suspended. SpringBoard's posix_spawn
// runs in its CS_PLATFORM_BINARY context, which is the only thing Dopamine's
// unpatched AMFI lets through for cross-OS main binaries.
static int sbs_launch(const char *bundle_id, const char *exec_path,
                      pid_t *out_pid, task_t *out_task) {
    if (load_sbs() != 0) return -1;
    cf_string_t bid = CFStringCreateWithCString_(NULL, bundle_id, 0x08000100 /* kCFStringEncodingUTF8 */);
    if (!bid) return -1;
    int rc = SBSLaunch_(bid, 1 /* suspended */);
    CFRelease_(bid);
    if (rc != 0) {
        LOG("[helper] SBSLaunch(%s)=%d\n", bundle_id, rc);
        return -1;
    }
    pid_t pid = find_pid_by_path(exec_path, 4000);
    if (pid == 0) { LOG("[helper] SBS launch did not produce a pid\n"); return -1; }
    task_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) {
        LOG("[helper] task_for_pid(%d) after SBS failed\n", pid);
        kill(pid, SIGKILL);
        return -1;
    }
    // SBS's suspended:1 relies on xpcproxy's "not ready" signal, not a real
    // task_suspend we can observe — by the time we grab the task, dyld may
    // be running. Freeze it ourselves so the address space is stable.
    task_suspend(task);
    *out_pid = pid;
    *out_task = task;
    LOG("[helper] SBS spawned %s pid=%d\n", bundle_id, pid);
    return 0;
}

// ----- posix_spawn + PT_TRACE_ME fallback -----------------------------

static int do_posix_spawn(const char *exec_path, pid_t *out_pid) {
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    char *argv[] = { (char *)exec_path, NULL };
    pid_t pid = 0;
    int rc = posix_spawn(&pid, exec_path, &fa, &attr, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&attr);
    if (rc == 0) *out_pid = pid;
    return rc;
}

// Cross-OS fallback: fork, child PT_TRACE_ME + execve. P_TRACED is set in
// proc BEFORE exec, so AMFI's post-exec check treats the child as
// under-debug and skips the minOS SIGKILL.
static int do_ptrace_spawn(const char *exec_path, pid_t *out_pid) {
    pid_t pid = fork();
    if (pid < 0) { ERR("fork: %s", strerror(errno)); return -1; }
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
        ERR("child died during exec of %s (status=0x%x)", exec_path, status);
        return -1;
    }
    *out_pid = pid;
    return 0;
}

// Some installed extensions ship mode 0644 because iOS loads them through
// ExtensionKit rather than execve. posix_spawn / execve from our helper both
// require +x, so stamp it on ahead of any spawn attempt. We run as root via
// sudo so chmod is always allowed.
static void ensure_executable(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return;
    mode_t want = st.st_mode | S_IXUSR | S_IXGRP | S_IXOTH;
    if (want == st.st_mode) return;
    if (chmod(path, want) == 0) {
        EVT("event=spawn_chmod path=\"%s\" old_mode=%o", path, st.st_mode & 0777);
    }
}

// Unified spawn. Returns 0 on success, fills out_pid/out_task. *out_ptrace
// is set to 1 iff the PT_TRACE_ME fallback was taken; caller must resume
// via PT_CONTINUE in that case.
static int spawn_suspended(const char *bundle_id, const char *exec_path,
                           pid_t *out_pid, task_t *out_task, int *out_ptrace) {
    *out_ptrace = 0;
    ensure_executable(exec_path);
    if (bundle_id && bundle_id[0]) {
        if (sbs_launch(bundle_id, exec_path, out_pid, out_task) == 0) {
            return 0;
        }
        EVT("event=spawn_path_fallback from=sbs exec=\"%s\"", exec_path);
    }
    pid_t pid = 0;
    task_t task = MACH_PORT_NULL;
    int rc = do_posix_spawn(exec_path, &pid);
    kern_return_t kr = KERN_FAILURE;
    if (rc == 0) kr = task_for_pid(mach_task_self(), pid, &task);
    if (rc != 0 || kr != KERN_SUCCESS) {
        if (rc == 0) kill(pid, SIGKILL);
        LOG("[helper] posix_spawn=%d tfp=%d, trying PT_TRACE_ME\n", rc, kr);
        EVT("event=spawn_path_fallback from=posix_spawn exec=\"%s\" posix_rc=%d tfp=%d",
            exec_path, rc, kr);
        if (do_ptrace_spawn(exec_path, &pid) != 0) return -1;
        *out_ptrace = 1;
        kr = task_for_pid(mach_task_self(), pid, &task);
        if (kr != KERN_SUCCESS) {
            ERR("task_for_pid(%d) after PT_TRACE_ME: %d", pid, kr);
            kill(pid, SIGKILL);
            return -1;
        }
        EVT("event=spawn_path path=ptrace exec=\"%s\"", exec_path);
    }
    *out_pid = pid;
    *out_task = task;
    return 0;
}

// ----- target-task image discovery ------------------------------------

// Locate the main MH_EXECUTE base by walking VM regions.
static int find_main_base(task_t task, mach_vm_address_t *out) {
    mach_vm_address_t addr = 0;
    for (;;) {
        mach_vm_size_t sz = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        if (mach_vm_region(task, &addr, &sz, VM_REGION_BASIC_INFO_64,
                (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) return -1;
        struct mach_header_64 hdr;
        mach_vm_size_t n = 0;
        if (mach_vm_read_overwrite(task, addr, sizeof(hdr),
                (mach_vm_address_t)(uintptr_t)&hdr, &n) == KERN_SUCCESS &&
            n == sizeof(hdr) &&
            (hdr.magic == MH_MAGIC_64 || hdr.magic == MH_MAGIC) &&
            hdr.filetype == MH_EXECUTE) {
            *out = addr;
            return 0;
        }
        addr += sz;
    }
}

// Enumerate images loaded in target via TASK_DYLD_INFO. Writes count of
// images into *out_count and returns a heap-allocated infoArray + path
// strings buffer (caller frees). Returns NULL on error.
static struct dyld_image_info *list_images(task_t task, uint32_t *out_count,
                                            char **out_paths) {
    struct task_dyld_info tdi;
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&tdi, &cnt) != KERN_SUCCESS)
        return NULL;
    struct dyld_all_image_infos aii;
    mach_vm_size_t n = 0;
    if (mach_vm_read_overwrite(task, tdi.all_image_info_addr, sizeof(aii),
            (mach_vm_address_t)(uintptr_t)&aii, &n) != KERN_SUCCESS) return NULL;
    if (aii.infoArrayCount == 0 || aii.infoArray == NULL) return NULL;

    size_t arr_sz = sizeof(struct dyld_image_info) * aii.infoArrayCount;
    struct dyld_image_info *infos = malloc(arr_sz);
    if (!infos) return NULL;
    if (mach_vm_read_overwrite(task, (mach_vm_address_t)aii.infoArray, arr_sz,
            (mach_vm_address_t)(uintptr_t)infos, &n) != KERN_SUCCESS) {
        free(infos); return NULL;
    }

    // Read each image's path into one big buffer; rewrite imageFilePath to
    // point inside it so the caller can use pointers directly.
    size_t path_cap = aii.infoArrayCount * 4096;
    char *paths = malloc(path_cap);
    if (!paths) { free(infos); return NULL; }
    size_t off = 0;
    for (uint32_t i = 0; i < aii.infoArrayCount; i++) {
        char *slot = paths + off;
        if (off + 4096 > path_cap) { infos[i].imageFilePath = NULL; continue; }
        mach_vm_size_t got = 0;
        if (mach_vm_read_overwrite(task, (mach_vm_address_t)infos[i].imageFilePath,
                4095, (mach_vm_address_t)(uintptr_t)slot, &got) == KERN_SUCCESS && got > 0) {
            slot[got < 4095 ? got : 4094] = '\0';
            // Re-terminate defensively at first NUL we already got.
            size_t len = strnlen(slot, got);
            slot[len] = '\0';
            infos[i].imageFilePath = slot;
            off += len + 1;
        } else {
            infos[i].imageFilePath = NULL;
        }
    }
    *out_count = aii.infoArrayCount;
    *out_paths = paths;
    return infos;
}

// ----- dump an encrypted image ----------------------------------------

// Read cryptsize bytes at image_base+cryptoff from target, splice onto a
// copy of the source file's bytes, zero cryptid, write to dst.
static int dump_image(const char *src, const char *dst, task_t task,
                      mach_vm_address_t image_base, const encinfo_t *info) {
    int fd = open(src, O_RDONLY);
    if (fd < 0) { ERR("open %s: %s", src, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }
    uint8_t *buf = malloc(st.st_size);
    if (!buf) { close(fd); return -1; }
    if (read(fd, buf, st.st_size) != st.st_size) {
        ERR("read %s: %s", src, strerror(errno));
        free(buf); close(fd); return -1;
    }
    close(fd);

    // Read decrypted pages from the target task, splice over the encrypted
    // bytes in the file-image buffer.
    mach_vm_address_t src_addr = image_base + info->cryptoff;
    mach_vm_address_t dst_addr = (mach_vm_address_t)(uintptr_t)(buf + info->slice_offset + info->cryptoff);
    mach_vm_size_t remaining = info->cryptsize;
    while (remaining > 0) {
        mach_vm_size_t chunk = remaining > 0x100000 ? 0x100000 : remaining;
        mach_vm_size_t got = 0;
        kern_return_t kr = mach_vm_read_overwrite(task, src_addr, chunk, dst_addr, &got);
        if (kr != KERN_SUCCESS || got == 0) {
            ERR("mach_vm_read @0x%llx size=0x%llx kr=%d", src_addr, chunk, kr);
            free(buf); return -1;
        }
        src_addr += got; dst_addr += got; remaining -= got;
    }
    // Sanity: scan the whole cryptoff region. If every byte is zero the
    // cryptoff pages were never page-faulted by the target (kernel returned
    // us the zero-filled backing store, not the decrypted content). Skip
    // writing so the dst stays as the original encrypted file — user gets a
    // cryptid=1 framework which at least surfaces the failure rather than a
    // cryptid=0 with broken bytes.
    {
        const uint8_t *p = buf + info->slice_offset + info->cryptoff;
        int nonzero = 0;
        for (uint32_t k = 0; k < info->cryptsize; k++) {
            if (p[k]) { nonzero = 1; break; }
        }
        if (!nonzero) {
            ERR("cryptoff read all zeros for %s — target hadn't faulted the pages yet", src);
            free(buf); return -1;
        }
    }

    // Patch cryptid to 0.
    uint32_t zero = 0;
    memcpy(buf + info->cryptid_file_offset, &zero, sizeof(zero));

    mkdirs(dst); // no-op if parent exists; creates parent if not
    // mkdirs above actually mkdirs the file path as a dir — fix by doing
    // parent only:
    char parent[4096];
    snprintf(parent, sizeof(parent), "%s", dst);
    char *slash = strrchr(parent, '/');
    if (slash) { *slash = '\0'; mkdirs(parent); }

    int out = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (out < 0) { ERR("open dst %s: %s", dst, strerror(errno)); free(buf); return -1; }
    if (write(out, buf, st.st_size) != st.st_size) {
        ERR("write dst %s: %s", dst, strerror(errno));
        close(out); free(buf); return -1;
    }
    close(out);
    free(buf);
    return 0;
}

// ----- dyld resume + exception-port watch -----------------------------

// Set an exception port on target and return its receive right. Catches the
// SIGABRT dyld fires when cross-OS bind-fails.
static mach_port_t make_exception_port(task_t task) {
    mach_port_t port = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS) return MACH_PORT_NULL;
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    task_set_exception_ports(task,
        EXC_MASK_CRASH | EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION |
        EXC_MASK_SOFTWARE | EXC_MASK_ARITHMETIC | EXC_MASK_BREAKPOINT,
        port, EXCEPTION_DEFAULT, ARM_THREAD_STATE64);
    return port;
}

// Resume target and wait up to `ms` for either a Mach exception (cross-OS
// bind-fail abort) or timeout, then suspend the task so the caller has a
// stable address space to walk.
static void run_and_suspend(task_t task, pid_t pid, int via_ptrace,
                             mach_port_t exc_port, int ms) {
    if (via_ptrace) {
        // PT_CONTINUE keeps the trace relationship; signals route to us via
        // waitpid rather than Mach exception.
        ptrace(PT_CONTINUE, pid, (void *)1, 0);
        int waited = 0;
        while (waited < ms) {
            int st;
            pid_t w = waitpid(pid, &st, WNOHANG | WUNTRACED);
            if (w == pid) {
                if (WIFEXITED(st) || WIFSIGNALED(st)) break;
                if (WIFSTOPPED(st)) {
                    int sig = WSTOPSIG(st);
                    int deliver = (sig == SIGTRAP || sig == SIGSTOP) ? 0 : sig;
                    ptrace(PT_CONTINUE, pid, (void *)1, deliver);
                }
            }
            usleep(200 * 1000);
            waited += 200;
        }
    } else {
        // SBS / posix_spawn leave the task with potentially multiple
        // suspensions (task itself + runningboardd assertion). Drain until
        // suspend count is 0 so threads actually run.
        while (task_resume(task) == KERN_SUCCESS) { /* loop */ }
        if (exc_port != MACH_PORT_NULL) {
            struct { mach_msg_header_t hdr; char body[2048]; } msg;
            memset(&msg, 0, sizeof(msg));
            mach_msg_return_t mr = mach_msg(&msg.hdr,
                MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(msg),
                exc_port, ms, MACH_PORT_NULL);
            LOG("[helper] mach_msg wait returned 0x%x\n", mr);
        } else {
            usleep(ms * 1000);
        }
    }
    task_suspend(task);
}

// ----- decrypt one bundle ---------------------------------------------

// Find main executable name from CFBundleExecutable in Info.plist, or fall
// back to "the single Mach-O file whose name matches the bundle dir sans
// .app/.appex suffix" heuristic. We avoid parsing plist here — plist format
// varies (XML vs binary) — and use the heuristic as a simple, robust enough
// alternative.
static int find_main_name(const char *bundle, char *out, size_t cap) {
    // Heuristic: try the bundle basename sans trailing .app/.appex; verify
    // it's a Mach-O. If not, scan for any Mach-O file at the bundle root.
    char base[1024];
    strncpy(base, bundle, sizeof(base) - 1); base[sizeof(base) - 1] = '\0';
    char *slash = strrchr(base, '/');
    const char *name = slash ? slash + 1 : base;
    char cand[4096];
    snprintf(cand, sizeof(cand), "%s/%s", bundle, name);
    char *dot = strrchr(cand, '.');
    if (dot && (strcmp(dot, ".app") == 0 || strcmp(dot, ".appex") == 0)) *dot = '\0';
    if (is_macho(cand)) {
        const char *bn = strrchr(cand, '/'); bn = bn ? bn + 1 : cand;
        strncpy(out, bn, cap - 1); out[cap - 1] = '\0';
        return 0;
    }
    // Fallback: scan.
    DIR *d = opendir(bundle);
    if (!d) return -1;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        char p[4096]; snprintf(p, sizeof(p), "%s/%s", bundle, e->d_name);
        struct stat st;
        if (lstat(p, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        if (is_macho(p)) {
            strncpy(out, e->d_name, cap - 1); out[cap - 1] = '\0';
            closedir(d);
            return 0;
        }
    }
    closedir(d);
    return -1;
}

// Decrypt one bundle (main .app, .appex, or any .framework with executable).
// bundle_src: original bundle on disk
// bundle_dst: where to write decrypted copy (should already contain a copy
//             of the bundle tree so we only overwrite the Mach-Os)
// bundle_id:  optional; when non-empty, SBS is used as the launch method
//             (only works for main apps registered with LaunchServices)
static int decrypt_bundle(const char *bundle_src, const char *bundle_dst,
                          const char *bundle_id) {
    char main_name[512];
    if (find_main_name(bundle_src, main_name, sizeof(main_name)) != 0) {
        LOG("[helper] no main exec in %s, skipping\n", bundle_src);
        EVT("event=bundle phase=skipped src=\"%s\" reason=\"no_main_exec\"", bundle_src);
        return 0;
    }
    char main_src[4096], main_dst[4096];
    snprintf(main_src, sizeof(main_src), "%s/%s", bundle_src, main_name);
    snprintf(main_dst, sizeof(main_dst), "%s/%s", bundle_dst, main_name);
    trust_walk(bundle_src);

    pid_t pid = 0;
    task_t task = MACH_PORT_NULL;
    int via_ptrace = 0;
    if (spawn_suspended(bundle_id, main_src, &pid, &task, &via_ptrace) != 0) {
        ERR("spawn failed for %s", bundle_src);
        EVT("event=spawn_failed src=\"%s\"", bundle_src);
        return 0; // non-fatal; continue with rest of the IPA
    }

    // 1) Dump the main exec by reading cryptoff pages out of the VM image.
    //    Works even before dyld starts binding; FairPlay decrypts on page
    //    fault during mach_vm_read_overwrite.
    encinfo_t info;
    int er = parse_macho(main_src, &info);
    if (er == 1) {
        mach_vm_address_t base = 0;
        if (find_main_base(task, &base) == 0) {
            LOG("[helper] dumping main %s (load=0x%llx, cryptsize=0x%x)\n",
                main_name, (unsigned long long)base, info.cryptsize);
            EVT("event=image phase=start name=\"%s\" kind=main", main_name);
            if (dump_image(main_src, main_dst, task, base, &info) == 0) {
                EVT("event=image phase=done name=\"%s\" kind=main size=%u",
                    main_name, info.cryptsize);
            } else {
                EVT("event=image phase=failed name=\"%s\" kind=main", main_name);
            }
        } else {
            ERR("could not locate MH_EXECUTE base in %s", bundle_src);
        }
    }

    // 2) Resume dyld so it maps Frameworks/* into the target's address
    //    space; FairPlay page-faults decrypt them on first access. We set a
    //    Mach exception port so the inevitable dyld bind-fail (on cross-OS
    //    missing-symbol abort) pauses the task before the process dies.
    mach_port_t exc = via_ptrace ? MACH_PORT_NULL : make_exception_port(task);
    LOG("[helper] resuming %s (via_ptrace=%d)\n", bundle_src, via_ptrace);
    EVT("event=dyld phase=resuming src=\"%s\" via_ptrace=%d", bundle_src, via_ptrace);
    run_and_suspend(task, pid, via_ptrace, exc, 2000);

    // 3) Enumerate images loaded in the (now suspended or dead) target task
    //    and dump every encrypted one whose path is inside this bundle.
    uint32_t img_count = 0;
    char *paths = NULL;
    struct dyld_image_info *imgs = list_images(task, &img_count, &paths);
    int extra = 0;
    // dyld image paths come back with a /private prefix that bundle_src
    // doesn't have. Match by suffix stripping either prefix.
    const char *bs = bundle_src;
    size_t bs_len = strlen(bs);
    const char *bs_alt = NULL;
    size_t bs_alt_len = 0;
    if (strncmp(bs, "/var/", 5) == 0) {
        bs_alt = bs; // no-op, but keep form for symmetry
    }
    // We'll check both "/bundle_src..." and "/private/bundle_src..." forms.
    char bs_pri[4096];
    snprintf(bs_pri, sizeof(bs_pri), "/private%s", bs);
    bs_alt = bs_pri;
    bs_alt_len = strlen(bs_pri);

    for (uint32_t i = 0; i < img_count && imgs; i++) {
        const char *ip = imgs[i].imageFilePath;
        if (!ip) continue;
        const char *rel = NULL;
        if (strncmp(ip, bs, bs_len) == 0) rel = ip + bs_len;
        else if (strncmp(ip, bs_alt, bs_alt_len) == 0) rel = ip + bs_alt_len;
        if (!rel) continue;
        while (*rel == '/') rel++;
        if (!*rel) continue; // this is the main exec, already handled
        if (strcmp(rel, main_name) == 0) continue; // main exec at <bundle>/<name>, already handled

        char rel_src[4096], rel_dst[4096];
        snprintf(rel_src, sizeof(rel_src), "%s/%s", bundle_src, rel);
        snprintf(rel_dst, sizeof(rel_dst), "%s/%s", bundle_dst, rel);
        encinfo_t ri;
        if (parse_macho(rel_src, &ri) != 1) continue;
        // Sanity-read header at load_addr to confirm the framework is really
        // mapped there. mach_vm_read of an unmapped region silently returns
        // zero-filled data which would produce a cryptid=0 IPA with broken
        // pages.
        mach_vm_address_t base = (mach_vm_address_t)(uintptr_t)imgs[i].imageLoadAddress;
        struct mach_header_64 mhchk;
        mach_vm_size_t got = 0;
        if (mach_vm_read_overwrite(task, base, sizeof(mhchk),
                (mach_vm_address_t)(uintptr_t)&mhchk, &got) != KERN_SUCCESS ||
            got != sizeof(mhchk) ||
            (mhchk.magic != MH_MAGIC_64 && mhchk.magic != MH_MAGIC)) {
            LOG("[helper] skip %s: header at 0x%llx not mapped (magic=0x%x)\n",
                rel, (unsigned long long)base, mhchk.magic);
            continue;
        }
        LOG("[helper] dumping %s (load=0x%llx, cryptsize=0x%x)\n", rel,
            (unsigned long long)base, ri.cryptsize);
        EVT("event=image phase=start name=\"%s\" kind=framework", rel);
        if (dump_image(rel_src, rel_dst, task, base, &ri) == 0) {
            extra++;
            EVT("event=image phase=done name=\"%s\" kind=framework size=%u",
                rel, ri.cryptsize);
        } else {
            EVT("event=image phase=failed name=\"%s\" kind=framework", rel);
        }
    }
    free(paths); free(imgs);
    LOG("[helper] %s: dumped %d framework(s)\n", bundle_src, extra);
    EVT("event=bundle phase=done src=\"%s\" extras=%d", bundle_src, extra);

    if (exc != MACH_PORT_NULL) {
        mach_port_mod_refs(mach_task_self(), exc, MACH_PORT_RIGHT_RECEIVE, -1);
    }
    task_terminate(task);
    kill(pid, SIGKILL);
    int st;
    waitpid(pid, &st, WNOHANG);
    return 0;
}

// Walk PlugIns/ and Extensions/ at the top of main_app and decrypt each appex.
static void decrypt_appexes(const char *bundle_src, const char *bundle_dst) {
    const char *subdirs[] = { "PlugIns", "Extensions", NULL };
    for (int si = 0; subdirs[si]; si++) {
        char dir_src[4096], dir_dst[4096];
        snprintf(dir_src, sizeof(dir_src), "%s/%s", bundle_src, subdirs[si]);
        snprintf(dir_dst, sizeof(dir_dst), "%s/%s", bundle_dst, subdirs[si]);
        DIR *d = opendir(dir_src);
        if (!d) continue;
        struct dirent *e;
        while ((e = readdir(d))) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
            const char *dot = strrchr(e->d_name, '.');
            if (!dot || strcmp(dot, ".appex") != 0) continue;
            char s[4096], t[4096];
            snprintf(s, sizeof(s), "%s/%s", dir_src, e->d_name);
            snprintf(t, sizeof(t), "%s/%s", dir_dst, e->d_name);
            LOG("[helper] decrypting appex %s/%s\n", subdirs[si], e->d_name);
            decrypt_bundle(s, t, NULL); // appexes don't launch via SBS
        }
        closedir(d);
    }
}

// ----- zip via /var/jb/usr/bin/zip ------------------------------------

static int run_zip(const char *staging, const char *ipa_path) {
    // posix_spawn_file_actions_addchdir_np is iOS-unavailable, so chdir
    // in the parent. This is the last step of the helper so the pwd change
    // doesn't matter afterwards.
    char cwd_save[4096];
    if (!getcwd(cwd_save, sizeof(cwd_save))) cwd_save[0] = '\0';
    if (chdir(staging) != 0) { ERR("chdir %s: %s", staging, strerror(errno)); return -1; }

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    char *argv[] = { "zip", "-qr", (char *)ipa_path, "Payload", NULL };
    pid_t pid = 0;
    const char *zip_paths[] = { "/var/jb/usr/bin/zip", "/usr/bin/zip", NULL };
    int rc = -1;
    for (int i = 0; zip_paths[i]; i++) {
        if (access(zip_paths[i], X_OK) != 0) continue;
        rc = posix_spawn(&pid, zip_paths[i], &fa, NULL, argv, environ);
        if (rc == 0) break;
    }
    posix_spawn_file_actions_destroy(&fa);
    if (cwd_save[0]) chdir(cwd_save);
    if (rc != 0 || pid == 0) { ERR("zip not available"); return -1; }
    int st;
    waitpid(pid, &st, 0);
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
}

// ----- main -----------------------------------------------------------

int main(int argc, char **argv) {
    // Allow -v at any position before the positional args.
    int pi = 1;
    while (pi < argc && argv[pi][0] == '-') {
        if (strcmp(argv[pi], "-v") == 0) { g_verbose = 1; pi++; continue; }
        break;
    }
    if (argc - pi != 3) {
        fprintf(stderr,
            "usage: %s [-v] <bundle-id> <bundle-src> <out-ipa>\n"
            "  bundle-id  CFBundleIdentifier (for SBS), or \"\" to skip main app\n"
            "  bundle-src absolute path to the installed .app on disk\n"
            "  out-ipa    where to write the decrypted IPA\n",
            argv[0]);
        return 2;
    }
    const char *bundle_id = argv[pi + 0];
    const char *bundle_src = argv[pi + 1];
    const char *out_ipa = argv[pi + 2];

    // Resolve the bundle's basename for the staging Payload/ layout.
    char src_copy[4096];
    snprintf(src_copy, sizeof(src_copy), "%s", bundle_src);
    char *app_name = strrchr(src_copy, '/');
    app_name = app_name ? app_name + 1 : src_copy;
    if (!*app_name || strchr(app_name, '/') != NULL) { ERR("bad bundle path"); return 1; }

    // Staging tree: /tmp/ipadecrypt-<pid>/Payload/<app>.app
    char staging[4096];
    snprintf(staging, sizeof(staging), "/tmp/ipadecrypt-%d", getpid());
    mkdirs(staging);
    char payload[4096];
    snprintf(payload, sizeof(payload), "%s/Payload", staging);
    mkdir(payload, 0755);
    char bundle_dst[4096];
    snprintf(bundle_dst, sizeof(bundle_dst), "%s/%s", payload, app_name);

    LOG("[helper] staging %s → %s\n", bundle_src, bundle_dst);
    if (copy_tree(bundle_src, bundle_dst) != 0) {
        ERR("copy_tree failed");
        rm_rf(staging);
        return 1;
    }

    if (bundle_id && bundle_id[0]) {
        decrypt_bundle(bundle_src, bundle_dst, bundle_id);
    }
    decrypt_appexes(bundle_src, bundle_dst);

    LOG("[helper] zipping → %s\n", out_ipa);
    EVT("event=pack phase=start ipa=\"%s\"", out_ipa);
    unlink(out_ipa);
    if (run_zip(staging, out_ipa) != 0) {
        ERR("zip failed");
        EVT("event=pack phase=failed ipa=\"%s\"", out_ipa);
        rm_rf(staging);
        return 1;
    }
    EVT("event=pack phase=done ipa=\"%s\"", out_ipa);
    rm_rf(staging);
    EVT("event=done ipa=\"%s\"", out_ipa);
    return 0;
}
