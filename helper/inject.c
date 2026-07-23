#include "inject.h"
#include "dump.h"
#include "dyld_patch.h"
#include "exc.h"
#include "fs.h"
#include "log.h"
#include "target.h"

#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <mach/arm/thread_status.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define INJECT_SENTINEL_LR 0x4141414141414141ULL

// pid_resume comes from libsystem_kernel as an undocumented entry; declare
// it here so we don't depend on private headers.
extern int pid_resume(pid_t pid);

// mremap_encrypted is a private syscall wrapper in libsystem_kernel. Not
// in public headers; declare it here so dlsym can locate it for slide.
extern int mremap_encrypted(void *addr, size_t len, uint32_t cryptid,
                            cpu_type_t cputype, cpu_subtype_t cpusubtype);

// ----- Pick a target pthread for hijack -------------------------------------

// Prefer the LAST non-zero idle thread (TH_STATE_WAITING/HALTED/STOPPED):
// most-recently-created pthread is least likely to hold global locks.
// Falls back to thread 0 when no idle non-zero thread exists (dyld
// bootstrap-only state after halt).
// Once a hijack thread wedges inside dyld's bind retry, every subsequent
// target_call returns immediately with rc=-1 because thread_set_state on
// the stuck thread fails. Pick_hijack_thread must never re-hand out a
// wedged port. We track terminated/wedged kernel ids in a tiny ring and
// thread_info-skip anything that matches.
#define WEDGE_CAP 64
static mach_port_name_t wedge_buf[WEDGE_CAP];
static int wedge_count = 0;

static int is_wedged(mach_port_name_t p) {
    for (int i = 0; i < wedge_count; i++) {
        if (wedge_buf[i] == p) return 1;
    }
    return 0;
}

static void mark_wedged(mach_port_name_t p) {
    if (wedge_count < WEDGE_CAP) wedge_buf[wedge_count++] = p;
}

static thread_act_t pick_hijack_thread(task_t task) {
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    if (task_threads(task, &threads, &count) != KERN_SUCCESS || !threads)
        return MACH_PORT_NULL;
    thread_act_t chosen = MACH_PORT_NULL;
    // PREFER main thread (threads[0]). Main was suspended cleanly by
    // run_and_suspend at dyld.settled, so its dyld state is fresh. The
    // worker threads (libdispatch, hermes) might already hold dyld API
    // locks from JS engine init; hijacking those leads to bind-time
    // lock cascades on the first failed dlopen, after which every
    // subsequent target_call returns rc=-1.
    if (count > 0 && !is_wedged(threads[0])) {
        chosen = threads[0];
    }
    // Fallback: idle non-wedged worker thread.
    if (chosen == MACH_PORT_NULL) {
        for (mach_msg_type_number_t i = 1; i < count; i++) {
            if (is_wedged(threads[i])) continue;
            struct thread_basic_info tbi;
            mach_msg_type_number_t tic = THREAD_BASIC_INFO_COUNT;
            if (thread_info(threads[i], THREAD_BASIC_INFO,
                    (thread_info_t)&tbi, &tic) != KERN_SUCCESS) continue;
            if (tbi.run_state == 2 || tbi.run_state == 3 || tbi.run_state == 5)
                chosen = threads[i];
        }
    }
    // Last resort: any non-wedged thread regardless of state.
    if (chosen == MACH_PORT_NULL) {
        for (mach_msg_type_number_t i = 0; i < count; i++) {
            if (!is_wedged(threads[i])) { chosen = threads[i]; break; }
        }
    }
    if (chosen != MACH_PORT_NULL) {
        mach_port_mod_refs(mach_task_self(), chosen, MACH_PORT_RIGHT_SEND, +1);
    }
    for (mach_msg_type_number_t i = 0; i < count; i++)
        mach_port_deallocate(mach_task_self(), threads[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(*threads));
    return chosen;
}

// Mark a hijack thread as unusable so pick_hijack_thread won't re-hand
// it out. We deliberately do NOT thread_terminate the target's thread 
// on iOS 16 the kernel sometimes responds to thread_terminate of a
// platform-binary's thread by killing the caller (saw exit 137). The
// blacklist alone is enough: subsequent thread_set_state on the wedged
// thread would just return KERN_FAILURE so we'd waste a cycle, but
// pick_hijack_thread now skips it and moves to the next candidate.
static void retire_hijack_thread(thread_act_t thread) {
    if (thread == MACH_PORT_NULL) return;
    mark_wedged(thread);
}

// ----- target_call: run a function on the hijacked thread -------------------

// Calls `pc(x0..x5)` on the suspended hijacked thread with LR=sentinel.
// When the called function returns, control jumps to the sentinel address
// which traps EXC_BAD_ACCESS at our exc_port. We then read x0 as the
// return value. Returns 0 on sentinel hit, -1 on timeout or other fault.
static int target_call(task_t task, thread_act_t thread, mach_port_t exc_port,
                       mach_vm_address_t pc,
                       uint64_t x0, uint64_t x1, uint64_t x2,
                       uint64_t x3, uint64_t x4, uint64_t x5,
                       mach_vm_address_t sp,
                       uint64_t *out_x0, int wait_ms) {
    if (thread_suspend(thread) != KERN_SUCCESS) return -1;
    // thread_abort_safely only aborts interruptible waits; for stuck
    // non-interruptible waits we fall back to thread_abort so thread_set_state
    // actually takes effect.
    if (thread_abort_safely(thread) != KERN_SUCCESS) thread_abort(thread);

    arm_thread_state64_t s = {0};
    mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
    if (thread_get_state(thread, ARM_THREAD_STATE64,
            (thread_state_t)&s, &sc) != KERN_SUCCESS) return -1;
    s.__pc = pc;
    s.__lr = INJECT_SENTINEL_LR;
    s.__sp = sp ? sp : ((s.__sp - 0x800) & ~0xfULL);
    s.__x[0] = x0; s.__x[1] = x1; s.__x[2] = x2;
    s.__x[3] = x3; s.__x[4] = x4; s.__x[5] = x5;
    if (thread_set_state(thread, ARM_THREAD_STATE64,
            (thread_state_t)&s, sc) != KERN_SUCCESS) return -1;

    // Force the sentinel SEGV onto our exc_port from both thread and task
    // levels. Thread-level ports take priority; pthread libraries (libdispatch,
    // Foundation, Crashlytics) sometimes install per-thread handlers that
    // would otherwise swallow our trap.
    const exception_mask_t exc_mask =
        EXC_MASK_CRASH | EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION |
        EXC_MASK_SOFTWARE | EXC_MASK_ARITHMETIC | EXC_MASK_BREAKPOINT |
        EXC_MASK_GUARD;
    thread_set_exception_ports(thread, exc_mask, exc_port,
        EXCEPTION_STATE_IDENTITY, ARM_THREAD_STATE64);
    task_set_exception_ports(task, exc_mask, exc_port,
        EXCEPTION_STATE_IDENTITY, ARM_THREAD_STATE64);

    thread_resume(thread);
    for (int i = 0; i < 8; i++) {
        if (thread_resume(thread) != KERN_SUCCESS) break;
    }

    // Reply to the pending exception only if the faulting thread is the
    // one we're hijacking. Otherwise let the brk-thread stay parked in
    // MACH_RECV_REPLY (task_terminate reaps it at bundle end). Replying
    // to a foreign thread would put two threads through our trampoline.
    if (g_pending_exc_valid &&
        (g_pending_exc_thread == MACH_PORT_NULL ||
         g_pending_exc_thread == thread)) {
        exc_reply_with_state(&g_pending_exc_hdr, &s);
        exc_clear_pending();
    }

    // Drain task suspends + drop the runningboardd proc-suspended hold
    // (xpcproxy leaves it on SBS-launched targets; task_resume can't clear it).
    for (int i = 0; i < 16; i++) {
        if (task_resume(task) != KERN_SUCCESS) break;
    }
    pid_t pid_for = 0;
    if (pid_for_task(task, &pid_for) == KERN_SUCCESS && pid_for > 0)
        pid_resume(pid_for);

    struct { mach_msg_header_t hdr; char body[2048]; } msg;
    memset(&msg, 0, sizeof(msg));
    mach_msg_return_t mr = mach_msg(&msg.hdr,
        MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(msg),
        exc_port, wait_ms, MACH_PORT_NULL);
    if (mr != MACH_MSG_SUCCESS) {
        return -1;
    }

    int exc = 0, sig = 0;
    int64_t c0 = 0, c1 = 0;
    exc_decode(&msg, msg.hdr.msgh_size, &exc, &c0, &c1, &sig, NULL);
    exc_clear_pending();
    g_pending_exc_hdr = msg.hdr;
    g_pending_exc_valid = 1;
    g_pending_exc_thread = exc_extract_thread(&msg, msg.hdr.msgh_size);
    exc_release_msg_ports(&msg, msg.hdr.msgh_size);

    unsigned long long fault = (unsigned long long)c1;
    // MACH_EXCEPTION_CODES is off → codes truncated to 32 bits. Sentinel
    // match against both full 64-bit and low 32 bits.
    if (exc != EXC_BAD_ACCESS ||
        (fault != INJECT_SENTINEL_LR &&
         fault != (INJECT_SENTINEL_LR & 0xfffffffful))) {
        return -1;
    }

    arm_thread_state64_t fs = {0};
    mach_msg_type_number_t fsc = ARM_THREAD_STATE64_COUNT;
    if (thread_get_state(thread, ARM_THREAD_STATE64,
            (thread_state_t)&fs, &fsc) != KERN_SUCCESS) return -1;
    if (out_x0) *out_x0 = fs.__x[0];
    return 0;
}

// ----- dyld API lock recovery ----------------------------------------------

// Reset every located API lock to "unlocked" (uint32_t 0). Called after
// a failed inject_dlopen so the next acquisition doesn't spin forever.
// dyld uses multiple distinct lock VAs (main API lock + recursive-lock
// variant + others), and any of them may be held by the stuck thread.
static void reset_api_locks(task_t task, const mach_vm_address_t *locks,
                            int count) {
    if (!locks || count <= 0) return;
    uint32_t zero = 0;
    for (int i = 0; i < count; i++) {
        if (!locks[i]) continue;
        mach_vm_write(task, locks[i],
            (vm_offset_t)(uintptr_t)&zero, sizeof(zero));
    }
}

// ----- Resolve libsystem symbol slid into the target task -------------------

// Resolve a libsystem function's slid VA in the target task. Uses the
// helper's local copy as anchor: dladdr → containing image base → match
// image by name in target's image list → slide function pointer.
static mach_vm_address_t resolve_target_fn(task_t task,
                                            struct dyld_image_info *imgs,
                                            uint32_t img_count,
                                            void *local_fn) {
    if (!local_fn) return 0;
    Dl_info di = {0};
    if (!dladdr(local_fn, &di) || !di.dli_fbase || !di.dli_fname) return 0;
    mach_vm_address_t target_img = target_find_image(task, imgs, img_count,
                                                     di.dli_fname);
    if (!target_img) return 0;
    return target_slide_func(task, imgs, img_count, local_fn, target_img,
                             (mach_vm_address_t)(uintptr_t)di.dli_fbase);
}

// ----- Inject dlopen --------------------------------------------------------

static int inject_dlopen(task_t task, mach_port_t exc_port,
                         thread_act_t thread,
                         const char *path,
                         mach_vm_address_t target_dlopen,
                         mach_vm_address_t *out_base) {
    if (target_dlopen == 0 || thread == MACH_PORT_NULL) return -1;

    size_t path_len = strlen(path) + 1;
    size_t scratch_size = (path_len + 0xfff) & ~(size_t)0xfff;
    mach_vm_address_t scratch = 0;
    if (mach_vm_allocate(task, &scratch, scratch_size, VM_FLAGS_ANYWHERE)
            != KERN_SUCCESS) return -1;
    if (mach_vm_write(task, scratch, (vm_offset_t)(uintptr_t)path,
            (mach_msg_type_number_t)path_len) != KERN_SUCCESS) {
        mach_vm_deallocate(task, scratch, scratch_size);
        return -1;
    }

    // Successful dlopens finish well under 1s. Failed dlopens  Python
    // cpython modules with unresolved sibling imports, frameworks whose
    // @rpath libs aren't loaded  sit in dyld's bind retry until our
    // timeout, so keep it tight to avoid compounding into minutes.
    uint64_t handle = 0;
    if (target_call(task, thread, exc_port, target_dlopen,
            scratch, 0x2 /* RTLD_NOW */, 0, 0, 0, 0, 0,
            &handle, 1500) != 0 || handle == 0) {
        mach_vm_deallocate(task, scratch, scratch_size);
        return -1;
    }

    uint32_t new_count = 0;
    char *new_paths = NULL;
    struct dyld_image_info *new_imgs = target_list_images(task, &new_count, &new_paths);
    mach_vm_address_t base = 0;
    if (new_imgs) {
        for (uint32_t i = 0; i < new_count; i++) {
            const char *ip = new_imgs[i].imageFilePath;
            if (ip && fs_path_equiv(ip, path)) {
                base = (mach_vm_address_t)(uintptr_t)new_imgs[i].imageLoadAddress;
                break;
            }
        }
        free(new_paths);
        free(new_imgs);
    }
    mach_vm_deallocate(task, scratch, scratch_size);
    // dlclose intentionally skipped: image stays mapped until task_terminate.
    if (base == 0) return -1;
    *out_base = base;
    return 0;
}

// ----- Path key: last two components, used for dep-vs-loaded matching ------

// Return strdup'd "DirBasename/FileBasename" (or "FileBasename" alone if
// the path has only one component). NULL on alloc fail. Trailing slashes
// are tolerated. Used both for loaded image paths and dep strings.
static char *path_key(const char *p) {
    if (!p || !*p) return NULL;
    size_t len = strlen(p);
    while (len > 1 && p[len - 1] == '/') len--;
    const char *end = p + len;
    const char *slash1 = NULL;
    const char *slash2 = NULL;
    for (const char *q = end - 1; q >= p; q--) {
        if (*q != '/') continue;
        if (!slash1) { slash1 = q; continue; }
        slash2 = q;
        break;
    }
    const char *start = slash2 ? slash2 + 1 : p;
    size_t klen = (size_t)(end - start);
    char *out = malloc(klen + 1);
    if (!out) return NULL;
    memcpy(out, start, klen);
    out[klen] = '\0';
    return out;
}

// Normalize a dep string to a path_key, stripping @rpath/@loader_path/
// @executable_path prefix. Returns strdup'd key (caller frees).
static char *dep_to_key(const char *dep) {
    if (!dep) return NULL;
    const char *p = dep;
    static const char *prefixes[] = {
        "@rpath/", "@loader_path/", "@executable_path/", NULL
    };
    for (int i = 0; prefixes[i]; i++) {
        size_t plen = strlen(prefixes[i]);
        if (strncmp(p, prefixes[i], plen) == 0) { p += plen; break; }
    }
    return path_key(p);
}

// ----- Loaded set: simple deduped string array ------------------------------

typedef struct {
    char **keys;
    int    count;
    int    cap;
} keyset_t;

static int keyset_has(const keyset_t *s, const char *key) {
    if (!key) return 0;
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->keys[i], key) == 0) return 1;
    }
    return 0;
}

static void keyset_add(keyset_t *s, const char *key) {
    if (!key || keyset_has(s, key)) return;
    if (s->count == s->cap) {
        int nc = s->cap ? s->cap * 2 : 32;
        char **n = realloc(s->keys, sizeof(char *) * nc);
        if (!n) return;
        s->keys = n;
        s->cap = nc;
    }
    s->keys[s->count++] = strdup(key);
}

static void keyset_free(keyset_t *s) {
    for (int i = 0; i < s->count; i++) free(s->keys[i]);
    free(s->keys);
    memset(s, 0, sizeof(*s));
}

// ----- Candidate framework collection (recursive bundle walk) ---------------

typedef struct {
    char            *path;     // absolute fs path
    selected_slice_t sel;
    macho_deps_t     deps;
    char            *self_key; // path_key(path); cached to avoid recompute
    int              loaded;   // 1 once dlopened & dumped
    int              skipped;  // 1 if deemed unsatisfiable
} fw_t;

typedef struct {
    fw_t *items;
    int   count;
    int   cap;
} fwvec_t;

static void fwvec_push(fwvec_t *v, fw_t fw) {
    if (v->count == v->cap) {
        int nc = v->cap ? v->cap * 2 : 64;
        fw_t *n = realloc(v->items, sizeof(fw_t) * nc);
        if (!n) { macho_deps_free(&fw.deps); free(fw.path); free(fw.self_key); return; }
        v->items = n;
        v->cap = nc;
    }
    v->items[v->count++] = fw;
}

static void fwvec_free(fwvec_t *v) {
    for (int i = 0; i < v->count; i++) {
        free(v->items[i].path);
        free(v->items[i].self_key);
        macho_deps_free(&v->items[i].deps);
    }
    free(v->items);
    memset(v, 0, sizeof(*v));
}

static void collect_candidates(const char *bundle_src,
                               const runtime_image_t *runtime,
                               struct dyld_image_info *imgs, uint32_t img_count,
                               fwvec_t *out) {
    typedef struct stk { char *dir; struct stk *next; } stk_t;
    stk_t *stack = malloc(sizeof(*stack));
    if (!stack) return;
    stack->dir = strdup(bundle_src);
    stack->next = NULL;
    if (!stack->dir) { free(stack); return; }

    while (stack) {
        stk_t *cur = stack;
        stack = stack->next;
        DIR *d = opendir(cur->dir);
        if (!d) { free(cur->dir); free(cur); continue; }

        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.') continue;
            char child[4096];
            snprintf(child, sizeof(child), "%s/%s", cur->dir, e->d_name);
            struct stat st;
            if (lstat(child, &st) != 0) continue;
            if (S_ISLNK(st.st_mode)) continue;
            if (S_ISDIR(st.st_mode)) {
                if (strcmp(cur->dir, bundle_src) == 0 &&
                    (strcmp(e->d_name, "PlugIns") == 0 ||
                     strcmp(e->d_name, "Extensions") == 0)) continue;
                stk_t *n = malloc(sizeof(*n));
                if (!n) continue;
                n->dir = strdup(child);
                if (!n->dir) { free(n); continue; }
                n->next = stack;
                stack = n;
                continue;
            }
            if (!S_ISREG(st.st_mode)) continue;
            if (!fs_is_macho(child)) continue;

            selected_slice_t sel;
            if (select_runtime_slice(child, runtime, &sel) != 1) continue;
            if (!slice_needs_dump(&sel)) continue;

            int already_loaded = 0;
            for (uint32_t i = 0; i < img_count; i++) {
                const char *ip = imgs[i].imageFilePath;
                if (!ip) continue;
                if (strcmp(ip, child) == 0 ||
                    (strncmp(ip, "/private", 8) == 0 && strcmp(ip + 8, child) == 0)) {
                    already_loaded = 1;
                    break;
                }
            }
            if (already_loaded) continue;

            fw_t fw = {0};
            fw.path = strdup(child);
            fw.self_key = path_key(child);
            fw.sel = sel;
            macho_collect_deps(child, runtime, &fw.deps);
            fwvec_push(out, fw);
        }
        closedir(d);
        free(cur->dir);
        free(cur);
    }
}

// ----- Thread pool: fresh pthreads spawned in target ------------------------
//
// One bootstrap hijack (typically main thread) calls pthread_create N
// times. Each new pthread runs pause()  it sits in __sigsuspend with
// zero dyld state, no held locks. We hand out one fresh pool entry per
// dlopen attempt and never reuse it. dlopen either returns (NULL on
// bind failure, handle on success)  both are quick. If it wedges
// mid-bind, the pool thread stays stuck holding the dyld API lock; we
// reset the lock externally and move to the next fresh thread.
//
// Why this matters: re-hijacking a wedged worker thread fails because
// thread_set_state returns KERN_FAILURE on a thread mid-uninterruptible-
// wait. Fresh pthreads created AFTER dyld.settled have never touched
// dyld, never wedged, and accept thread_set_state cleanly.
typedef struct {
    task_t            task;
    mach_port_t       exc;
    thread_act_t     *pool;
    int               pool_count;
    int               next;
    mach_vm_address_t scratch;
    size_t            scratch_size;
} threadpool_t;

static int tp_contains(thread_act_array_t arr, mach_msg_type_number_t n,
                       thread_act_t needle) {
    for (mach_msg_type_number_t i = 0; i < n; i++) {
        if (arr[i] == needle) return 1;
    }
    return 0;
}

static int tp_init(threadpool_t *tp, task_t task, mach_port_t exc,
                   thread_act_t bootstrap,
                   struct dyld_image_info *imgs, uint32_t img_count,
                   int target_size) {
    memset(tp, 0, sizeof(*tp));
    if (bootstrap == MACH_PORT_NULL) return -1;
    tp->task = task;
    tp->exc = exc;

    mach_vm_address_t t_pthread_create = resolve_target_fn(task, imgs, img_count,
                                                            (void *)pthread_create);
    mach_vm_address_t t_pause = resolve_target_fn(task, imgs, img_count,
                                                   (void *)pause);
    if (!t_pthread_create || !t_pause) {
        attrs_t a; attrs_init(&a);
        attrs_hex(&a, "pthread_create", (unsigned long long)t_pthread_create);
        attrs_hex(&a, "pause", (unsigned long long)t_pause);
        emit(LOG_WARN, "tp.resolve_fail", &a,
             "threadpool resolve fail pthread_create=0x%llx pause=0x%llx",
             (unsigned long long)t_pthread_create,
             (unsigned long long)t_pause);
        return -1;
    }

    tp->scratch_size = 0x1000;
    if (mach_vm_allocate(task, &tp->scratch, tp->scratch_size,
                          VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        emit(LOG_WARN, "tp.alloc_fail", NULL, "threadpool scratch alloc failed");
        return -1;
    }

    thread_act_array_t before = NULL;
    mach_msg_type_number_t before_count = 0;
    if (task_threads(task, &before, &before_count) != KERN_SUCCESS) {
        mach_vm_deallocate(task, tp->scratch, tp->scratch_size);
        tp->scratch = 0;
        return -1;
    }

    int created = 0;
    for (int i = 0; i < target_size; i++) {
        uint64_t rc_val = 0;
        int rc = target_call(task, bootstrap, exc, t_pthread_create,
                              tp->scratch, 0, t_pause, 0, 0, 0, 0,
                              &rc_val, 2000);
        if (rc != 0 || (int32_t)rc_val != 0) {
            attrs_t a; attrs_init(&a);
            attrs_int(&a, "i", i);
            attrs_int(&a, "rc", rc);
            attrs_int(&a, "ret", (int32_t)rc_val);
            emit(LOG_WARN, "tp.create_fail", &a,
                 "pthread_create stopped at i=%d rc=%d ret=%d",
                 i, rc, (int32_t)rc_val);
            break;
        }
        created++;
    }
    {
        attrs_t a; attrs_init(&a);
        attrs_int(&a, "created", created);
        attrs_int(&a, "target", target_size);
        emit(LOG_INFO, "tp.spawned", &a,
             "threadpool: spawned %d/%d fresh pthreads",
             created, target_size);
    }

    thread_act_array_t after = NULL;
    mach_msg_type_number_t after_count = 0;
    if (task_threads(task, &after, &after_count) != KERN_SUCCESS) {
        for (mach_msg_type_number_t i = 0; i < before_count; i++)
            mach_port_deallocate(mach_task_self(), before[i]);
        vm_deallocate(mach_task_self(), (vm_address_t)before,
                      before_count * sizeof(*before));
        mach_vm_deallocate(task, tp->scratch, tp->scratch_size);
        tp->scratch = 0;
        return -1;
    }

    tp->pool = calloc((size_t)created + 16, sizeof(thread_act_t));
    if (!tp->pool) {
        for (mach_msg_type_number_t i = 0; i < before_count; i++)
            mach_port_deallocate(mach_task_self(), before[i]);
        for (mach_msg_type_number_t i = 0; i < after_count; i++)
            mach_port_deallocate(mach_task_self(), after[i]);
        vm_deallocate(mach_task_self(), (vm_address_t)before,
                      before_count * sizeof(*before));
        vm_deallocate(mach_task_self(), (vm_address_t)after,
                      after_count * sizeof(*after));
        mach_vm_deallocate(task, tp->scratch, tp->scratch_size);
        tp->scratch = 0;
        return -1;
    }
    for (mach_msg_type_number_t i = 0; i < after_count; i++) {
        if (tp_contains(before, before_count, after[i])) continue;
        mach_port_mod_refs(mach_task_self(), after[i],
                            MACH_PORT_RIGHT_SEND, +1);
        tp->pool[tp->pool_count++] = after[i];
    }

    for (mach_msg_type_number_t i = 0; i < before_count; i++)
        mach_port_deallocate(mach_task_self(), before[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)before,
                  before_count * sizeof(*before));
    for (mach_msg_type_number_t i = 0; i < after_count; i++)
        mach_port_deallocate(mach_task_self(), after[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)after,
                  after_count * sizeof(*after));

    attrs_t a; attrs_init(&a);
    attrs_int(&a, "pool", tp->pool_count);
    emit(LOG_INFO, "tp.ready", &a,
         "threadpool ready: %d fresh pthreads to hijack", tp->pool_count);

    return tp->pool_count > 0 ? 0 : -1;
}

static thread_act_t tp_next(threadpool_t *tp) {
    if (!tp || tp->next >= tp->pool_count) return MACH_PORT_NULL;
    return tp->pool[tp->next++];
}

static void tp_destroy(threadpool_t *tp) {
    if (!tp) return;
    for (int i = 0; i < tp->pool_count; i++) {
        mach_port_deallocate(mach_task_self(), tp->pool[i]);
    }
    free(tp->pool);
    if (tp->scratch) {
        mach_vm_deallocate(tp->task, tp->scratch, tp->scratch_size);
    }
    memset(tp, 0, sizeof(*tp));
}

// ----- inject_missing_frameworks (the orchestrator) -------------------------

int inject_missing_frameworks(task_t task, mach_port_t exc,
                              const char *bundle_src,
                              const char *bundle_dst,
                              struct dyld_image_info *imgs,
                              uint32_t img_count,
                              const runtime_image_t *runtime) {
    if (!task || exc == MACH_PORT_NULL || !runtime) return 0;
    wedge_count = 0;

    if (runtime->cputype != CPU_TYPE_ARM64 ||
        cpusubtype_base(runtime->cpusubtype) != CPU_SUBTYPE_ARM64_ALL) {
        attrs_t a; attrs_init(&a);
        attrs_hex(&a, "cputype", runtime->cputype);
        attrs_hex(&a, "cpusubtype", runtime->cpusubtype);
        emit(LOG_DEBUG, "inject.skipped", &a,
             "inject skipped: target arch isn't plain arm64");
        return 0;
    }

    size_t bs_len = strlen(bundle_src);

    mach_vm_address_t target_dlopen = resolve_target_fn(task, imgs, img_count,
                                                         (void *)dlopen);
    if (!target_dlopen) {
        emit(LOG_WARN, "inject.no_dlopen", NULL,
             "target dlopen unresolved  inject skipped");
        return 0;
    }

    thread_act_t bootstrap = pick_hijack_thread(task);
    if (bootstrap == MACH_PORT_NULL) {
        emit(LOG_WARN, "inject.no_bootstrap", NULL,
             "no usable bootstrap thread  inject skipped");
        return 0;
    }

    keyset_t loaded = {0};
    for (uint32_t i = 0; i < img_count; i++) {
        const char *ip = imgs[i].imageFilePath;
        if (!ip) continue;
        char *k = path_key(ip);
        if (k) { keyset_add(&loaded, k); free(k); }
    }

    fwvec_t fws = {0};
    collect_candidates(bundle_src, runtime, imgs, img_count, &fws);

    // Keys of every bundle framework we're responsible for loading. The
    // dep-gate in the topo loop blocks ONLY on these (intra-bundle load
    // order). External deps - system /usr/lib/swift, /System, or toolchain
    // dylibs not shipped in the bundle - must never block: dlopen resolves
    // them from the shared cache / filesystem, or fails cleanly on its own.
    // The old gate blocked on any unloaded dep, so a single unbundled dep
    // (e.g. /usr/lib/swift/libswift_Builtin_float.dylib) wrongly skipped
    // every framework transitively needing it.
    keyset_t bundle_keys = {0};
    for (int i = 0; i < fws.count; i++) {
        if (fws.items[i].self_key) keyset_add(&bundle_keys, fws.items[i].self_key);
    }

    // Count remaining work to size the pool. One pool thread per dlopen
    // attempt  we never reuse, so the pool has to cover the worst-case
    // sum of attempts across topo passes.
    int candidates = 0;
    for (int i = 0; i < fws.count; i++) {
        const char *rel = fws.items[i].path + bs_len;
        while (*rel == '/') rel++;
        char abs_dst[4096];
        snprintf(abs_dst, sizeof(abs_dst), "%s/%s", bundle_dst, rel);
        selected_slice_t dst_sel;
        if (select_runtime_slice(abs_dst, runtime, &dst_sel) == 1 &&
            !slice_needs_dump(&dst_sel)) continue;
        candidates++;
    }
    if (candidates == 0) {
        fwvec_free(&fws);
        keyset_free(&loaded);
        keyset_free(&bundle_keys);
        mach_port_deallocate(mach_task_self(), bootstrap);
        return 0;
    }

    // dyld API locks for emergency reset between calls (in case a prior
    // dlopen wedged a pool thread mid-bind holding the API lock  fresh
    // thread can't grab it without the reset).
    mach_vm_address_t api_locks[16] = {0};
    int api_lock_count = dyld_find_api_locks(task, api_locks,
        (int)(sizeof(api_locks)/sizeof(api_locks[0])));

    // Pool sized for candidates + slack for multi-pass topo retries.
    int pool_target = candidates * 2 + 32;
    if (pool_target > 800) pool_target = 800;
    threadpool_t tp;
    if (tp_init(&tp, task, exc, bootstrap, imgs, img_count, pool_target) != 0) {
        emit(LOG_WARN, "inject.tp_init_fail", NULL,
             "threadpool init failed  inject skipped");
        fwvec_free(&fws);
        keyset_free(&loaded);
        keyset_free(&bundle_keys);
        mach_port_deallocate(mach_task_self(), bootstrap);
        return 0;
    }
    mach_port_deallocate(mach_task_self(), bootstrap);

    int injected = 0;
    // Multi-pass topo: pass N picks up frameworks whose deps were loaded
    // in pass N-1. Loop exits early when a pass loads nothing new, so the
    // cap is just a safety bound - deep bundle dep chains (e.g. Swift
    // Playgrounds' SwiftBuild: leaf -> SWBCore -> ... -> SWBBuildSystem ->
    // SWBBuildService is 5+ levels) need more than a handful of passes.
    for (int pass = 0; pass < 16; pass++) {
        int loaded_this_pass = 0;
        for (int i = 0; i < fws.count; i++) {
            fw_t *fw = &fws.items[i];
            if (fw->loaded) continue;

            int missing = 0;
            for (int j = 0; j < fw->deps.dep_count; j++) {
                char *dk = dep_to_key(fw->deps.deps[j]);
                if (!dk) continue;
                int self_dep = (fw->self_key && strcmp(dk, fw->self_key) == 0);
                // Only an unloaded *bundle* framework blocks; external deps
                // are dlopen's problem, not a topo-order constraint.
                if (!self_dep && keyset_has(&bundle_keys, dk) &&
                    !keyset_has(&loaded, dk)) {
                    missing = 1;
                    free(dk);
                    break;
                }
                free(dk);
            }
            if (missing) continue;

            const char *rel = fw->path + bs_len;
            while (*rel == '/') rel++;

            char abs_dst[4096];
            snprintf(abs_dst, sizeof(abs_dst), "%s/%s", bundle_dst, rel);

            // Skip if already decrypted (multi-spawn or prior pass).
            selected_slice_t dst_sel;
            if (select_runtime_slice(abs_dst, runtime, &dst_sel) == 1 &&
                !slice_needs_dump(&dst_sel)) {
                fw->loaded = 1;
                if (fw->self_key) keyset_add(&loaded, fw->self_key);
                continue;
            }

            thread_act_t hijack = tp_next(&tp);
            if (hijack == MACH_PORT_NULL) {
                attrs_t a; attrs_init(&a);
                attrs_int(&a, "exhausted_at", i);
                attrs_int(&a, "pass", pass);
                emit(LOG_WARN, "inject.pool_exhausted", &a,
                     "thread pool exhausted pass=%d at i=%d/%d",
                     pass, i, fws.count);
                pass = 999; // force outer break
                break;
            }

            // Stage path string into target.
            size_t path_len = strlen(fw->path) + 1;
            size_t spages = (path_len + 0xfff) & ~(size_t)0xfff;
            mach_vm_address_t scratch_path = 0;
            if (mach_vm_allocate(task, &scratch_path, spages,
                                  VM_FLAGS_ANYWHERE) != KERN_SUCCESS) continue;
            if (mach_vm_write(task, scratch_path,
                              (vm_offset_t)(uintptr_t)fw->path,
                              (mach_msg_type_number_t)path_len) != KERN_SUCCESS) {
                mach_vm_deallocate(task, scratch_path, spages);
                continue;
            }

            // Reset API lock first  if a prior pool thread wedged mid-
            // bind, this clears the lock so our fresh thread can proceed.
            reset_api_locks(task, api_locks, api_lock_count);

            uint64_t handle = 0;
            int rc = target_call(task, hijack, exc, target_dlopen,
                                  scratch_path, 0x2 /* RTLD_NOW */,
                                  0, 0, 0, 0, 0, &handle, 15000);
            mach_vm_deallocate(task, scratch_path, spages);

            if (rc != 0 || handle == 0) {
                attrs_t a; attrs_init(&a);
                attrs_str(&a, "name", rel);
                attrs_int(&a, "rc", rc);
                attrs_hex(&a, "handle", (unsigned long long)handle);
                emit(LOG_DEBUG, "inject.dlopen_fail", &a,
                     "dlopen failed name=%s rc=%d handle=0x%llx",
                     rel, rc, (unsigned long long)handle);
                continue;
            }

            // Locate the newly-loaded image's base via dyld's image list.
            uint32_t new_count = 0;
            char *new_paths = NULL;
            struct dyld_image_info *new_imgs =
                target_list_images(task, &new_count, &new_paths);
            mach_vm_address_t base = 0;
            for (uint32_t j = 0; new_imgs && j < new_count; j++) {
                const char *ip = new_imgs[j].imageFilePath;
                if (ip && fs_path_equiv(ip, fw->path)) {
                    base = (mach_vm_address_t)(uintptr_t)new_imgs[j].imageLoadAddress;
                    break;
                }
            }
            free(new_paths); free(new_imgs);
            if (base == 0) {
                attrs_t a; attrs_init(&a);
                attrs_str(&a, "name", rel);
                emit(LOG_DEBUG, "inject.no_base", &a,
                     "dlopen returned handle but image not in list: %s", rel);
                continue;
            }

            dump_result_t dr = dump_image(fw->path, abs_dst, task, base, &fw->sel);
            attrs_t a; attrs_init(&a);
            attrs_str(&a, "name", rel);
            attrs_str(&a, "kind", "framework");
            attrs_str(&a, "source", "inject");
            if (dr == DUMP_OK) {
                attrs_uint(&a, "size", fw->sel.selected.crypt.cryptsize);
                emit(LOG_INFO, "image.done", &a,
                     "decrypted %s (%s)", rel,
                     human_bytes(fw->sel.selected.crypt.cryptsize));
                injected++;
                loaded_this_pass++;
            } else {
                attrs_str(&a, "reason", dump_reason(dr));
                emit(LOG_WARN, "image.failed", &a,
                     "failed to dump %s (%s)", rel, dump_reason(dr));
            }
            fw->loaded = 1;
            if (fw->self_key) keyset_add(&loaded, fw->self_key);
        }
        {
            attrs_t a; attrs_init(&a);
            attrs_int(&a, "pass", pass);
            attrs_int(&a, "loaded", loaded_this_pass);
            emit(LOG_INFO, "inject.pass_done", &a,
                 "inject pass %d loaded %d", pass, loaded_this_pass);
        }
        if (loaded_this_pass == 0) break;
    }

    // Report unsatisfied stragglers with their blocking dep, if any.
    for (int i = 0; i < fws.count; i++) {
        fw_t *fw = &fws.items[i];
        if (fw->loaded) continue;
        const char *rel = fw->path + bs_len;
        while (*rel == '/') rel++;
        const char *missing_dep = NULL;
        for (int j = 0; j < fw->deps.dep_count; j++) {
            char *dk = dep_to_key(fw->deps.deps[j]);
            if (!dk) continue;
            int self_dep = (fw->self_key && strcmp(dk, fw->self_key) == 0);
            if (!self_dep && keyset_has(&bundle_keys, dk) &&
                !keyset_has(&loaded, dk)) {
                missing_dep = fw->deps.deps[j];
                free(dk);
                break;
            }
            free(dk);
        }
        attrs_t a; attrs_init(&a);
        attrs_str(&a, "name", rel);
        if (missing_dep) {
            attrs_str(&a, "dep", missing_dep);
            emit(LOG_WARN, "inject.unsatisfied", &a,
                 "skipped %s: dep not loaded (%s)", rel, missing_dep);
        } else {
            emit(LOG_WARN, "inject.failed", &a,
                 "inject failed for %s (dlopen returned NULL or hung)", rel);
        }
    }

    tp_destroy(&tp);
    fwvec_free(&fws);
    keyset_free(&loaded);
    keyset_free(&bundle_keys);
    return injected;
}
