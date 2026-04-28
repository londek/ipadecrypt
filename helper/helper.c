// ipadecrypt-helper-arm64 - on-device FairPlay decrypter.
//
// Spawns target suspended, reads cryptoff pages via mach_vm_read_overwrite
// (kernel page-fault decrypts), patches cryptid=0, packs IPA. Walks
// PlugIns/*.appex + Extensions/*.appex. Spawn-path strategy at
// spawn_suspended(); rescue path for cross-OS dyld aborts at
// rescue_unmapped_frameworks().
//
// CLI: ipadecrypt-helper-arm64 [-v] <bundle-id> <bundle-src> <out-ipa>
//   bundle-id  - CFBundleIdentifier; "" skips the main-app pass (appex only).
//                Used for SpringBoard SBS launch - launchd-lineage spawn that
//                bypasses Sandbox kext's hook_execve gate on Dopamine.
//   bundle-src - absolute path to the installed .app on disk.
//   out-ipa    - absolute path to write the decrypted IPA to.

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
#include <libkern/OSByteOrder.h>

// ----- SDK-missing SPI forward decls -----------------------------------

// mach_vm is "unsupported" in iOS SDK headers; syscalls exist at runtime.
typedef uint64_t mach_vm_address_t;
typedef uint64_t mach_vm_size_t;
extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t,
    mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
extern kern_return_t mach_vm_region(vm_map_t, mach_vm_address_t *,
    mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t,
    mach_msg_type_number_t *, mach_port_t *);

// libproc SPI - not in iOS SDK.
extern int proc_listallpids(void *, int);
extern int proc_pidpath(int, void *, uint32_t);

// ptrace - sys/ptrace.h is iOS-hidden. We only need these two requests.
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

#ifndef FAT_MAGIC_64
#define FAT_MAGIC_64 0xcafebabf
#endif
#ifndef FAT_CIGAM_64
#define FAT_CIGAM_64 0xbfbafeca
#endif

#ifndef CPU_SUBTYPE_MASK
#define CPU_SUBTYPE_MASK 0xff000000
#endif

// ----- logging ---------------------------------------------------------

static int g_verbose = 0;

#define LOG(...) do { if (g_verbose) fprintf(stderr, __VA_ARGS__); } while (0)
#define ERR(fmt, ...) fprintf(stderr, "[helper] ERROR: " fmt "\n", ##__VA_ARGS__)
#define EVT(fmt, ...) do { fprintf(stdout, "@evt " fmt "\n", ##__VA_ARGS__); fflush(stdout); } while (0)

// ----- Mach-O metadata types ------------------------------------------

// Arch fingerprint of a loaded image, read from the target task.
typedef struct {
    uint32_t cputype;
    uint32_t cpusubtype;
    int      is_64;
} runtime_image_t;

// Thin Mach-O slice geometry within a file (whole file for thin Mach-O).
typedef struct {
    off_t    slice_offset;
    uint64_t slice_size;
    int      is_64;
    uint32_t cputype;
    uint32_t cpusubtype;
} slice_meta_t;

// LC_ENCRYPTION_INFO[_64] findings. has_crypt=0 means no such load command.
typedef struct {
    int      has_crypt;
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid;
    off_t    cryptid_file_offset;
} crypt_meta_t;

typedef struct {
    slice_meta_t slice;
    crypt_meta_t crypt;
} mach_slice_t;

// Outcome of slice selection. any_slice_encrypted flags whether a fat
// input still has an encrypted sibling that thinning must drop.
typedef struct {
    mach_slice_t selected;
    int          is_fat;
    int          any_slice_encrypted;
} selected_slice_t;

// dump_image outcomes. decrypt_bundle maps these to reason= attrs on
// image phase=failed events so users get actionable context instead of
// a silent skip in the IPA.
typedef enum {
    DUMP_OK = 0,
    DUMP_OPEN_SRC_FAIL,
    DUMP_READ_SRC_FAIL,
    DUMP_VM_READ_FAIL,
    DUMP_ZERO_PAGES,
    DUMP_OPEN_DST_FAIL,
    DUMP_WRITE_DST_FAIL,
    DUMP_OOM,
} dump_result_t;

static const char *dump_reason(dump_result_t r) {
    switch (r) {
    case DUMP_OPEN_SRC_FAIL:  return "open_src_fail";
    case DUMP_READ_SRC_FAIL:  return "read_src_fail";
    case DUMP_VM_READ_FAIL:   return "vm_read_err";
    case DUMP_ZERO_PAGES:     return "zero_pages";
    case DUMP_OPEN_DST_FAIL:  return "open_dst_fail";
    case DUMP_WRITE_DST_FAIL: return "write_dst_fail";
    case DUMP_OOM:            return "oom";
    default:                  return "ok";
    }
}

// ----- slice selection helpers ----------------------------------------

// Strip CPU capability bits so arm64/arm64e and signed variants compare
// on their base subtype.
static uint32_t cpusubtype_base(uint32_t subtype) {
    return subtype & ~(uint32_t)CPU_SUBTYPE_MASK;
}

static int slice_matches_runtime(const slice_meta_t *slice,
                                 const runtime_image_t *rt) {
    return slice->is_64 == rt->is_64 &&
           slice->cputype == rt->cputype &&
           cpusubtype_base(slice->cpusubtype) == cpusubtype_base(rt->cpusubtype);
}

// True when the matched slice is encrypted, or when the file is fat with
// any encrypted slice (we will thin to drop the sibling).
static int slice_needs_dump(const selected_slice_t *sel) {
    if (sel->selected.crypt.has_crypt && sel->selected.crypt.cryptid != 0) return 1;
    return sel->is_fat && sel->any_slice_encrypted;
}

// ----- Mach-O parsing -------------------------------------------------

// Parse one thin Mach-O slice. Returns 1 on success, 0 if the bytes
// aren't a Mach-O, -1 if malformed.
static int parse_thin_slice(const uint8_t *slice, size_t slice_len,
                            off_t slice_off, uint64_t slice_size,
                            mach_slice_t *out) {
    if (slice_len < sizeof(struct mach_header)) return 0;

    struct mach_header mh;
    memcpy(&mh, slice, sizeof(mh));

    int is_64;
    size_t hdr_sz;
    uint32_t ncmds, szcmds;
    if (mh.magic == MH_MAGIC_64) {
        if (slice_len < sizeof(struct mach_header_64)) return 0;
        struct mach_header_64 mh64;
        memcpy(&mh64, slice, sizeof(mh64));
        is_64 = 1;
        ncmds = mh64.ncmds; szcmds = mh64.sizeofcmds; hdr_sz = sizeof(mh64);
        out->slice.cputype = mh64.cputype;
        out->slice.cpusubtype = mh64.cpusubtype;
    } else if (mh.magic == MH_MAGIC) {
        is_64 = 0;
        ncmds = mh.ncmds; szcmds = mh.sizeofcmds; hdr_sz = sizeof(mh);
        out->slice.cputype = mh.cputype;
        out->slice.cpusubtype = mh.cpusubtype;
    } else {
        return 0;
    }
    if (hdr_sz + szcmds > slice_len) return -1;

    out->slice.slice_offset = slice_off;
    out->slice.slice_size = slice_size;
    out->slice.is_64 = is_64;
    out->crypt.has_crypt = 0;

    const uint8_t *lc_end = slice + hdr_sz + szcmds;
    const uint8_t *lc_ptr = slice + hdr_sz;
    uint32_t want = is_64 ? LC_ENCRYPTION_INFO_64 : LC_ENCRYPTION_INFO;
    for (uint32_t i = 0; i < ncmds; i++) {
        if ((size_t)(lc_end - lc_ptr) < sizeof(struct load_command)) return -1;
        struct load_command lc;
        memcpy(&lc, lc_ptr, sizeof(lc));
        if (lc.cmdsize == 0 || (size_t)(lc_end - lc_ptr) < lc.cmdsize) return -1;

        if (lc.cmd == want) {
            if (lc.cmdsize < sizeof(struct encryption_info_command)) return -1;
            struct encryption_info_command eic;
            memcpy(&eic, lc_ptr, sizeof(eic));
            if ((uint64_t)eic.cryptoff + eic.cryptsize > slice_size) return -1;
            out->crypt.has_crypt = 1;
            out->crypt.cryptoff = eic.cryptoff;
            out->crypt.cryptsize = eic.cryptsize;
            out->crypt.cryptid = eic.cryptid;
            out->crypt.cryptid_file_offset = slice_off + (lc_ptr - slice) +
                offsetof(struct encryption_info_command, cryptid);
            break;
        }
        lc_ptr += lc.cmdsize;
    }
    return 1;
}

// Resolve (file_offset, size) of the i-th fat slice. Returns -1 if the
// table entry or slice runs past file_sz.
static int fat_slice_range(const uint8_t *base, size_t file_sz,
                           int is_fat64, int swap, uint32_t idx,
                           uint64_t *out_off, uint64_t *out_size) {
    uint64_t arch_size = is_fat64 ? sizeof(struct fat_arch_64)
                                  : sizeof(struct fat_arch);
    uint64_t entry_off = sizeof(struct fat_header) + arch_size * idx;
    if (entry_off + arch_size > file_sz) return -1;

    uint64_t off, sz;
    if (is_fat64) {
        struct fat_arch_64 fa;
        memcpy(&fa, base + entry_off, sizeof(fa));
        off = swap ? OSSwapBigToHostInt64(fa.offset) : fa.offset;
        sz  = swap ? OSSwapBigToHostInt64(fa.size)   : fa.size;
    } else {
        struct fat_arch fa;
        memcpy(&fa, base + entry_off, sizeof(fa));
        off = swap ? OSSwapBigToHostInt32(fa.offset) : fa.offset;
        sz  = swap ? OSSwapBigToHostInt32(fa.size)   : fa.size;
    }
    if (sz > file_sz || off > file_sz - sz) return -1;
    *out_off = off;
    *out_size = sz;
    return 0;
}

// Open a Mach-O file (thin or fat[64]) and pick the slice matching `rt`.
// Returns 1 with *out filled, 0 if no slice matches or file isn't
// Mach-O, -1 on I/O or malformed input.
static int select_runtime_slice(const char *path,
                                const runtime_image_t *rt,
                                selected_slice_t *out) {
    memset(out, 0, sizeof(*out));

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }
    if (st.st_size < (off_t)sizeof(struct fat_header)) { close(fd); return 0; }

    size_t file_sz = (size_t)st.st_size;
    void *map = mmap(NULL, file_sz, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return -1;

    int rc = 0;
    const uint8_t *base = map;
    uint32_t magic;
    memcpy(&magic, base, 4);

    if (magic == FAT_MAGIC || magic == FAT_CIGAM ||
        magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
        int is_fat64 = (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);
        int swap = (magic == FAT_CIGAM || magic == FAT_CIGAM_64);
        struct fat_header fh;
        memcpy(&fh, base, sizeof(fh));
        uint32_t nfat = swap ? OSSwapBigToHostInt32(fh.nfat_arch) : fh.nfat_arch;
        uint64_t arch_size = is_fat64 ? sizeof(struct fat_arch_64)
                                      : sizeof(struct fat_arch);
        if (nfat == 0 || nfat > (file_sz - sizeof(struct fat_header)) / arch_size) {
            rc = -1; goto done;
        }

        out->is_fat = 1;
        for (uint32_t i = 0; i < nfat; i++) {
            uint64_t s_off, s_sz;
            if (fat_slice_range(base, file_sz, is_fat64, swap, i, &s_off, &s_sz) != 0) {
                rc = -1; goto done;
            }
            mach_slice_t slice;
            int sr = parse_thin_slice(base + s_off, (size_t)s_sz,
                                      (off_t)s_off, s_sz, &slice);
            if (sr < 0) { rc = -1; goto done; }
            if (sr == 0) continue;
            if (slice.crypt.has_crypt && slice.crypt.cryptid != 0)
                out->any_slice_encrypted = 1;
            if (rc == 0 && slice_matches_runtime(&slice.slice, rt)) {
                out->selected = slice;
                rc = 1;
            }
        }
    } else {
        mach_slice_t slice;
        int sr = parse_thin_slice(base, file_sz, 0, file_sz, &slice);
        if (sr <= 0) { rc = sr; goto done; }
        if (!slice_matches_runtime(&slice.slice, rt)) goto done;
        out->any_slice_encrypted = slice.crypt.has_crypt && slice.crypt.cryptid != 0;
        out->selected = slice;
        rc = 1;
    }

done:
    munmap(map, file_sz);
    return rc;
}

static int is_macho(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    uint32_t m = 0;
    ssize_t n = read(fd, &m, sizeof(m));
    close(fd);
    return n == sizeof(m) &&
        (m == MH_MAGIC || m == MH_MAGIC_64 ||
         m == FAT_MAGIC || m == FAT_CIGAM ||
         m == FAT_MAGIC_64 || m == FAT_CIGAM_64);
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

static int write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) { errno = EIO; return -1; }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_full(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) { errno = EIO; return -1; }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int copy_file(const char *src, const char *dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    struct stat st;
    if (fstat(in, &st) != 0) { close(in); return -1; }
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode & 0777);
    if (out < 0) { close(in); return -1; }
    char buf[64 * 1024];
    ssize_t n = 0;
    for (;;) {
        n = read(in, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        if (write_all(out, buf, (size_t)n) != 0) { close(in); close(out); return -1; }
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
    pid_t pid = find_pid_by_path(exec_path, 2000);
    if (pid == 0) { LOG("[helper] SBS launch did not produce a pid\n"); return -1; }
    task_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) {
        LOG("[helper] task_for_pid(%d) after SBS failed\n", pid);
        kill(pid, SIGKILL);
        return -1;
    }
    // SBS's suspended:1 relies on xpcproxy's "not ready" signal, not a real
    // task_suspend we can observe - by the time we grab the task, dyld may
    // be running. Freeze it ourselves so the address space is stable.
    task_suspend(task);
    *out_pid = pid;
    *out_task = task;
    LOG("[helper] SBS spawned %s pid=%d\n", bundle_id, pid);
    return 0;
}

// ----- PT_TRACE_ME spawn -----------------------------------------------

// fork, child PT_TRACE_ME + execve. P_LTRACED is set on the proc BEFORE
// exec, so Sandbox's hook_execve takes the debugger-exemption branch and
// doesn't apply the "only launchd may spawn untrusted binaries" gate.
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

// Installed appex mains often ship mode 0644; execve needs +x.
static void ensure_executable(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return;
    mode_t want = st.st_mode | S_IXUSR | S_IXGRP | S_IXOTH;
    if (want == st.st_mode) return;
    if (chmod(path, want) == 0) {
        EVT("event=spawn_chmod path=\"%s\" old_mode=%o", path, st.st_mode & 0777);
    }
}

// *out_ptrace=1 iff PT_TRACE_ME path taken (caller resumes via PT_CONTINUE).
//
// Spawn-path order:
//   bundle_id non-empty (main app):
//     1. SBS suspended-launch  - launchd lineage, bypasses Sandbox hook_execve
//     2. fork+PT_TRACE_ME+execve - P_LTRACED debugger-exemption branch
//   bundle_id empty (appex):
//     PT_TRACE_ME directly. SBS rejects appex with kSBSError(7).
static int spawn_suspended(const char *bundle_id, const char *exec_path,
                           pid_t *out_pid, task_t *out_task, int *out_ptrace) {
    *out_ptrace = 0;
    ensure_executable(exec_path);
    if (bundle_id && bundle_id[0]) {
        if (sbs_launch(bundle_id, exec_path, out_pid, out_task) == 0) {
            return 0;
        }
        EVT("event=spawn_path_fallback exec=\"%s\"", exec_path);
    }

    pid_t pid = 0;
    if (do_ptrace_spawn(exec_path, &pid) != 0) return -1;
    task_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        ERR("task_for_pid(%d) after PT_TRACE_ME: %d", pid, kr);
        kill(pid, SIGKILL);
        return -1;
    }
    *out_ptrace = 1;
    *out_pid = pid;
    *out_task = task;
    EVT("event=spawn_path path=ptrace exec=\"%s\"", exec_path);
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
        if (sz == 0 || addr + sz <= addr) return -1;
        addr += sz;
    }
}

// Read mach_header[_64] at a runtime base and capture its arch.
static int read_runtime_image(task_t task, mach_vm_address_t base,
                              runtime_image_t *out) {
    struct mach_header_64 hdr;
    mach_vm_size_t got = 0;
    if (mach_vm_read_overwrite(task, base, sizeof(hdr),
            (mach_vm_address_t)(uintptr_t)&hdr, &got) != KERN_SUCCESS ||
        got != sizeof(hdr)) {
        return -1;
    }
    if (hdr.magic != MH_MAGIC && hdr.magic != MH_MAGIC_64) return -1;
    out->is_64 = (hdr.magic == MH_MAGIC_64);
    out->cputype = hdr.cputype;
    out->cpusubtype = hdr.cpusubtype;
    return 0;
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

// Splice cryptsize decrypted bytes from the target into `buf` at the
// slice's absolute file offset.
static dump_result_t vm_read_crypt_region(task_t task, mach_vm_address_t image_base,
                                          const mach_slice_t *slice, uint8_t *buf) {
    mach_vm_address_t src = image_base + slice->crypt.cryptoff;
    mach_vm_address_t dst = (mach_vm_address_t)(uintptr_t)
        (buf + slice->slice.slice_offset + slice->crypt.cryptoff);
    mach_vm_size_t remaining = slice->crypt.cryptsize;
    while (remaining > 0) {
        mach_vm_size_t chunk = remaining > 0x100000 ? 0x100000 : remaining;
        mach_vm_size_t got = 0;
        kern_return_t kr = mach_vm_read_overwrite(task, src, chunk, dst, &got);
        if (kr != KERN_SUCCESS || got == 0) {
            ERR("mach_vm_read @0x%llx size=0x%llx kr=%d", src, chunk, kr);
            return DUMP_VM_READ_FAIL;
        }
        src += got; dst += got; remaining -= got;
    }
    return DUMP_OK;
}

// All-zero cryptoff means the target never faulted those pages and the
// kernel handed us the zero-filled backing store, not decrypted bytes.
static int crypt_region_has_data(const uint8_t *buf, const mach_slice_t *slice) {
    const uint8_t *p = buf + slice->slice.slice_offset + slice->crypt.cryptoff;
    for (uint32_t i = 0; i < slice->crypt.cryptsize; i++) {
        if (p[i]) return 1;
    }
    return 0;
}

// Write the matched slice's bytes for fat input (thinning the output) or
// the whole buffer for thin input.
static dump_result_t write_output(const char *dst, const uint8_t *buf,
                                  size_t file_sz, const selected_slice_t *sel) {
    char parent[4096];
    snprintf(parent, sizeof(parent), "%s", dst);
    char *slash = strrchr(parent, '/');
    if (slash) { *slash = '\0'; mkdirs(parent); }

    int fd = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (fd < 0) { ERR("open dst %s: %s", dst, strerror(errno)); return DUMP_OPEN_DST_FAIL; }

    const uint8_t *p = sel->is_fat ? buf + sel->selected.slice.slice_offset : buf;
    size_t n = sel->is_fat ? (size_t)sel->selected.slice.slice_size : file_sz;
    if (write_all(fd, p, n) != 0) {
        ERR("write dst %s: %s", dst, strerror(errno));
        close(fd); return DUMP_WRITE_DST_FAIL;
    }
    close(fd);
    return DUMP_OK;
}

// Decrypt the matched slice into a thin Mach-O at `dst`. Fat siblings
// are dropped on the way out.
static dump_result_t dump_image(const char *src, const char *dst, task_t task,
                                mach_vm_address_t image_base,
                                const selected_slice_t *sel) {
    const mach_slice_t *slice = &sel->selected;

    int fd = open(src, O_RDONLY);
    if (fd < 0) { ERR("open %s: %s", src, strerror(errno)); return DUMP_OPEN_SRC_FAIL; }
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return DUMP_OPEN_SRC_FAIL; }
    size_t file_sz = (size_t)st.st_size;
    uint8_t *buf = malloc(file_sz);
    if (!buf) { close(fd); return DUMP_OOM; }
    if (read_full(fd, buf, file_sz) != 0) {
        ERR("read %s: %s", src, strerror(errno));
        free(buf); close(fd); return DUMP_READ_SRC_FAIL;
    }
    close(fd);

    if (slice->crypt.has_crypt && slice->crypt.cryptid != 0 && slice->crypt.cryptsize) {
        dump_result_t dr = vm_read_crypt_region(task, image_base, slice, buf);
        if (dr != DUMP_OK) { free(buf); return dr; }
        if (!crypt_region_has_data(buf, slice)) {
            ERR("cryptoff read all zeros for %s - target hadn't faulted the pages yet", src);
            free(buf); return DUMP_ZERO_PAGES;
        }
    }

    if (slice->crypt.has_crypt) {
        uint32_t zero = 0;
        memcpy(buf + slice->crypt.cryptid_file_offset, &zero, sizeof(zero));
    }

    dump_result_t dr = write_output(dst, buf, file_sz, sel);
    free(buf);
    return dr;
}

// ----- dyld resume + exception-port watch -----------------------------

// Set an exception port on target and return its receive right. Catches the
// SIGABRT dyld fires when cross-OS bind-fails.
static mach_port_t make_exception_port(task_t task) {
    mach_port_t port = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS) return MACH_PORT_NULL;
    if (mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
        mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
        return MACH_PORT_NULL;
    }
    if (task_set_exception_ports(task,
        EXC_MASK_CRASH | EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION |
        EXC_MASK_SOFTWARE | EXC_MASK_ARITHMETIC | EXC_MASK_BREAKPOINT,
        port, EXCEPTION_DEFAULT, ARM_THREAD_STATE64) != KERN_SUCCESS) {
        mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
        return MACH_PORT_NULL;
    }
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
        // SBS leaves the task with potentially multiple suspensions
        // (task itself + runningboardd assertion). Drain until suspend
        // count is 0 so threads actually run.
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

// Heuristic: try the bundle basename sans trailing .app/.appex (avoids
// parsing Info.plist which varies XML vs binary). Falls back to scanning
// for any Mach-O at the bundle root.
static int find_main_name(const char *bundle, char *out, size_t cap) {
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

// mmap-rescue dump: skip dyld, mmap the file PROT_READ in our own VM,
// memcpy through dump_image's mach_vm_read_overwrite path. The kernel's
// FairPlay page-fault handler decrypts on first touch - it's vnode + cdhash
// bound, not caller-bundle-id bound, so this works from helper context.
// Bypassing dyld dodges cross-OS bind-fail aborts on missing system
// dylibs (e.g. iOS 14.8 lacks /usr/lib/swift/libswift_Concurrency.dylib
// which iOS-16.4-minos apps strict-link against).
static dump_result_t mmap_dump(const char *src, const char *dst,
                               const selected_slice_t *sel) {
    int fd = open(src, O_RDONLY);
    if (fd < 0) { ERR("open %s: %s", src, strerror(errno)); return DUMP_OPEN_SRC_FAIL; }
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return DUMP_OPEN_SRC_FAIL; }
    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) {
        ERR("mmap %s: %s", src, strerror(errno));
        return DUMP_VM_READ_FAIL;
    }
    mach_vm_address_t image_base = (mach_vm_address_t)(uintptr_t)map +
                                   sel->selected.slice.slice_offset;
    dump_result_t dr = dump_image(src, dst, mach_task_self(), image_base, sel);
    munmap(map, st.st_size);
    return dr;
}

// Try to mmap-dump a single Mach-O at <bundle_src>/<rel>. Returns 1 on
// success, 0 if skipped or failed. Used by the recursive rescue walk.
static int rescue_try_dump(const char *rel,
                           const char *bundle_src, const char *bundle_dst,
                           const runtime_image_t *runtime,
                           const char **dumped, int n_dumped) {
    for (int i = 0; i < n_dumped; i++) {
        if (strcmp(dumped[i], rel) == 0) return 0;
    }

    char abs_src[4096], abs_dst[4096];
    snprintf(abs_src, sizeof(abs_src), "%s/%s", bundle_src, rel);
    snprintf(abs_dst, sizeof(abs_dst), "%s/%s", bundle_dst, rel);

    if (!is_macho(abs_src)) return 0;

    selected_slice_t sel;
    if (select_runtime_slice(abs_src, runtime, &sel) != 1) return 0;
    if (!slice_needs_dump(&sel)) return 0;

    EVT("event=image phase=start name=\"%s\" kind=framework source=rescue", rel);
    dump_result_t dr = mmap_dump(abs_src, abs_dst, &sel);
    if (dr == DUMP_OK) {
        EVT("event=image phase=done name=\"%s\" kind=framework size=%u source=rescue",
            rel, sel.selected.crypt.cryptsize);
        return 1;
    }
    EVT("event=image phase=failed name=\"%s\" kind=framework reason=\"%s\" source=rescue",
        rel, dump_reason(dr));
    return 0;
}

// Recursively walk a bundle directory looking for encrypted Mach-Os not
// already covered by the target-task discovery loop. Skips top-level
// PlugIns/ and Extensions/ (handled by decrypt_appexes) and the bundle's
// main exec. Symlinks are not followed, to avoid loops.
static void rescue_walk(const char *bundle_src, const char *bundle_dst,
                        const runtime_image_t *runtime,
                        const char **dumped, int n_dumped,
                        const char *main_name,
                        const char *rel_dir, int depth, int *rescued) {
    char dir_path[4096];
    if (rel_dir[0])
        snprintf(dir_path, sizeof(dir_path), "%s/%s", bundle_src, rel_dir);
    else
        snprintf(dir_path, sizeof(dir_path), "%s", bundle_src);

    DIR *d = opendir(dir_path);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;

        // Top-level appex containers handled separately.
        if (depth == 0 &&
            (strcmp(e->d_name, "PlugIns") == 0 ||
             strcmp(e->d_name, "Extensions") == 0))
            continue;

        char rel[4096];
        if (rel_dir[0])
            snprintf(rel, sizeof(rel), "%s/%s", rel_dir, e->d_name);
        else
            snprintf(rel, sizeof(rel), "%s", e->d_name);

        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", dir_path, e->d_name);

        struct stat st;
        if (lstat(full, &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) continue;

        if (S_ISDIR(st.st_mode)) {
            rescue_walk(bundle_src, bundle_dst, runtime, dumped, n_dumped,
                        main_name, rel, depth + 1, rescued);
            continue;
        }
        if (!S_ISREG(st.st_mode)) continue;

        // Bundle's main exec lives at <bundle>/<name>; skip at depth 0.
        if (depth == 0 && main_name && main_name[0] &&
            strcmp(e->d_name, main_name) == 0) continue;

        if (rescue_try_dump(rel, bundle_src, bundle_dst, runtime,
                            dumped, n_dumped))
            (*rescued)++;
    }
    closedir(d);
}

// Recursively walk the bundle on disk and dump every encrypted Mach-O the
// target-task discovery loop didn't cover. Catches nested frameworks,
// embedded toolchains, and Developer/ payloads (e.g. Swift Playgrounds).
static int rescue_unmapped_frameworks(const char *bundle_src, const char *bundle_dst,
                                      const runtime_image_t *runtime,
                                      const char **dumped, int n_dumped,
                                      const char *main_name) {
    if (!runtime) return 0;
    int rescued = 0;
    rescue_walk(bundle_src, bundle_dst, runtime, dumped, n_dumped,
                main_name, "", 0, &rescued);
    return rescued;
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

    pid_t pid = 0;
    task_t task = MACH_PORT_NULL;
    int via_ptrace = 0;
    if (spawn_suspended(bundle_id, main_src, &pid, &task, &via_ptrace) != 0) {
        ERR("spawn failed for %s", bundle_src);
        EVT("event=spawn_failed src=\"%s\"", bundle_src);
        return 0; // non-fatal; continue with rest of the IPA
    }

    // 1) Dump the main exec. Fingerprint runtime arch from the loaded
    //    mach_header so slice selection matches what dyld actually mapped.
    //    FairPlay decrypts on page fault during mach_vm_read_overwrite,
    //    so this works even before dyld starts binding.
    runtime_image_t bundle_rt;
    int have_bundle_rt = 0;
    mach_vm_address_t main_base = 0;
    if (find_main_base(task, &main_base) == 0 &&
        read_runtime_image(task, main_base, &bundle_rt) == 0) {
        have_bundle_rt = 1;

        selected_slice_t sel;
        int sr = select_runtime_slice(main_src, &bundle_rt, &sel);
        if (sr == 1 && slice_needs_dump(&sel)) {
            LOG("[helper] dumping main %s (load=0x%llx, cryptsize=0x%x)\n",
                main_name, (unsigned long long)main_base,
                sel.selected.crypt.cryptsize);
            EVT("event=image phase=start name=\"%s\" kind=main", main_name);
            dump_result_t dr = dump_image(main_src, main_dst, task, main_base, &sel);
            if (dr == DUMP_OK) {
                EVT("event=image phase=done name=\"%s\" kind=main size=%u",
                    main_name, sel.selected.crypt.cryptsize);
            } else {
                EVT("event=image phase=failed name=\"%s\" kind=main reason=\"%s\"",
                    main_name, dump_reason(dr));
            }
        }
    } else {
        ERR("could not locate MH_EXECUTE base in %s", bundle_src);
        EVT("event=image phase=failed name=\"%s\" kind=main reason=\"no_exec_base\"",
            main_name);
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
    // Bundle-relative paths dumped here, fed to rescue pass to skip dupes.
    char **dumped_rel = NULL;
    int n_dumped = 0, dumped_cap = 0;
    // dyld image paths come back with a /private prefix that bundle_src
    // lacks. Match against both forms.
    const char *bs = bundle_src;
    size_t bs_len = strlen(bs);
    char bs_pri[4096];
    snprintf(bs_pri, sizeof(bs_pri), "/private%s", bs);
    const char *bs_alt = bs_pri;
    size_t bs_alt_len = strlen(bs_pri);

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

        // Reading the loaded header at imageLoadAddress doubles as a
        // sanity check (mach_vm_read of an unmapped region returns zeros)
        // and as the per-image runtime arch fingerprint.
        mach_vm_address_t base = (mach_vm_address_t)(uintptr_t)imgs[i].imageLoadAddress;
        runtime_image_t img_rt;
        if (read_runtime_image(task, base, &img_rt) != 0) {
            LOG("[helper] skip %s: header at 0x%llx not mapped\n",
                rel, (unsigned long long)base);
            continue;
        }
        if (!have_bundle_rt) {
            bundle_rt = img_rt;
            have_bundle_rt = 1;
        }

        selected_slice_t sel;
        if (select_runtime_slice(rel_src, &img_rt, &sel) != 1) continue;
        if (!slice_needs_dump(&sel)) continue;

        LOG("[helper] dumping %s (load=0x%llx, cryptsize=0x%x)\n", rel,
            (unsigned long long)base, sel.selected.crypt.cryptsize);
        EVT("event=image phase=start name=\"%s\" kind=framework", rel);
        dump_result_t dr = dump_image(rel_src, rel_dst, task, base, &sel);
        if (dr == DUMP_OK) {
            extra++;
            EVT("event=image phase=done name=\"%s\" kind=framework size=%u",
                rel, sel.selected.crypt.cryptsize);
            if (n_dumped >= dumped_cap) {
                dumped_cap = dumped_cap ? dumped_cap * 2 : 16;
                char **nb = realloc(dumped_rel, dumped_cap * sizeof(*nb));
                if (nb) dumped_rel = nb;
            }
            if (n_dumped < dumped_cap) {
                dumped_rel[n_dumped++] = strdup(rel);
            }
        } else {
            EVT("event=image phase=failed name=\"%s\" kind=framework reason=\"%s\"",
                rel, dump_reason(dr));
        }
    }
    free(paths); free(imgs);
    LOG("[helper] %s: dumped %d framework(s)\n", bundle_src, extra);

    // Tear the target down before the rescue pass so xpcproxy/launchd don't
    // hold the bundle paths busy while we mmap them.
    if (exc != MACH_PORT_NULL) {
        mach_port_mod_refs(mach_task_self(), exc, MACH_PORT_RIGHT_RECEIVE, -1);
        exc = MACH_PORT_NULL;
    }
    task_terminate(task);
    kill(pid, SIGKILL);
    int reaped;
    waitpid(pid, &reaped, WNOHANG);
    pid = 0;

    // 4) Rescue pass: target dyld may have aborted on a cross-OS bind-fail
    //    before mapping all @rpath frameworks; even on a clean dyld run,
    //    nested frameworks, embedded toolchains, and Developer/ payloads
    //    aren't loaded at launch. Recursively walk the bundle on disk,
    //    mmap each encrypted Mach-O, and decrypt via FairPlay page-fault
    //    on memcpy.
    int rescued = rescue_unmapped_frameworks(bundle_src, bundle_dst,
        have_bundle_rt ? &bundle_rt : NULL,
        (const char **)dumped_rel, n_dumped, main_name);
    extra += rescued;

    for (int i = 0; i < n_dumped; i++) free(dumped_rel[i]);
    free(dumped_rel);

    EVT("event=bundle phase=done src=\"%s\" extras=%d", bundle_src, extra);
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
