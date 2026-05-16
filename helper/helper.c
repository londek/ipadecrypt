// ipadecrypt-helper-arm64 - on-device FairPlay decrypter.
//
// Spawns target suspended (SBS or ptrace), reads dyld-mapped cryptoff
// pages via mach_vm_read_overwrite (kernel page-fault decrypts), then
// recursively walks the bundle and decrypts every still-encrypted Mach-O
// by injecting mremap_encrypted (syscall 489) into the target via thread
// hijack. Patches cryptid=0, packs IPA. Walks PlugIns/*.appex +
// Extensions/*.appex separately.
//
// CLI: ipadecrypt-helper-arm64 [-v] [--skip-appex] <bundle-id> <bundle-src> <out-ipa>
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

// pid_resume - drops the runningboardd-style "suspend whole proc" hold
// xpcproxy leaves on SBS-launched targets. task_resume() can't clear it,
// so target_call uses pid_resume after task_resume to ensure the
// hijacked thread is actually scheduled.
extern int pid_resume(int pid);

// mremap_encrypted: kernel hook (#489) used by dyld to flip an existing
// file-backed mmap into apple_protect_pager. On the next page fault the
// kernel forwards to fairplayd which returns plaintext for cryptid=1.
// Helper-context calls return EPERM under iOS-16 AMFI policy, but the same
// call from the spawned target succeeds because the target's CS context
// satisfies AMFI's text_crypter_create_hook gate. We thread-hijack the
// target to invoke it cross-task.
extern int mremap_encrypted(void *addr, size_t len,
                            uint32_t cryptid, uint32_t cputype, uint32_t cpusubtype);

// mach_vm cross-task primitives - SDK redirects mach_vm.h to an #error.
extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *,
    mach_vm_size_t, int);
extern kern_return_t mach_vm_write(vm_map_t, mach_vm_address_t,
    vm_offset_t, mach_msg_type_number_t);
extern kern_return_t mach_vm_protect(vm_map_t, mach_vm_address_t,
    mach_vm_size_t, boolean_t, vm_prot_t);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t,
    mach_vm_size_t);
extern kern_return_t mach_vm_machine_attribute(vm_map_t,
    mach_vm_address_t, mach_vm_size_t,
    vm_machine_attribute_t, vm_machine_attribute_val_t *);

#ifndef MATTR_CACHE
#define MATTR_CACHE 1
#endif
#ifndef MATTR_VAL_CACHE_FLUSH
#define MATTR_VAL_CACHE_FLUSH 6
#endif

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
static int g_skip_appex = 0;

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

// LC_CODE_SIGNATURE findings. Registered with the kernel via
// F_ADDFILESIGS_RETURN inside the inject pass; mremap_encrypted needs
// it to identify the file's vnode for apple_protect_pager.
typedef struct {
    int      has_cs;
    uint32_t cs_offset; // file offset of the CS blob within the slice
    uint32_t cs_size;
} cs_meta_t;

typedef struct {
    slice_meta_t slice;
    crypt_meta_t crypt;
    cs_meta_t    cs;
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
    case DUMP_ZERO_PAGES:     return "cryptoff_zero_pages";
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
    out->cs.has_cs = 0;

    const uint8_t *lc_end = slice + hdr_sz + szcmds;
    const uint8_t *lc_ptr = slice + hdr_sz;
    uint32_t want_crypt = is_64 ? LC_ENCRYPTION_INFO_64 : LC_ENCRYPTION_INFO;
    for (uint32_t i = 0; i < ncmds; i++) {
        if ((size_t)(lc_end - lc_ptr) < sizeof(struct load_command)) return -1;
        struct load_command lc;
        memcpy(&lc, lc_ptr, sizeof(lc));
        if (lc.cmdsize == 0 || (size_t)(lc_end - lc_ptr) < lc.cmdsize) return -1;

        if (lc.cmd == want_crypt) {
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
        } else if (lc.cmd == LC_CODE_SIGNATURE) {
            if (lc.cmdsize < sizeof(struct linkedit_data_command)) return -1;
            struct linkedit_data_command ldc;
            memcpy(&ldc, lc_ptr, sizeof(ldc));
            if ((uint64_t)ldc.dataoff + ldc.datasize > slice_size) return -1;
            out->cs.has_cs = 1;
            out->cs.cs_offset = ldc.dataoff;
            out->cs.cs_size = ldc.datasize;
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

// Stage `src` at `dst`. Files are hardlinked (instant, zero I/O) on the
// same filesystem; write_output() unlinks before O_CREAT so subsequent
// writes break the link without touching the original. Falls back to a
// real byte copy if link() fails (e.g. cross-filesystem). Symlinks and
// directories are recreated structurally so the bundle layout matches.
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
    if (link(src, dst) == 0) return 0;
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

    // Break any hardlink staging set up by copy_tree before writing,
    // otherwise O_TRUNC would also clobber the original installed bundle
    // (same inode). unlink() removes only this directory entry; the
    // original keeps its own.
    unlink(dst);
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
        // Snapshot the on-disk ciphertext so we can verify the vm_read
        // actually returned plaintext. FairPlay decrypt-on-fault doesn't
        // fire reliably across all jailbreak/iOS combos (notably iOS 15
        // dopamine); without this check we'd write cryptid=0 over still-
        // encrypted bytes and ship an IPA that looks decrypted but isn't.
        size_t crypt_off = (size_t)slice->slice.slice_offset +
                           (size_t)slice->crypt.cryptoff;
        size_t crypt_sz  = (size_t)slice->crypt.cryptsize;
        uint8_t *raw_copy = malloc(crypt_sz);
        if (!raw_copy) { free(buf); return DUMP_OOM; }
        memcpy(raw_copy, buf + crypt_off, crypt_sz);

        dump_result_t dr = vm_read_crypt_region(task, image_base, slice, buf);
        if (dr != DUMP_OK) { free(raw_copy); free(buf); return dr; }
        if (!crypt_region_has_data(buf, slice)) {
            ERR("cryptoff read all zeros for %s - target hadn't faulted the pages yet", src);
            free(raw_copy); free(buf); return DUMP_ZERO_PAGES;
        }
        if (memcmp(raw_copy, buf + crypt_off, crypt_sz) == 0) {
            ERR("FairPlay decrypt-on-page-fault did not fire for %s "
                "(cross-task vm_read returned the on-disk ciphertext "
                "verbatim); cryptid not patched, staged copy left "
                "encrypted", src);
            free(raw_copy); free(buf); return DUMP_VM_READ_FAIL;
        }
        free(raw_copy);
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

// Set an exception port on target and return its receive right.
//
// EXC_MASK_GUARD is critical: dyld's cross-OS bind-fail goes through
// abort_with_payload() which raises EXC_GUARD on the Mach side BEFORE the
// kernel converts it to SIGKILL. Catching EXC_GUARD freezes the target
// mid-abort with all currently-loaded frameworks still mapped, so we can
// vm_read them - without it, the SIGKILL terminates the process and any
// frameworks dyld didn't fully bind are lost. The other masks cover
// generic crashes (EXC_BAD_ACCESS, EXC_CRASH) we already saw.
static mach_port_t make_exception_port(task_t task) {
    mach_port_t port = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS) return MACH_PORT_NULL;
    if (mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
        mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
        return MACH_PORT_NULL;
    }
    // EXCEPTION_STATE_IDENTITY (vs EXCEPTION_DEFAULT) sends thread state in
    // the message and lets us reply with new state. iOS 16's
    // EXCEPTION_DEFAULT reply silently drops thread_set_state changes for
    // EXC_CRASH'd threads (verified empirically with Swift Playgrounds);
    // STATE_IDENTITY forces the kernel to apply our new state on
    // exception-handled resume, which is what makes inject-rescue work
    // for cross-OS bind-fail apps.
    if (task_set_exception_ports(task,
        EXC_MASK_CRASH | EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION |
        EXC_MASK_SOFTWARE | EXC_MASK_ARITHMETIC | EXC_MASK_BREAKPOINT |
        EXC_MASK_GUARD,
        port, EXCEPTION_STATE_IDENTITY, ARM_THREAD_STATE64) != KERN_SUCCESS) {
        mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
        return MACH_PORT_NULL;
    }
    return port;
}

// Map an exception_type_t to a short tag for events/logs.
static const char *exc_tag(int exc) {
    switch (exc) {
    case EXC_BAD_ACCESS:      return "EXC_BAD_ACCESS";
    case EXC_BAD_INSTRUCTION: return "EXC_BAD_INSTRUCTION";
    case EXC_ARITHMETIC:      return "EXC_ARITHMETIC";
    case EXC_EMULATION:       return "EXC_EMULATION";
    case EXC_SOFTWARE:        return "EXC_SOFTWARE";
    case EXC_BREAKPOINT:      return "EXC_BREAKPOINT";
    case EXC_SYSCALL:         return "EXC_SYSCALL";
    case EXC_MACH_SYSCALL:    return "EXC_MACH_SYSCALL";
    case EXC_RPC_ALERT:       return "EXC_RPC_ALERT";
    case EXC_CRASH:           return "EXC_CRASH";
    case EXC_RESOURCE:        return "EXC_RESOURCE";
    case EXC_GUARD:           return "EXC_GUARD";
    case EXC_CORPSE_NOTIFY:   return "EXC_CORPSE_NOTIFY";
    default:                  return "EXC_UNKNOWN";
    }
}

// Reply to a received EXCEPTION_STATE_IDENTITY mach_msg, sending new
// thread state in the reply payload. Kernel applies the new state on
// resume - critical for iOS 16, where EXCEPTION_DEFAULT-flavor reply
// silently drops earlier thread_set_state changes.
//
// Reply layout (msgh_id = original + 100, e.g. 2403->2503):
//   mach_msg_header_t hdr (24)
//   NDR_record (8)
//   kern_return_t retcode (4)
//   int flavor (4)
//   mach_msg_type_number_t new_stateCnt (4)
//   natural_t new_state[count] (count * 4 bytes)
//
// Pass new_state=NULL/state_count=0 to keep current state and only
// release the thread (used for sentinel SEGVs we don't want to
// re-deliver to the next handler).
static mach_msg_return_t reply_exception_with_state(const mach_msg_header_t *received_hdr,
                                                    const arm_thread_state64_t *new_state) {
    if (!received_hdr || received_hdr->msgh_remote_port == MACH_PORT_NULL)
        return MACH_SEND_INVALID_DEST;
    struct {
        mach_msg_header_t hdr;
        char ndr[8];
        int32_t retcode;
        int32_t flavor;
        uint32_t state_count;
        uint32_t state_data[ARM_THREAD_STATE64_COUNT];
    } reply;
    memset(&reply, 0, sizeof(reply));
    reply.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    reply.hdr.msgh_remote_port = received_hdr->msgh_remote_port;
    reply.hdr.msgh_local_port = MACH_PORT_NULL;
    reply.hdr.msgh_id = received_hdr->msgh_id + 100;
    reply.retcode = KERN_SUCCESS;
    reply.flavor = ARM_THREAD_STATE64;
    if (new_state) {
        reply.state_count = ARM_THREAD_STATE64_COUNT;
        memcpy(reply.state_data, new_state, sizeof(arm_thread_state64_t));
        reply.hdr.msgh_size = (mach_msg_size_t)(
            sizeof(mach_msg_header_t) + 8 + 4 + 4 + 4 +
            sizeof(arm_thread_state64_t));
    } else {
        reply.state_count = 0;
        reply.hdr.msgh_size = (mach_msg_size_t)(
            sizeof(mach_msg_header_t) + 8 + 4 + 4 + 4);
    }
    return mach_msg(&reply.hdr, MACH_SEND_MSG, reply.hdr.msgh_size, 0,
             MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

// Decode a Mach exception_raise message. Handles both EXCEPTION_DEFAULT
// (msgh_id=2401) and EXCEPTION_STATE_IDENTITY (msgh_id=2403) - the latter
// includes thread state inline. Returns 1 if parsed, sets *out_state if
// non-NULL and the message carried a state payload.
static int decode_exception(const void *buf, mach_msg_size_t buf_sz,
                            int *exc_out, int64_t *code0_out,
                            int64_t *code1_out, int *signal_out,
                            arm_thread_state64_t *out_state) {
    if (buf_sz < 76) return 0;
    const uint8_t *p = (const uint8_t *)buf;
    mach_msg_header_t hdr;
    memcpy(&hdr, p, sizeof(hdr));
    if (hdr.msgh_id != 2401 && hdr.msgh_id != 2403) return 0;

    // Layout is identical up through the codes array. STATE_IDENTITY
    // adds flavor+old_stateCnt+old_state after the codes. Codes are
    // mach_exception_data_type_t (int64_t) on 64-bit since EXC_MASK_*
    // is delivered as 64-bit codes in iOS 16.
    int exc; uint32_t code_cnt;
    memcpy(&exc, p + 60, sizeof(exc));
    memcpy(&code_cnt, p + 64, sizeof(code_cnt));

    // iOS arm64 sends 4-byte codes when behavior doesn't include the
    // MACH_EXCEPTION_CODES flag - we use plain EXCEPTION_STATE_IDENTITY
    // so codes are exception_data_type_t (uint32_t). For full 64-bit
    // PC values (e.g. EXC_BREAKPOINT fault address) the caller should
    // use the out_state payload's __pc field instead of code1.
    int32_t c0 = 0, c1 = 0;
    if (code_cnt >= 1 && buf_sz >= 72) memcpy(&c0, p + 68, 4);
    if (code_cnt >= 2 && buf_sz >= 76) memcpy(&c1, p + 72, 4);
    *exc_out = exc;
    *code0_out = c0;
    *code1_out = c1;
    *signal_out = (exc == EXC_CRASH) ? ((c0 >> 24) & 0xff) : 0;

    if (hdr.msgh_id == 2403 && out_state) {
        // State payload offset: codes_end + flavor(4) + state_cnt(4)
        size_t codes_end = 68 + (size_t)code_cnt * 4;
        if (buf_sz >= codes_end + 8 + sizeof(arm_thread_state64_t)) {
            memcpy(out_state, p + codes_end + 8, sizeof(arm_thread_state64_t));
        }
    }
    return 1;
}

// Stashed copy of the most recent received Mach exception header. The
// kernel holds the faulting thread in MACH_RECV_REPLY until this header's
// reply port gets a KERN_SUCCESS - so we can't resume that thread (e.g.
// to hijack it for dlopen injection) until reply_exception_default is
// called against this header. run_and_suspend stashes; inject path
// flushes after thread_set_state.
static mach_msg_header_t g_pending_exc_hdr;
static int g_pending_exc_valid = 0;

// Resume target and wait up to `ms` for either a Mach exception (cross-OS
// bind-fail abort) or timeout, then suspend the task so the caller has a
// stable address space to walk.
//
// Both spawn paths set up a Mach exception port now: dyld's bind-fail
// raises EXC_GUARD via abort_with_payload BEFORE the kernel converts it
// to SIGKILL, so catching the Mach exception freezes the target with all
// loaded frameworks still mapped - whereas waiting for waitpid SIGKILL
// loses everything dyld didn't already commit. The ptrace path additionally
// drains stop-notifications via waitpid because PT_TRACE_ME steals SIGTRAP/
// SIGSTOP routing; we PT_CONTINUE through those while polling.
static void run_and_suspend(task_t task, pid_t pid, int via_ptrace,
                             mach_port_t exc_port, int ms) {
    // Stale pending-exception state from a prior bundle's inject would
    // make target_call reply to a dead port. Always start clean.
    g_pending_exc_valid = 0;
    if (via_ptrace) {
        // Kick the target out of its initial PT_TRACE_ME stop. PT_CONTINUE
        // delivers signal=0 (no signal) and lets the child run.
        ptrace(PT_CONTINUE, pid, (void *)1, 0);
    } else {
        // SBS leaves the task with potentially multiple suspensions
        // (task itself + runningboardd assertion). Drain until suspend
        // count is 0 so threads actually run.
        while (task_resume(task) == KERN_SUCCESS) { /* loop */ }
    }

    if (exc_port != MACH_PORT_NULL) {
        struct { mach_msg_header_t hdr; char body[2048]; } msg;
        // Poll mach_msg + waitpid concurrently in 200ms slices: Mach
        // exception fires first on dyld bind-fail, but if the kernel went
        // straight to SIGKILL (no Mach hop) waitpid catches the exit.
        int waited = 0;
        int trapped_via_mach = 0;
        int exited = 0, signaled = 0, exit_code = 0, exit_sig = 0;
        int exc = 0, sig = 0;
        int64_t c0 = 0, c1 = 0;
        mach_msg_return_t mr = MACH_RCV_TIMED_OUT;

        while (waited < ms) {
            memset(&msg, 0, sizeof(msg));
            mr = mach_msg(&msg.hdr,
                MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(msg),
                exc_port, 200, MACH_PORT_NULL);
            if (mr == MACH_MSG_SUCCESS) {
                trapped_via_mach = 1;
                decode_exception(&msg, msg.hdr.msgh_size,
                    &exc, &c0, &c1, &sig, NULL);
                // Stash header so the inject path can reply to release
                // the faulting thread from MACH_RECV_REPLY before
                // hijacking it.
                g_pending_exc_hdr = msg.hdr;
                g_pending_exc_valid = 1;
                EVT("event=dyld phase=exc_msg msgh_bits=0x%x msgh_size=%u "
                    "msgh_remote=0x%x msgh_local=0x%x msgh_id=%d",
                    msg.hdr.msgh_bits, msg.hdr.msgh_size,
                    msg.hdr.msgh_remote_port, msg.hdr.msgh_local_port,
                    msg.hdr.msgh_id);
                break;
            }
            if (via_ptrace) {
                int st;
                pid_t w = waitpid(pid, &st, WNOHANG | WUNTRACED);
                if (w == pid) {
                    if (WIFEXITED(st)) {
                        exited = 1; exit_code = WEXITSTATUS(st); break;
                    }
                    if (WIFSIGNALED(st)) {
                        signaled = 1; exit_sig = WTERMSIG(st); break;
                    }
                    if (WIFSTOPPED(st)) {
                        int s = WSTOPSIG(st);
                        int deliver = (s == SIGTRAP || s == SIGSTOP) ? 0 : s;
                        ptrace(PT_CONTINUE, pid, (void *)1, deliver);
                    }
                }
            }
            waited += 200;
        }

        if (trapped_via_mach) {
            const char *via = via_ptrace ? "ptrace+mach" : "mach";
            LOG("[helper] target trapped: %s code0=0x%llx code1=0x%llx signal=%d via=%s\n",
                exc_tag(exc),
                (unsigned long long)c0, (unsigned long long)c1, sig, via);
            EVT("event=dyld phase=trapped via=%s exception=%s "
                "code0=0x%llx code1=0x%llx signal=%d mach_msg=0x%x",
                via, exc_tag(exc),
                (unsigned long long)c0, (unsigned long long)c1, sig, mr);

            // dyld halt brk caught. Leave the exception unreplied so the
            // kernel keeps the thread paused with full task memory still
            // mapped for vm_read + cross-task mach_vm_allocate. Replying
            // would resume the thread which immediately re-traps at the
            // same brk (cs_validation re-pages it) and the kernel reaps
            // the task. Caller dumps whatever dyld already mapped, then
            // injects mremap_encrypted on the rest.
        } else if (exited) {
            EVT("event=dyld phase=trapped via=ptrace outcome=exited code=%d", exit_code);
        } else if (signaled) {
            EVT("event=dyld phase=trapped via=ptrace outcome=signaled signal=%d", exit_sig);
        } else {
            const char *via = via_ptrace ? "ptrace" : "mach";
            EVT("event=dyld phase=settled via=%s mach_msg=0x%x", via, mr);
        }
        task_suspend(task);
        return;
    }

    // Fallback for unusual paths where no exception port was created.
    usleep(ms * 1000);
    EVT("event=dyld phase=settled via=sleep");
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

// fcntl(F_ADDFILESIGS_RETURN) takes this layout. Pulled in here because
// <sys/fcntl.h> hides it on iOS, and we don't want to depend on the SDK's
// userland headers.
#ifndef F_ADDFILESIGS_RETURN
#define F_ADDFILESIGS_RETURN 97
#endif
typedef struct {
    off_t  fs_file_start;  // file offset of Mach-O slice (0 for thin)
    void  *fs_blob_start;  // for F_ADDFILESIGS*: file offset of CS blob
    size_t fs_blob_size;   // CS blob size
} helper_fsignatures_t;



#define INJECT_SENTINEL_LR 0x4141414141414141ULL



// Run a single function call in target context, hijacking the supplied
// thread. Caller must already have:
//   - exception port set on task and ours to read
//   - any prior pending Mach exception stashed in g_pending_exc_hdr (this
//     function replies to release the thread before resuming)
// Returns 0 on sentinel hit, sets *out_x0 to the call's return value.
// Returns -1 if mach_msg timed out or returned a non-sentinel exception.
static int target_call(task_t task, thread_act_t thread, mach_port_t exc_port,
                       mach_vm_address_t pc,
                       uint64_t x0, uint64_t x1, uint64_t x2,
                       uint64_t x3, uint64_t x4, uint64_t x5,
                       mach_vm_address_t sp,
                       uint64_t *out_x0, int wait_ms) {
    if (thread_suspend(thread) != KERN_SUCCESS) return -1;
    // thread_abort_safely only aborts interruptible waits (kqueue, sleep,
    // condvar). Threads blocked in non-interruptible waits (e.g. mach_msg
    // RECV that can't be cancelled) need thread_abort to actually leave
    // kernel mode; without it our thread_set_state appears applied but the
    // thread never runs because the kernel restores its saved syscall
    // state on resume.
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
    thread_resume(thread);

    // Drop any extra thread suspends from the abort_safely + suspend cycle.
    for (int i = 0; i < 8; i++) {
        if (thread_resume(thread) != KERN_SUCCESS) break;
    }

    // Reply to whatever exception is pending so the kernel schedules the
    // thread. Use STATE_IDENTITY reply payload to deliver our new state -
    // iOS 16's EXCEPTION_DEFAULT reply silently drops our prior
    // thread_set_state for EXC_CRASH'd threads.
    if (g_pending_exc_valid) {
        reply_exception_with_state(&g_pending_exc_hdr, &s);
        g_pending_exc_valid = 0;
    }

    // Drain task suspends + drop the runningboardd hold (xpcproxy leaves
    // a separate "proc suspended" assertion on SBS-launched targets that
    // task_resume can't clear; without pid_resume, the hijacked thread
    // stays paused even with thread+task suspend counts at zero).
    for (int i = 0; i < 16; i++) {
        if (task_resume(task) != KERN_SUCCESS) break;
    }
    pid_t pid_for = 0;
    if (pid_for_task(task, &pid_for) == KERN_SUCCESS && pid_for > 0)
        pid_resume(pid_for);

    // Wait for sentinel SEGV.
    struct { mach_msg_header_t hdr; char body[2048]; } msg;
    memset(&msg, 0, sizeof(msg));
    mach_msg_return_t mr = mach_msg(&msg.hdr,
        MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(msg),
        exc_port, wait_ms, MACH_PORT_NULL);
    if (mr != MACH_MSG_SUCCESS) {
        // Read final state for context.
        arm_thread_state64_t fs = {0};
        mach_msg_type_number_t fsc = ARM_THREAD_STATE64_COUNT;
        if (thread_get_state(thread, ARM_THREAD_STATE64,
                (thread_state_t)&fs, &fsc) == KERN_SUCCESS) {
            EVT("event=inject phase=target_call_timeout pc=0x%llx lr=0x%llx x0=0x%llx mr=0x%x",
                (unsigned long long)fs.__pc, (unsigned long long)fs.__lr,
                (unsigned long long)fs.__x[0], mr);
        } else {
            EVT("event=inject phase=target_call_timeout mr=0x%x state_unreadable=1", mr);
        }
        return -1;
    }

    int exc = 0, sig = 0;
    int64_t c0 = 0, c1 = 0;
    decode_exception(&msg, msg.hdr.msgh_size, &exc, &c0, &c1, &sig, NULL);
    g_pending_exc_hdr = msg.hdr;
    g_pending_exc_valid = 1;

    unsigned long long fault = (unsigned long long)c1;
    if (exc != EXC_BAD_ACCESS ||
        (fault != INJECT_SENTINEL_LR &&
         fault != (INJECT_SENTINEL_LR & 0xfffffffful))) {
        // Not our sentinel - syscall faulted somewhere unexpected.
        arm_thread_state64_t fs = {0};
        mach_msg_type_number_t fsc = ARM_THREAD_STATE64_COUNT;
        if (thread_get_state(thread, ARM_THREAD_STATE64,
                (thread_state_t)&fs, &fsc) == KERN_SUCCESS) {
            EVT("event=inject phase=target_call_crashed exc=%d code1=0x%llx pc=0x%llx x0=0x%llx",
                exc, fault, (unsigned long long)fs.__pc,
                (unsigned long long)fs.__x[0]);
        } else {
            EVT("event=inject phase=target_call_crashed exc=%d code1=0x%llx",
                exc, fault);
        }
        return -1;
    }

    arm_thread_state64_t fs = {0};
    mach_msg_type_number_t fsc = ARM_THREAD_STATE64_COUNT;
    if (thread_get_state(thread, ARM_THREAD_STATE64,
            (thread_state_t)&fs, &fsc) != KERN_SUCCESS) return -1;
    if (out_x0) *out_x0 = fs.__x[0];
    EVT("event=inject phase=target_call_returned x0=0x%llx", (unsigned long long)fs.__x[0]);
    return 0;
}

#ifndef VM_PROT_COPY
#define VM_PROT_COPY 0x10
#endif

// abort_with_payload - dyld's halt() routes through this for cross-OS
// bind-fail aborts. Patched to `ret` pre-resume so dyld silently falls
// through; mapped frameworks stay readable for vm_read instead of going
// through SIGABRT -> EXC_CRASH -> task reaped.
extern int abort_with_payload(uint32_t reason_namespace, uint64_t reason_code,
    void *payload, uint32_t payload_size, const char *reason_string,
    uint64_t reason_flags);

// Find target's libdyld base via image list, falling back to
// dyld_all_image_infos.dyldImageLoadAddress when dyld halted before
// registering libdyld in its infoArray.
static mach_vm_address_t find_target_dlopen_image(task_t task,
                                                  struct dyld_image_info *imgs,
                                                  uint32_t img_count,
                                                  const char *helper_path) {
    if (helper_path) {
        const char *helper_base = strrchr(helper_path, '/');
        helper_base = helper_base ? helper_base + 1 : helper_path;
        for (uint32_t i = 0; i < img_count; i++) {
            const char *p = imgs[i].imageFilePath;
            if (!p) continue;
            const char *b = strrchr(p, '/');
            b = b ? b + 1 : p;
            if (strcmp(b, helper_base) == 0)
                return (mach_vm_address_t)(uintptr_t)imgs[i].imageLoadAddress;
        }
    }
    static const char *needles[] = { "libdyld.dylib", "/usr/lib/dyld", NULL };
    for (int n = 0; needles[n]; n++) {
        for (uint32_t i = 0; i < img_count; i++) {
            const char *p = imgs[i].imageFilePath;
            if (p && strstr(p, needles[n]))
                return (mach_vm_address_t)(uintptr_t)imgs[i].imageLoadAddress;
        }
    }
    struct task_dyld_info tdi;
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&tdi, &cnt) == KERN_SUCCESS) {
        struct dyld_all_image_infos aii = {0};
        mach_vm_size_t got = 0;
        if (mach_vm_read_overwrite(task, tdi.all_image_info_addr, sizeof(aii),
                (mach_vm_address_t)(uintptr_t)&aii, &got) == KERN_SUCCESS &&
            aii.dyldImageLoadAddress) {
            return (mach_vm_address_t)(uintptr_t)aii.dyldImageLoadAddress;
        }
    }
    return 0;
}

// Compute target-side address of a helper-linked function via dladdr +
// shared-cache slide assumption. Helper and target share one slide so
// (target_libdyld_base + (helper_func - helper_libdyld_base)) is correct
// for any function in the shared cache.
static mach_vm_address_t target_func_addr(task_t task,
                                          struct dyld_image_info *imgs,
                                          uint32_t img_count,
                                          void *helper_func,
                                          mach_vm_address_t target_libdyld_fb,
                                          mach_vm_address_t helper_libdyld_fb) {
    if (!helper_func) return 0;
    Dl_info info = {0};
    if (dladdr(helper_func, &info) && info.dli_fbase) {
        mach_vm_address_t target_base = find_target_dlopen_image(task, imgs,
            img_count, info.dli_fname);
        if (target_base) {
            mach_vm_address_t off = (mach_vm_address_t)(uintptr_t)helper_func -
                (mach_vm_address_t)(uintptr_t)info.dli_fbase;
            return target_base + off;
        }
    }
    if (target_libdyld_fb && helper_libdyld_fb) {
        return target_libdyld_fb +
            ((mach_vm_address_t)(uintptr_t)helper_func - helper_libdyld_fb);
    }
    return 0;
}

// COW + write `bytes` at addr in target, then restore RX. Crosses one
// page boundary at most. Used for libc abort -> ret (4 bytes) and dyld
// inline syscall pair -> nop;nop (8 bytes).
static int patch_target_bytes(task_t task, mach_vm_address_t addr,
                              const void *bytes, size_t len, const char *tag) {
    if (!addr) {
        EVT("event=patch phase=skip tag=%s reason=no_addr", tag);
        return -1;
    }
    mach_vm_address_t page = addr & ~(mach_vm_address_t)0xfff;
    mach_vm_size_t span = ((addr + len - page + 0xfff) & ~(mach_vm_size_t)0xfff);
    EVT("event=patch phase=start tag=%s addr=0x%llx", tag,
        (unsigned long long)addr);
    if (mach_vm_protect(task, page, span, FALSE,
            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) return -1;
    if (mach_vm_write(task, addr, (vm_offset_t)(uintptr_t)bytes,
            (mach_msg_type_number_t)len) != KERN_SUCCESS) return -1;
    mach_vm_protect(task, page, span, FALSE,
        VM_PROT_READ | VM_PROT_EXECUTE);
    EVT("event=patch phase=done tag=%s", tag);
    return 0;
}

// Scan dyld __TEXT for `mov x16, #N; svc #0x80` and NOP every match
// where N is a process-killing syscall (abort_with_payload, terminate,
// __exit, kill, __pthread_kill, __bsdthread_terminate).
static int scan_dyld_for_abort_syscalls(task_t task, mach_vm_address_t dyld_base) {
    if (!dyld_base) {
        EVT("event=patch phase=scan_skip reason=no_dyld_base");
        return 0;
    }
    struct mach_header_64 mh;
    mach_vm_size_t got = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, dyld_base, sizeof(mh),
            (mach_vm_address_t)(uintptr_t)&mh, &got);
    if (kr != KERN_SUCCESS) {
        EVT("event=patch phase=scan_skip reason=read_mh_fail kr=%d base=0x%llx",
            kr, (unsigned long long)dyld_base);
        return 0;
    }
    if (mh.magic != MH_MAGIC_64) {
        EVT("event=patch phase=scan_skip reason=bad_magic magic=0x%x base=0x%llx",
            mh.magic, (unsigned long long)dyld_base);
        return 0;
    }
    // Read dyld __TEXT in 64K chunks - pages may be lazily mapped
    // pre-resume, so a 4MB single read fails on the first not-yet-faulted
    // page. Stop at first chunk that fails; we usually have ~1-2 MB of
    // dyld __TEXT mapped by the time the task is suspended for us.
    size_t text_cap = 4 * 1024 * 1024;
    uint8_t *buf = malloc(text_cap);
    if (!buf) return 0;
    size_t total = 0;
    const size_t chunk = 0x10000;
    while (total < text_cap) {
        mach_vm_size_t cgot = 0;
        if (mach_vm_read_overwrite(task, dyld_base + total, chunk,
                (mach_vm_address_t)(uintptr_t)(buf + total), &cgot) != KERN_SUCCESS ||
            cgot == 0) break;
        total += cgot;
        if (cgot < chunk) break;
    }
    got = total;
    if (got < 8) {
        free(buf);
        EVT("event=patch phase=scan_skip reason=no_text_bytes");
        return 0;
    }
    EVT("event=patch phase=scan_text bytes=0x%llx", (unsigned long long)got);
    static const uint8_t svc_pattern[4] = { 0x01, 0x10, 0x00, 0xd4 };
    int kills = 0;
    for (size_t i = 4; i + 4 <= got; i += 4) {
        if (memcmp(buf + i, svc_pattern, 4) != 0) continue;
        uint32_t prev;
        memcpy(&prev, buf + i - 4, 4);
        // movz x16, #imm  or  movz w16, #imm
        if (((prev & 0xffe0001f) != (0xd2800000 | 16)) &&
            ((prev & 0xffe0001f) != (0x52800000 | 16))) continue;
        uint32_t imm = (prev >> 5) & 0xffff;
        if (imm == 0x209 || imm == 0x208 || imm == 0x20c || imm == 0x20d ||
            imm == 0x169 || imm == 0x148 || imm == 0x1   || imm == 0x25) {
            static const uint32_t nop_pair[2] = { 0xd503201fu, 0xd503201fu };
            char tag[64];
            snprintf(tag, sizeof(tag), "dyld_kill_syscall_%u_%d", imm, kills);
            if (patch_target_bytes(task, dyld_base + i - 4, nop_pair,
                    sizeof(nop_pair), tag) == 0) kills++;
        }
    }
    free(buf);
    EVT("event=patch phase=scan_done kills=%d", kills);
    return kills;
}

// Patch every dyld halt path so cross-OS bind-fail returns silently
// instead of raising SIGABRT -> EXC_CRASH (which kills the task and
// breaks the inject pass). Two layers:
//   1. libsystem entry points (abort_with_payload/abort) -> ret
//   2. dyld __TEXT inline syscall pairs -> nop;nop
static int patch_target_abort(task_t task,
                              struct dyld_image_info *imgs, uint32_t img_count,
                              mach_vm_address_t target_libdyld_fb,
                              mach_vm_address_t helper_libdyld_fb) {
    int hits = 0;
    static const char *names[] = { "abort_with_payload", "__abort_with_payload",
                                   "abort", NULL };
    static const uint32_t ret_op = 0xd65f03c0;
    for (int i = 0; names[i]; i++) {
        void *helper_fn = dlsym(RTLD_DEFAULT, names[i]);
        if (!helper_fn) continue;
        mach_vm_address_t a = target_func_addr(task, imgs, img_count,
            helper_fn, target_libdyld_fb, helper_libdyld_fb);
        if (patch_target_bytes(task, a, &ret_op, sizeof(ret_op), names[i]) == 0)
            hits++;
    }
    // Use target_libdyld_fb as the dyld base. iOS 16 merges dyld and
    // libdyld at the same shared-cache slide, so the libdyld base is
    // also dyld's __TEXT base for our svc-pattern scan. Falling back to
    // task_info / dyld_all_image_infos picks up the same value when dyld
    // populated aii pre-trap.
    mach_vm_address_t dyld_base = target_libdyld_fb;
    if (!dyld_base) {
        struct task_dyld_info tdi;
        mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
        if (task_info(task, TASK_DYLD_INFO, (task_info_t)&tdi, &cnt) == KERN_SUCCESS) {
            struct dyld_all_image_infos aii = {0};
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(task, tdi.all_image_info_addr, sizeof(aii),
                    (mach_vm_address_t)(uintptr_t)&aii, &got) == KERN_SUCCESS) {
                dyld_base = (mach_vm_address_t)(uintptr_t)aii.dyldImageLoadAddress;
            }
        }
    }
    hits += scan_dyld_for_abort_syscalls(task, dyld_base);
    return hits;
}


// Pick a target pthread to hijack. Prefer a non-zero idle thread
// (TH_STATE_WAITING/HALTED/STOPPED) - picking a thread mid-syscall
// breaks because thread_abort_safely + thread_set_state can leave it
// resuming the original syscall instead of our injected PC. Fall back
// to thread 0 (dyld bootstrap, only thread alive after halt) when no
// idle non-zero thread exists.
static thread_act_t pick_hijack_thread(task_t task) {
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    if (task_threads(task, &threads, &count) != KERN_SUCCESS || !threads)
        return MACH_PORT_NULL;
    thread_act_t chosen = MACH_PORT_NULL;
    // Prefer the LAST non-zero idle thread - most-recently-created
    // pthread is least likely to be holding global locks. Iterate forward
    // and overwrite chosen so the loop ends on the latest idle match.
    for (mach_msg_type_number_t i = 1; i < count; i++) {
        struct thread_basic_info tbi;
        mach_msg_type_number_t tic = THREAD_BASIC_INFO_COUNT;
        if (thread_info(threads[i], THREAD_BASIC_INFO,
                (thread_info_t)&tbi, &tic) != KERN_SUCCESS) continue;
        // 2 = TH_STATE_STOPPED, 3 = TH_STATE_WAITING, 5 = TH_STATE_HALTED.
        if (tbi.run_state == 2 || tbi.run_state == 3 || tbi.run_state == 5)
            chosen = threads[i];
    }
    if (chosen == MACH_PORT_NULL) chosen = threads[0];
    if (chosen != MACH_PORT_NULL) {
        mach_port_mod_refs(mach_task_self(), chosen, MACH_PORT_RIGHT_SEND, +1);
        EVT("event=inject phase=hijack_pick thread=%u total=%d", chosen, count);
    } else {
        EVT("event=inject phase=hijack_pick thread=NONE total=%d", count);
    }
    for (mach_msg_type_number_t i = 0; i < count; i++)
        mach_port_deallocate(mach_task_self(), threads[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(*threads));
    return chosen;
}


// Inject open/fcntl/mmap syscall chain into target context to map an
// Inject open + fcntl(F_ADDFILESIGS_RETURN) + mmap + mremap_encrypted
// into target via the hijacked thread. The mremap call is what attaches
// apple_protect_pager so caller's mach_vm_read returns plaintext for
// the cryptoff range. Helper-context mremap_encrypted EPERMs under iOS 16
// AMFI; running it from target context satisfies text_crypter_create_hook.
//
// Returns 0 with *out_addr = target's mapping base. Leaks scratch on
// success - target gets task_terminate'd shortly.
static int inject_mmap_in_target(task_t task, mach_port_t exc_port,
                                 thread_act_t thread,
                                 const char *path,
                                 const selected_slice_t *sel,
                                 mach_vm_address_t *out_addr,
                                 size_t *out_size) {
    if (!sel->selected.cs.has_cs) {
        EVT("event=inject phase=mmap_skipped reason=no_cs_blob");
        return -1;
    }

    // Allocate one scratch page for [path][fsignatures] + one trampoline
    // page for raw syscall stubs. Raw stubs avoid libc cerror_nocancel,
    // which derefs pthread TLS on errors - bootstrap thread has no TLS.
    size_t path_len = strlen(path) + 1;
    size_t scratch_size = ((path_len + sizeof(helper_fsignatures_t) + 0xfff)
                          & ~(size_t)0xfff);
    mach_vm_address_t scratch = 0, tramp = 0;
    if (mach_vm_allocate(task, &scratch, scratch_size, VM_FLAGS_ANYWHERE)
            != KERN_SUCCESS) {
        EVT("event=inject phase=mmap_alloc_fail");
        return -1;
    }
    if (mach_vm_allocate(task, &tramp, 0x4000, VM_FLAGS_ANYWHERE)
            != KERN_SUCCESS) {
        EVT("event=inject phase=tramp_alloc_fail");
        mach_vm_deallocate(task, scratch, scratch_size);
        return -1;
    }

    // Lay out scratch.
    mach_vm_address_t target_path = scratch;
    mach_vm_address_t target_fs   = scratch + ((path_len + 7) & ~7ULL);
    helper_fsignatures_t fs = {
        .fs_file_start = sel->selected.slice.slice_offset,
        .fs_blob_start = (void *)(uintptr_t)sel->selected.cs.cs_offset,
        .fs_blob_size  = sel->selected.cs.cs_size,
    };
    if (mach_vm_write(task, target_path, (vm_offset_t)(uintptr_t)path,
            (mach_msg_type_number_t)path_len) != KERN_SUCCESS ||
        mach_vm_write(task, target_fs, (vm_offset_t)(uintptr_t)&fs,
            sizeof(fs)) != KERN_SUCCESS) {
        mach_vm_deallocate(task, tramp, 0x4000);
        mach_vm_deallocate(task, scratch, scratch_size);
        return -1;
    }

    // Build trampolines: each 16-byte slot is `movz x16,#N; svc #0x80; ret`.
    // Slots: 0=open(5), 1=fcntl(92), 2=mmap(197), 3=mremap_encrypted(489).
    static const uint32_t syscalls[4] = { 5, 92, 197, 489 };
    uint32_t buf[4 * 4] = {0};
    for (int i = 0; i < 4; i++) {
        uint32_t *slot = &buf[i * 4];
        slot[0] = 0xD2800010u | (syscalls[i] << 5);
        slot[1] = 0xD4001001u;
        slot[2] = slot[3] = 0xD65F03C0u;
    }

    // Prefault trampoline at slot offset 64. After mremap_encrypted attaches
    // apple_protect_pager to the crypt region, the kernel still won't run
    // fairplayd until something inside the *target* task touches each page.
    // Cross-task vm_read doesn't trigger that fault path - on iOS combos
    // where dyld halts before binding (e.g. iOS 16.1.1 Dopamine), the
    // helper would otherwise read raw on-disk ciphertext.
    //
    //   prefault(x0=base, x1=size, x2=stride):
    //     cbz   x1, .ret
    //   .lp: ldrb  w3, [x0]
    //     add   x0, x0, x2
    //     subs  x1, x1, x2
    //     b.hi  .lp
    //   .ret: ret
    static const uint32_t prefault[6] = {
        0xB40000A1u, // cbz x1, +20
        0x39400003u, // ldrb w3, [x0]
        0x8B020000u, // add x0, x0, x2
        0xEB020021u, // subs x1, x1, x2
        0x54FFFFA8u, // b.hi -12
        0xD65F03C0u, // ret
    };
    if (mach_vm_write(task, tramp, (vm_offset_t)(uintptr_t)buf, sizeof(buf))
            != KERN_SUCCESS ||
        mach_vm_write(task, tramp + sizeof(buf),
            (vm_offset_t)(uintptr_t)prefault, sizeof(prefault)) != KERN_SUCCESS ||
        mach_vm_protect(task, tramp, 0x4000, FALSE,
            VM_PROT_READ | VM_PROT_EXECUTE) != KERN_SUCCESS) {
        EVT("event=inject phase=tramp_write_fail");
        mach_vm_deallocate(task, tramp, 0x4000);
        mach_vm_deallocate(task, scratch, scratch_size);
        return -1;
    }
    {
        vm_machine_attribute_val_t cv = MATTR_VAL_CACHE_FLUSH;
        mach_vm_machine_attribute(task, tramp, 0x4000, MATTR_CACHE, &cv);
    }
    const mach_vm_address_t tramp_open     = tramp + 0;
    const mach_vm_address_t tramp_fcntl    = tramp + 16;
    const mach_vm_address_t tramp_mmap     = tramp + 32;
    const mach_vm_address_t tramp_mremap   = tramp + 48;
    const mach_vm_address_t tramp_prefault = tramp + sizeof(buf);

    // open(path, O_RDONLY)
    uint64_t fd = 0;
    if (target_call(task, thread, exc_port, tramp_open,
            target_path, O_RDONLY, 0, 0, 0, 0, 0, &fd, 15000) != 0 ||
        (int32_t)fd < 0) {
        EVT("event=inject phase=mmap_open_fail");
        mach_vm_deallocate(task, tramp, 0x4000);
        mach_vm_deallocate(task, scratch, scratch_size);
        return -1;
    }

    // fcntl(fd, F_ADDFILESIGS_RETURN, &fs) - registers cs_blob.
    uint64_t fcr = 0;
    if (target_call(task, thread, exc_port, tramp_fcntl,
            fd, F_ADDFILESIGS_RETURN, target_fs, 0, 0, 0, 0, &fcr, 10000) != 0) {
        EVT("event=inject phase=mmap_fcntl_fail");
        mach_vm_deallocate(task, tramp, 0x4000);
        mach_vm_deallocate(task, scratch, scratch_size);
        return -1;
    }

    // mmap(NULL, file_sz, PROT_READ|PROT_EXEC, MAP_PRIVATE, fd, 0)
    size_t file_sz = (size_t)sel->selected.slice.slice_size;
    if (file_sz == 0)
        file_sz = sel->selected.slice.slice_offset
                + sel->selected.cs.cs_offset + sel->selected.cs.cs_size;
    uint64_t mapped = 0;
    if (target_call(task, thread, exc_port, tramp_mmap,
            0, file_sz, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0,
            0, &mapped, 15000) != 0 || (int64_t)mapped == -1) {
        EVT("event=inject phase=mmap_mmap_fail");
        mach_vm_deallocate(task, tramp, 0x4000);
        mach_vm_deallocate(task, scratch, scratch_size);
        return -1;
    }

    // mremap_encrypted on cryptoff range - kernel attaches apple_protect_pager.
    if (sel->selected.crypt.has_crypt &&
        sel->selected.crypt.cryptid != 0 && sel->selected.crypt.cryptsize > 0) {
        const size_t page = 0x4000;
        mach_vm_address_t enc = mapped + sel->selected.slice.slice_offset
            + sel->selected.crypt.cryptoff;
        size_t len = (sel->selected.crypt.cryptsize + page - 1) & ~(page - 1);
        uint64_t rc = 0;
        if (target_call(task, thread, exc_port, tramp_mremap,
                enc, len, sel->selected.crypt.cryptid,
                sel->selected.slice.cputype, sel->selected.slice.cpusubtype, 0,
                0, &rc, 20000) != 0 || (int32_t)rc != 0) {
            EVT("event=inject phase=mremap_fail rc=%lld", (long long)(int32_t)rc);
        } else {
            EVT("event=inject phase=mremap_done rc=%lld", (long long)(int32_t)rc);

            // Force fairplayd decrypt-on-fault for every page now, while we
            // still have the target thread hijacked. Without this, the next
            // step's cross-task vm_read pulls the raw file-backed bytes
            // because the target never touched them itself (dyld halted
            // early on iOS 16.1.1 Dopamine etc.). 60s budget covers a
            // multi-MB region: ~one fairplayd RPC per 16 KB page.
            uint64_t pf_rc = 0;
            if (target_call(task, thread, exc_port, tramp_prefault,
                    enc, len, page, 0, 0, 0, 0, &pf_rc, 60000) != 0) {
                EVT("event=inject phase=prefault_fail");
            } else {
                EVT("event=inject phase=prefault_done pages=%llu",
                    (unsigned long long)(len / page));
            }
        }
    }

    if (out_addr) *out_addr = mapped;
    if (out_size) *out_size = file_sz;
    return 0;
}


// Recursively walk the bundle on disk and decrypt every encrypted Mach-O
// the target hasn't already mapped, by injecting an open + fcntl +
// mmap + mremap_encrypted chain into the target via thread hijack.
// Helper-context mremap_encrypted gets EPERM under iOS-16 AMFI policy;
// the target's CS context satisfies AMFI, so the kernel attaches
// apple_protect_pager and page faults route through fairplayd.
// Returns count dumped; appends bundle-relative paths to dumped_rel.
static int inject_missing_frameworks(task_t task, mach_port_t exc,
                                     const char *bundle_src,
                                     const char *bundle_dst,
                                     struct dyld_image_info *imgs,
                                     uint32_t img_count,
                                     const runtime_image_t *runtime,
                                     char ***dumped_rel_p, int *n_dumped_p,
                                     int *dumped_cap_p) {
    if (!task || exc == MACH_PORT_NULL || !imgs || !runtime) return 0;

    // arm64e PAC blocks crafted PCs; only attempt on plain arm64.
    if (runtime->cputype != CPU_TYPE_ARM64 ||
        cpusubtype_base(runtime->cpusubtype) != CPU_SUBTYPE_ARM64_ALL) {
        LOG("[helper] inject: skip - target arch isn't plain arm64 "
            "(cputype=0x%x subtype=0x%x); thread injection needs PAC bypass\n",
            runtime->cputype, runtime->cpusubtype);
        EVT("event=inject phase=skipped reason=not_plain_arm64");
        return 0;
    }

    // Build a set of bundle-relative paths the target already mapped, so
    // we don't waste an injection cycle on those.
    const char *bs = bundle_src;
    size_t bs_len = strlen(bs);
    char bs_pri[4096];
    snprintf(bs_pri, sizeof(bs_pri), "/private%s", bs);

    // Pick one thread up front and reuse for every framework: each
    // target_call cycle suspends/sets/resumes the same thread, so picking
    // it once avoids burning re-discovery cycles per framework.
    thread_act_t hijacked = pick_hijack_thread(task);

    int injected = 0;

    typedef struct stack_ent { char *dir; struct stack_ent *next; } stack_ent_t;
    stack_ent_t *stack = malloc(sizeof(*stack));
    if (!stack) return 0;
    stack->dir = strdup(bundle_src);
    stack->next = NULL;
    if (!stack->dir) { free(stack); return 0; }

    while (stack) {
        stack_ent_t *cur = stack;
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
                // Skip PlugIns/ and Extensions/ at top level - those are
                // handled by separate decrypt_appex passes. Otherwise
                // descend so we cover SwiftBuild.framework/Frameworks/*,
                // Developer/Toolchains/..., and any deeper nest.
                if (strcmp(cur->dir, bundle_src) == 0 &&
                    (strcmp(e->d_name, "PlugIns") == 0 ||
                     strcmp(e->d_name, "Extensions") == 0)) continue;
                stack_ent_t *n = malloc(sizeof(*n));
                if (!n) continue;
                n->dir = strdup(child);
                if (!n->dir) { free(n); continue; }
                n->next = stack;
                stack = n;
                continue;
            }
            if (!S_ISREG(st.st_mode)) continue;
            if (!is_macho(child)) continue;

            selected_slice_t sel;
            if (select_runtime_slice(child, runtime, &sel) != 1) continue;
            if (!slice_needs_dump(&sel)) continue;

            // Skip if the target already has this image mapped.
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

            LOG("[helper] inject: %s not loaded by target\n", child);
            EVT("event=inject phase=start name=\"%s\"", child);

            // mmap+mremap_encrypted in target context. Target's CS context
            // satisfies AMFI's text_crypter_create_hook gate (helper-context
            // gets EPERM), so the kernel attaches apple_protect_pager and
            // page faults route through fairplayd for plaintext.
            if (hijacked == MACH_PORT_NULL) {
                EVT("event=inject phase=skipped name=\"%s\" reason=no_thread", child);
                continue;
            }
            mach_vm_address_t mapped = 0;
            size_t mapped_size = 0;
            if (inject_mmap_in_target(task, exc, hijacked,
                    child, &sel, &mapped, &mapped_size) != 0) {
                EVT("event=inject phase=failed name=\"%s\"", child);
                continue;
            }
            mach_vm_address_t base = mapped + sel.selected.slice.slice_offset;
            EVT("event=inject phase=success addr=0x%llx", (unsigned long long)base);

            const char *rel = child + bs_len;
            while (*rel == '/') rel++;
            char abs_dst[4096];
            snprintf(abs_dst, sizeof(abs_dst), "%s/%s", bundle_dst, rel);

            EVT("event=image phase=start name=\"%s\" kind=framework source=inject_mmap", rel);
            dump_result_t dr = dump_image(child, abs_dst, task, base, &sel);
            if (dr == DUMP_OK) {
                EVT("event=image phase=done name=\"%s\" kind=framework size=%u source=inject_mmap",
                    rel, sel.selected.crypt.cryptsize);
                injected++;
                if (*n_dumped_p >= *dumped_cap_p) {
                    int newcap = *dumped_cap_p ? *dumped_cap_p * 2 : 16;
                    char **nb = realloc(*dumped_rel_p, newcap * sizeof(*nb));
                    if (nb) { *dumped_rel_p = nb; *dumped_cap_p = newcap; }
                }
                if (*n_dumped_p < *dumped_cap_p) {
                    (*dumped_rel_p)[(*n_dumped_p)++] = strdup(rel);
                }
            } else {
                EVT("event=image phase=failed name=\"%s\" kind=framework reason=\"%s\" source=inject_mmap",
                    rel, dump_reason(dr));
            }
        }
        closedir(d);
        free(cur->dir);
        free(cur);
    }
    if (hijacked != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), hijacked);
    }
    return injected;
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

    // 2) Set Mach exception port + patch dyld's halt path BEFORE resume.
    //    Without the patch, dyld's cross-OS bind-fail raises SIGABRT via
    //    abort_with_payload -> EXC_CRASH -> kernel reaps the task -> all
    //    later mach_vm_allocate fails and the inject pass dies. With the
    //    patch (libc abort entries -> ret + dyld inline syscalls -> nop)
    //    the halt() returns silently, dyld stays alive in a
    //    partially-bound state, EXC_BREAKPOINT at the trailing brk #1
    //    pauses the task with everything dyld already mapped readable,
    //    and the inject pass picks up the rest.
    mach_port_t exc = make_exception_port(task);
    {
        // Pre-resume image list is usually empty (dyld hasn't run yet);
        // find_target_dlopen_image's task_info / dyld_all_image_infos
        // fallback supplies the dyld base regardless.
        uint32_t pre_count = 0;
        char *pre_paths = NULL;
        struct dyld_image_info *pre_imgs = list_images(task, &pre_count, &pre_paths);
        Dl_info hi = {0};
        dladdr((void *)dlopen, &hi);
        mach_vm_address_t target_libdyld = find_target_dlopen_image(task,
            pre_imgs, pre_count, hi.dli_fname);
        mach_vm_address_t helper_libdyld_v =
            (mach_vm_address_t)(uintptr_t)hi.dli_fbase;
        if (target_libdyld && helper_libdyld_v) {
            patch_target_abort(task, pre_imgs, pre_count,
                target_libdyld, helper_libdyld_v);
        } else {
            EVT("event=patch phase=skip reason=no_libdyld target=0x%llx helper=0x%llx",
                (unsigned long long)target_libdyld,
                (unsigned long long)helper_libdyld_v);
        }
        free(pre_paths); free(pre_imgs);
    }

    LOG("[helper] resuming %s (via_ptrace=%d)\n", bundle_src, via_ptrace);
    EVT("event=dyld phase=resuming src=\"%s\" via_ptrace=%d", bundle_src, via_ptrace);
    // Wait long enough for the target's main() to reach the dlopen calls
    // for runtime-loaded frameworks (Metal compat dylibs, plugin bundles,
    // etc). Mach-exception delivery and ptrace SIGKILL both short-circuit
    // the wait, so healthy targets are the only thing that pays the full
    // timeout. 30s is empirically enough for most games to finish their
    // Metal/graphics init pass; longer would just slow down quick apps.
    run_and_suspend(task, pid, via_ptrace, exc, 30000);

    // 3) Enumerate images loaded in the (now suspended or dead) target task
    //    and dump every encrypted one whose path is inside this bundle.
    uint32_t img_count = 0;
    char *paths = NULL;
    struct dyld_image_info *imgs = list_images(task, &img_count, &paths);
    int extra = 0;
    // Bundle-relative paths dumped from already-mapped images, fed to
    // inject pass to skip dupes.
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
    LOG("[helper] %s: dumped %d framework(s) via target task\n", bundle_src, extra);

    // 4) Decrypt remaining encrypted Mach-Os in the bundle that dyld didn't
    //    map (or hadn't reached before halt) by injecting open + fcntl +
    //    mmap + mremap_encrypted into target via thread hijack.
    if (have_bundle_rt && exc != MACH_PORT_NULL) {
        int injected = inject_missing_frameworks(task, exc, bundle_src,
            bundle_dst, imgs, img_count, &bundle_rt,
            &dumped_rel, &n_dumped, &dumped_cap);
        extra += injected;
    }
    free(paths); free(imgs);

    // Tear the target down once we've drained everything we want from it.
    if (exc != MACH_PORT_NULL) {
        mach_port_mod_refs(mach_task_self(), exc, MACH_PORT_RIGHT_RECEIVE, -1);
        exc = MACH_PORT_NULL;
    }
    task_terminate(task);
    kill(pid, SIGKILL);
    int reaped;
    waitpid(pid, &reaped, WNOHANG);
    pid = 0;

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
    char *argv[] = { "zip", "-qr", "-1", (char *)ipa_path, "Payload",
        "-x",
        "Payload/*/Watch/*", "Payload/*/Watch",
        "Payload/*/WatchKitSupport2/*", "Payload/*/WatchKitSupport2",
        "Payload/*/SC_Info/*", "Payload/*/SC_Info",
        "*/SC_Info/*", "*/SC_Info",
        "Payload/*/*.dSYM/*", "Payload/*/*.dSYM",
        "Payload/*/BCSymbolMaps/*", "Payload/*/BCSymbolMaps",
        "Payload/*/Symbols/*", "Payload/*/Symbols",
        "Payload/META-INF/*", "Payload/META-INF",
        "Payload/iTunesMetadata.plist", "Payload/iTunesArtwork",
        NULL };
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
        if (strcmp(argv[pi], "--skip-appex") == 0) { g_skip_appex = 1; pi++; continue; }
        break;
    }
    if (argc - pi != 3) {
        fprintf(stderr,
            "usage: %s [-v] [--skip-appex] <bundle-id> <bundle-src> <out-ipa>\n"
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
    if (g_skip_appex) {
        EVT("event=appex phase=skipped");
    } else {
        decrypt_appexes(bundle_src, bundle_dst);
    }

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
