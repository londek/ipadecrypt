// ipadecrypt-helper: on-device FairPlay decrypter using posix_spawn +
// task_for_pid + mach_vm_read (TrollDecryptJB's technique).
//
// Rationale: mremap_encrypted from an arbitrary userland process returns EPERM
// on iOS 16 - the kernel won't hand over FairPlay keys to a process that
// isn't the target app. Running the app itself with POSIX_SPAWN_START_SUSPENDED
// maps its __TEXT into a task with the right crypto context; a root-privileged
// observer with task_for_pid can then mach_vm_read those pages and the kernel
// decrypts them on-demand inside the page-fault handler. This works even for
// apps that would crash at dyld bind (e.g. iOS-17 app on an iOS-16 device),
// because we never actually resume the suspended task.
//
// Subcommands:
//   helper find <app-dir-name>      → scan install container dir, print path
//   helper [-v] <bundle> <out-ipa>  → decrypt bundle, produce IPA

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <libgen.h>
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

// mach_vm.h is marked "unsupported" in the iOS SDK but the syscalls exist at
// runtime. Forward-declare the ones we use, matching the declarations in
// TrollDecryptJB/TDDumpDecrypted.m:54-58.
typedef uint64_t mach_vm_address_t;
typedef uint64_t mach_vm_size_t;
typedef uint64_t mach_vm_offset_t;

extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task,
    mach_vm_address_t address, mach_vm_size_t size,
    mach_vm_address_t data, mach_vm_size_t *outsize);

extern kern_return_t mach_vm_region(vm_map_t target_task,
    mach_vm_address_t *address, mach_vm_size_t *size,
    vm_region_flavor_t flavor, vm_region_info_t info,
    mach_msg_type_number_t *infoCnt, mach_port_t *object_name);

#ifndef LC_ENCRYPTION_INFO
#define LC_ENCRYPTION_INFO 0x21
#endif
#ifndef LC_ENCRYPTION_INFO_64
#define LC_ENCRYPTION_INFO_64 0x2C
#endif

extern char **environ;

static int verbose = 0;
static int events  = 0; // emit machine-readable @evt lines
#define LOG(...) do { if (verbose) fprintf(stderr, __VA_ARGS__); } while (0)
#define ERR(...) do { fprintf(stderr, "[helper] " __VA_ARGS__); fputc('\n', stderr); } while (0)

// EVT emits a single `@evt key=value …\n` line to stderr when -e is set.
// Callers pass the attribute list (without leading "@evt ").
__attribute__((format(printf, 1, 2)))
static void EVT(const char *fmt, ...) {
    if (!events) return;
    fprintf(stderr, "@evt ");
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}

// ----- bundle install-dir find subcommand ------------------------------

static int find_app_dir(const char *app_dir_name) {
    const char *root = "/var/containers/Bundle/Application";
    DIR *d = opendir(root);
    if (!d) {
        ERR("opendir %s: %s", root, strerror(errno));
        return 2;
    }
    struct dirent *de;
    int rc = 1;
    int scanned = 0;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        scanned++;
        char candidate[4096];
        snprintf(candidate, sizeof(candidate), "%s/%s/%s", root, de->d_name, app_dir_name);
        struct stat st;
        if (stat(candidate, &st) == 0 && S_ISDIR(st.st_mode)) {
            printf("%s\n", candidate);
            rc = 0;
            break;
        }
    }
    closedir(d);
    if (rc != 0) {
        fprintf(stderr, "[helper] find: scanned %d UUID dirs under %s; %s not present\n",
                scanned, root, app_dir_name);
    }
    return rc;
}

// ----- Mach-O / encryption-info parsing on local files -----------------

// Info about an encrypted slice within a (thin or fat) Mach-O.
// We support only thin arm64/arm64e binaries for the spawn path - the kernel
// will pick the right slice itself when it loads the fat executable, but our
// in-memory patching below still needs to know which slice it was. For iOS,
// nearly all app binaries are thin arm64/arm64e.
typedef struct {
    int is_64;
    off_t slice_offset;       // byte offset in file where this slice starts
    uint32_t cryptoff;        // within slice
    uint32_t cryptsize;
    uint32_t cryptid;
    uint32_t cputype;
    uint32_t cpusubtype;
    off_t cryptid_file_offset; // absolute byte offset of cryptid in file
} encinfo_t;

static uint32_t bswap32(uint32_t x) {
    return ((x & 0xff) << 24) | ((x & 0xff00) << 8) |
           ((x & 0xff0000) >> 8) | ((x & 0xff000000) >> 24);
}

// Parse a single slice and fill `out` if it has an LC_ENCRYPTION_INFO[_64]
// with cryptid != 0. Returns 1 if encrypted, 0 if unencrypted/no header, <0 on error.
static int parse_slice(const uint8_t *slice, size_t slice_len, off_t slice_off, encinfo_t *out) {
    if (slice_len < sizeof(struct mach_header)) return 0;
    struct mach_header mh_common;
    memcpy(&mh_common, slice, sizeof(mh_common));

    int is_64;
    uint32_t ncmds, sizeofcmds;
    size_t header_sz;
    uint32_t cputype, cpusubtype;
    if (mh_common.magic == MH_MAGIC_64) {
        struct mach_header_64 mh64;
        memcpy(&mh64, slice, sizeof(mh64));
        is_64 = 1;
        ncmds = mh64.ncmds;
        sizeofcmds = mh64.sizeofcmds;
        cputype = mh64.cputype;
        cpusubtype = mh64.cpusubtype;
        header_sz = sizeof(mh64);
    } else if (mh_common.magic == MH_MAGIC) {
        is_64 = 0;
        ncmds = mh_common.ncmds;
        sizeofcmds = mh_common.sizeofcmds;
        cputype = mh_common.cputype;
        cpusubtype = mh_common.cpusubtype;
        header_sz = sizeof(mh_common);
    } else {
        return 0;
    }
    if (header_sz + sizeofcmds > slice_len) return -1;

    const uint8_t *lc_ptr = slice + header_sz;
    for (uint32_t i = 0; i < ncmds; i++) {
        struct load_command lc;
        memcpy(&lc, lc_ptr, sizeof(lc));
        if (lc.cmdsize == 0) return -1;
        if ((size_t)((lc_ptr - slice) + lc.cmdsize) > header_sz + sizeofcmds) return -1;

        if ((is_64 && lc.cmd == LC_ENCRYPTION_INFO_64) ||
            (!is_64 && lc.cmd == LC_ENCRYPTION_INFO)) {
            struct encryption_info_command eic;
            memcpy(&eic, lc_ptr, sizeof(eic));
            if (eic.cryptid == 0) return 0;
            out->is_64 = is_64;
            out->slice_offset = slice_off;
            out->cryptoff = eic.cryptoff;
            out->cryptsize = eic.cryptsize;
            out->cryptid = eic.cryptid;
            out->cputype = cputype;
            out->cpusubtype = cpusubtype;
            out->cryptid_file_offset = slice_off + (lc_ptr - slice) +
                                       offsetof(struct encryption_info_command, cryptid);
            return 1;
        }
        lc_ptr += lc.cmdsize;
    }
    return 0;
}

// Parse a Mach-O file (thin or fat). Returns 1 if encrypted (fills *out with
// first encrypted slice info), 0 if not encrypted / not Mach-O, <0 on error.
static int parse_macho_file(const char *path, encinfo_t *out) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }
    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return -1;

    int rc = 0;
    uint8_t *base = (uint8_t *)map;
    if ((size_t)st.st_size >= 4) {
        uint32_t magic;
        memcpy(&magic, base, 4);
        if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
            int swap = (magic == FAT_CIGAM);
            struct fat_header fh;
            memcpy(&fh, base, sizeof(fh));
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

static int is_macho_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    uint32_t m = 0;
    ssize_t n = read(fd, &m, sizeof(m));
    close(fd);
    if (n != sizeof(m)) return 0;
    return (m == MH_MAGIC || m == MH_MAGIC_64 || m == FAT_CIGAM || m == FAT_MAGIC);
}

// ----- target-task image discovery -------------------------------------

// Find the main executable's Mach-O base address in the target task by
// walking VM regions looking for an MH_EXECUTE Mach-O header.
static int find_main_exec_base(task_t task, mach_vm_address_t *out_base) {
    mach_vm_address_t addr = 0;
    for (;;) {
        mach_vm_size_t sz = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t info_cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj_name = MACH_PORT_NULL;
        kern_return_t kr = mach_vm_region(task, &addr, &sz,
                                          VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&info, &info_cnt, &obj_name);
        if (kr != KERN_SUCCESS) return -1;

        struct mach_header_64 hdr;
        mach_vm_size_t n = 0;
        kr = mach_vm_read_overwrite(task, addr, sizeof(hdr),
                                    (mach_vm_address_t)(uintptr_t)&hdr, &n);
        if (kr == KERN_SUCCESS && n == sizeof(hdr) &&
            (hdr.magic == MH_MAGIC_64 || hdr.magic == MH_MAGIC) &&
            hdr.filetype == MH_EXECUTE) {
            *out_base = addr;
            return 0;
        }
        addr += sz;
    }
}

// ----- decrypt flow ----------------------------------------------------

// Spawn exec_path with SPAWN_START_SUSPENDED, return pid + task port. The
// caller must kill/deallocate on success.
static int spawn_suspended(const char *exec_path, pid_t *out_pid, task_t *out_task) {
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    // Silence the target's stdout/stderr.
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);

    char *argv[] = { (char *)exec_path, NULL };
    pid_t pid = 0;
    int rc = posix_spawn(&pid, exec_path, &fa, &attr, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&attr);
    if (rc != 0) {
        ERR("posix_spawn %s: %s", exec_path, strerror(rc));
        return -1;
    }

    task_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        ERR("task_for_pid(%d): %d (%s)", pid, kr, mach_error_string(kr));
        kill(pid, SIGKILL);
        return -1;
    }
    *out_pid = pid;
    *out_task = task;
    return 0;
}

// Dump an encrypted Mach-O image at `image_base` in `task` back to disk.
// Reads src_path, replaces the encrypted region with plaintext obtained via
// mach_vm_read, zeroes cryptid, writes dst_path. Works for both the main
// executable and loaded frameworks/dylibs.
static int dump_image_region(const char *src_path, const char *dst_path,
                             task_t task, mach_vm_address_t image_base,
                             const encinfo_t *info) {
    // Read src file to local buffer.
    int fd = open(src_path, O_RDONLY);
    if (fd < 0) { ERR("open %s: %s", src_path, strerror(errno)); return -1; }
    struct stat st;
    fstat(fd, &st);
    uint8_t *buf = malloc(st.st_size);
    if (read(fd, buf, st.st_size) != st.st_size) {
        free(buf); close(fd); ERR("read %s: %s", src_path, strerror(errno));
        return -1;
    }
    close(fd);

    // For thin binaries slice_offset is 0 so target vmaddr cryptoff maps
    // 1:1 to file byte offset. Kernel faults + decrypts the encrypted pages
    // on demand during the read.
    mach_vm_address_t src_addr = image_base + info->cryptoff;
    mach_vm_address_t dst_addr = (mach_vm_address_t)(uintptr_t)(buf + info->slice_offset + info->cryptoff);
    mach_vm_size_t remaining = info->cryptsize;
    while (remaining > 0) {
        mach_vm_size_t chunk = remaining;
        if (chunk > 0x100000) chunk = 0x100000;
        mach_vm_size_t nread = 0;
        kern_return_t kr = mach_vm_read_overwrite(task, src_addr, chunk, dst_addr, &nread);
        if (kr != KERN_SUCCESS) {
            ERR("mach_vm_read_overwrite @0x%llx size=0x%llx: kr=%d (%s)",
                (unsigned long long)src_addr, (unsigned long long)chunk,
                kr, mach_error_string(kr));
            free(buf);
            return -1;
        }
        if (nread == 0) { ERR("mach_vm_read returned 0 bytes"); free(buf); return -1; }
        src_addr += nread;
        dst_addr += nread;
        remaining -= nread;
    }

    uint32_t zero = 0;
    memcpy(buf + info->cryptid_file_offset, &zero, sizeof(zero));

    int out = open(dst_path, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (out < 0) { ERR("open dst %s: %s", dst_path, strerror(errno)); free(buf); return -1; }
    if (write(out, buf, st.st_size) != st.st_size) {
        ERR("write dst %s: %s", dst_path, strerror(errno));
        close(out); free(buf); return -1;
    }
    close(out);
    free(buf);
    return 0;
}

// Check whether a task is still alive by querying its basic info.
static int task_alive(task_t task) {
    struct task_basic_info tbi;
    mach_msg_type_number_t cnt = TASK_BASIC_INFO_COUNT;
    return task_info(task, TASK_BASIC_INFO, (task_info_t)&tbi, &cnt) == KERN_SUCCESS;
}

// Read a NUL-terminated string from a target task, up to `max` bytes, into
// `dst`. Returns 0 on success or -1 on mach_vm_read failure.
static int read_cstr_from_task(task_t task, mach_vm_address_t addr, char *dst, size_t max) {
    if (max == 0) return -1;
    mach_vm_size_t n = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, addr, max - 1,
        (mach_vm_address_t)(uintptr_t)dst, &n);
    if (kr != KERN_SUCCESS) return -1;
    dst[n] = 0;
    // Truncate at first NUL we find.
    for (size_t i = 0; i < n; i++) {
        if (dst[i] == 0) { return 0; }
    }
    dst[max - 1] = 0;
    return 0;
}

// Read the LC_ENCRYPTION_INFO[_64] out of the Mach-O at `image_base` in task.
// Fills *info (slice_offset = 0 since in-memory thin image). Returns 1 if
// encrypted (cryptid != 0), 0 if not, -1 on error.
static int read_image_encinfo(task_t task, mach_vm_address_t image_base, encinfo_t *info) {
    struct mach_header_64 hdr;
    mach_vm_size_t n = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, image_base, sizeof(hdr),
        (mach_vm_address_t)(uintptr_t)&hdr, &n);
    if (kr != KERN_SUCCESS || n != sizeof(hdr)) return -1;

    int is_64;
    uint32_t ncmds, sizeofcmds;
    size_t header_sz;
    uint32_t cputype, cpusubtype;
    if (hdr.magic == MH_MAGIC_64) {
        is_64 = 1;
        ncmds = hdr.ncmds; sizeofcmds = hdr.sizeofcmds;
        cputype = hdr.cputype; cpusubtype = hdr.cpusubtype;
        header_sz = sizeof(struct mach_header_64);
    } else if (hdr.magic == MH_MAGIC) {
        struct mach_header h32;
        memcpy(&h32, &hdr, sizeof(h32));
        is_64 = 0;
        ncmds = h32.ncmds; sizeofcmds = h32.sizeofcmds;
        cputype = h32.cputype; cpusubtype = h32.cpusubtype;
        header_sz = sizeof(h32);
    } else {
        return -1;
    }
    if (sizeofcmds == 0 || sizeofcmds > 1 << 20) return -1;

    uint8_t *cmds = malloc(sizeofcmds);
    kr = mach_vm_read_overwrite(task, image_base + header_sz, sizeofcmds,
        (mach_vm_address_t)(uintptr_t)cmds, &n);
    if (kr != KERN_SUCCESS) { free(cmds); return -1; }

    uint8_t *p = cmds;
    int rc = 0;
    for (uint32_t i = 0; i < ncmds; i++) {
        struct load_command lc;
        memcpy(&lc, p, sizeof(lc));
        if (lc.cmdsize == 0 || (size_t)((p - cmds) + lc.cmdsize) > sizeofcmds) break;
        if ((is_64 && lc.cmd == LC_ENCRYPTION_INFO_64) ||
            (!is_64 && lc.cmd == LC_ENCRYPTION_INFO)) {
            struct encryption_info_command eic;
            memcpy(&eic, p, sizeof(eic));
            if (eic.cryptid != 0) {
                info->is_64 = is_64;
                info->slice_offset = 0;
                info->cryptoff = eic.cryptoff;
                info->cryptsize = eic.cryptsize;
                info->cryptid = eic.cryptid;
                info->cputype = cputype;
                info->cpusubtype = cpusubtype;
                info->cryptid_file_offset = header_sz + (p - cmds) +
                    offsetof(struct encryption_info_command, cryptid);
                rc = 1;
            }
            break;
        }
        p += lc.cmdsize;
    }
    free(cmds);
    return rc;
}

// ----- bundle copy ----------------------------------------------------

// Copy a plain file.
static int copy_file(const char *src, const char *dst, mode_t mode) {
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    int out = open(dst, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (out < 0) { close(in); return -1; }
    char buf[65536];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        if (write(out, buf, n) != n) { close(in); close(out); return -1; }
    }
    close(in); close(out);
    return 0;
}

// The recursive walker: copies everything verbatim. Encrypted Mach-Os
// (main exec + any encrypted frameworks) get patched in-place afterwards
// via mach_vm_read from the target task.
static int copy_tree(const char *src_root, const char *dst_root, const char *rel) {
    char src_path[4096], dst_path[4096];
    snprintf(src_path, sizeof(src_path), "%s%s%s", src_root, rel[0] ? "/" : "", rel);
    snprintf(dst_path, sizeof(dst_path), "%s%s%s", dst_root, rel[0] ? "/" : "", rel);

    struct stat st;
    if (lstat(src_path, &st) < 0) { ERR("lstat %s: %s", src_path, strerror(errno)); return -1; }

    if (S_ISDIR(st.st_mode)) {
        if (mkdir(dst_path, 0755) < 0 && errno != EEXIST) {
            ERR("mkdir %s: %s", dst_path, strerror(errno));
            return -1;
        }
        DIR *d = opendir(src_path);
        if (!d) { ERR("opendir %s: %s", src_path, strerror(errno)); return -1; }
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] == '.' && (de->d_name[1] == 0 ||
                (de->d_name[1] == '.' && de->d_name[2] == 0))) continue;
            char child_rel[4096];
            snprintf(child_rel, sizeof(child_rel), "%s%s%s", rel, rel[0] ? "/" : "", de->d_name);
            if (copy_tree(src_root, dst_root, child_rel) != 0) {
                closedir(d);
                return -1;
            }
        }
        closedir(d);
        return 0;
    }
    if (S_ISLNK(st.st_mode)) {
        char target[4096];
        ssize_t n = readlink(src_path, target, sizeof(target) - 1);
        if (n < 0) { ERR("readlink %s: %s", src_path, strerror(errno)); return -1; }
        target[n] = 0;
        if (symlink(target, dst_path) < 0 && errno != EEXIST) {
            ERR("symlink %s: %s", dst_path, strerror(errno));
            return -1;
        }
        return 0;
    }
    if (!S_ISREG(st.st_mode)) return 0;

    if (copy_file(src_path, dst_path, st.st_mode & 0777) != 0) return -1;
    chmod(dst_path, st.st_mode & 0777);
    return 0;
}

// Normalize "/private/var/..." to "/var/..." (iOS symlinks /var to /private/var).
static const char *strip_private(const char *p) {
    if (strncmp(p, "/private/", 9) == 0) return p + 8;
    return p;
}

// Planned dump target discovered via first scan.
typedef struct {
    mach_vm_address_t image_base;
    encinfo_t info;
    char rel[4096];
} target_t;

// Enumerate every image loaded in the target task; for each image whose path
// is inside the bundle AND has a non-zero cryptid, dump via mach_vm_read into
// the corresponding file under app_dst. Returns count of dumped images.
//
// Two passes when emitting events, so the Go side can show a real progress
// bar: first scan collects targets + emits `event=plan total=N`, then each
// dump emits `event=image idx=i/N`.
static int dump_encrypted_loaded_images(task_t task, const char *bundle_root,
                                        const char *app_dst) {
    struct task_dyld_info dinfo;
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    kern_return_t kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dinfo, &cnt);
    if (kr != KERN_SUCCESS) {
        ERR("task_info(TASK_DYLD_INFO): %d", kr);
        return 0;
    }
    if (dinfo.all_image_info_addr == 0) {
        ERR("dyld_all_image_infos not yet populated; target didn't get far enough");
        return 0;
    }

    struct dyld_all_image_infos aii;
    mach_vm_size_t n = 0;
    kr = mach_vm_read_overwrite(task, dinfo.all_image_info_addr, sizeof(aii),
        (mach_vm_address_t)(uintptr_t)&aii, &n);
    if (kr != KERN_SUCCESS) {
        ERR("read dyld_all_image_infos: %d", kr);
        return 0;
    }

    uint32_t img_count = aii.infoArrayCount;
    if (img_count == 0 || img_count > 8192) {
        ERR("suspicious image count: %u", img_count);
        return 0;
    }
    size_t ia_bytes = (size_t)img_count * sizeof(struct dyld_image_info);
    struct dyld_image_info *infos = malloc(ia_bytes);
    kr = mach_vm_read_overwrite(task, (mach_vm_address_t)(uintptr_t)aii.infoArray,
        ia_bytes, (mach_vm_address_t)(uintptr_t)infos, &n);
    if (kr != KERN_SUCCESS) {
        ERR("read infoArray: %d", kr);
        free(infos);
        return 0;
    }

    const char *bundle_n = strip_private(bundle_root);
    size_t bundle_len = strlen(bundle_n);

    target_t *targets = malloc((size_t)img_count * sizeof(*targets));
    int n_targets = 0;

    for (uint32_t i = 0; i < img_count; i++) {
        if (infos[i].imageFilePath == NULL || infos[i].imageLoadAddress == NULL) continue;
        char path[4096];
        if (read_cstr_from_task(task,
                (mach_vm_address_t)(uintptr_t)infos[i].imageFilePath,
                path, sizeof(path)) != 0) continue;
        const char *pn = strip_private(path);
        if (strncmp(pn, bundle_n, bundle_len) != 0) continue;

        const char *rel = pn + bundle_len;
        while (*rel == '/') rel++;

        mach_vm_address_t image_base = (mach_vm_address_t)(uintptr_t)infos[i].imageLoadAddress;
        encinfo_t info;
        if (read_image_encinfo(task, image_base, &info) != 1) continue;

        targets[n_targets].image_base = image_base;
        targets[n_targets].info = info;
        snprintf(targets[n_targets].rel, sizeof(targets[n_targets].rel), "%s", rel);
        n_targets++;
    }
    free(infos);

    EVT("event=plan total=%d", n_targets);

    int dumped = 0;
    for (int i = 0; i < n_targets; i++) {
        char src[4096], dst[4096];
        snprintf(src, sizeof(src), "%s/%s", bundle_root, targets[i].rel);
        snprintf(dst, sizeof(dst), "%s/%s", app_dst, targets[i].rel);

        LOG("[helper] decrypting: %s (load=0x%llx cryptoff=0x%x size=0x%x)\n",
            targets[i].rel, (unsigned long long)targets[i].image_base,
            targets[i].info.cryptoff, targets[i].info.cryptsize);
        EVT("event=image idx=%d total=%d name=\"%s\" size=%u",
            i + 1, n_targets, targets[i].rel, targets[i].info.cryptsize);

        if (dump_image_region(src, dst, task, targets[i].image_base, &targets[i].info) != 0) {
            ERR("failed to dump %s", targets[i].rel);
            EVT("event=image_fail idx=%d name=\"%s\"", i + 1, targets[i].rel);
            continue;
        }
        dumped++;
    }
    free(targets);
    return dumped;
}

// ----- main-executable identification ---------------------------------

// Derive the main executable file's basename.
// Strategy: default = bundle directory name minus ".app"/".appex" (matches
// CFBundleExecutable for the vast majority of apps and extensions). If that
// file doesn't exist / isn't a Mach-O, fall back to any single Mach-O file
// directly in the bundle root.
static int find_main_exec_name(const char *bundle, char *out, size_t out_sz) {
    const char *bn = strrchr(bundle, '/');
    bn = bn ? bn + 1 : bundle;
    char name[4096];
    snprintf(name, sizeof(name), "%s", bn);
    size_t nlen = strlen(name);
    // Try .appex first (6 chars) since it also ends in ".app".
    if (nlen >= 6 && strcmp(name + nlen - 6, ".appex") == 0) {
        name[nlen - 6] = 0;
    } else if (nlen >= 4 && strcmp(name + nlen - 4, ".app") == 0) {
        name[nlen - 4] = 0;
    }
    char candidate[4096];
    snprintf(candidate, sizeof(candidate), "%s/%s", bundle, name);
    if (is_macho_file(candidate)) {
        snprintf(out, out_sz, "%s", name);
        return 0;
    }
    // Fallback: scan bundle root for the first Mach-O file.
    DIR *d = opendir(bundle);
    if (!d) return -1;
    struct dirent *de;
    int rc = -1;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char p[4096];
        snprintf(p, sizeof(p), "%s/%s", bundle, de->d_name);
        struct stat st;
        if (lstat(p, &st) < 0 || !S_ISREG(st.st_mode)) continue;
        if (is_macho_file(p)) {
            snprintf(out, out_sz, "%s", de->d_name);
            rc = 0;
            break;
        }
    }
    closedir(d);
    return rc;
}

// ----- zip helper ------------------------------------------------------

static int zip_payload(const char *staging_dir, const char *out_path) {
    char abs_out[4096];
    if (out_path[0] == '/') {
        snprintf(abs_out, sizeof(abs_out), "%s", out_path);
    } else {
        char cwd[4096];
        if (!getcwd(cwd, sizeof(cwd))) { ERR("getcwd: %s", strerror(errno)); return -1; }
        snprintf(abs_out, sizeof(abs_out), "%s/%s", cwd, out_path);
    }
    pid_t pid = fork();
    if (pid < 0) { ERR("fork: %s", strerror(errno)); return -1; }
    if (pid == 0) {
        if (chdir(staging_dir) != 0) {
            fprintf(stderr, "[helper] chdir %s: %s\n", staging_dir, strerror(errno));
            _exit(127);
        }
        execl("/usr/bin/zip", "zip", "-rqyX", abs_out, "Payload", (char *)NULL);
        execl("/usr/local/bin/zip", "zip", "-rqyX", abs_out, "Payload", (char *)NULL);
        execlp("zip", "zip", "-rqyX", abs_out, "Payload", (char *)NULL);
        fprintf(stderr, "[helper] exec zip: %s\n", strerror(errno));
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) { ERR("waitpid: %s", strerror(errno)); return -1; }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        ERR("zip exit %d", WEXITSTATUS(status));
        return -1;
    }
    return 0;
}

static int rm_rf(const char *path) {
    struct stat st;
    if (lstat(path, &st) < 0) return errno == ENOENT ? 0 : -1;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (!d) return -1;
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] == '.' && (de->d_name[1] == 0 ||
                (de->d_name[1] == '.' && de->d_name[2] == 0))) continue;
            char child[4096];
            snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
            rm_rf(child);
        }
        closedir(d);
        return rmdir(path);
    }
    return unlink(path);
}

// ----- per-bundle decrypt pass -----------------------------------------

// decrypt_bundle runs the full spawn / dump-main / let-dyld-map / dump-frameworks
// pipeline for one bundle (the main .app or a PlugIns/*.appex). Returns 0 on
// success or -1 on a fatal failure that should abort the whole run.
//
// bundle_src: absolute source bundle path on the installed device (where the
//             still-encrypted Mach-Os live - kernel will decrypt them lazily
//             when we mach_vm_read from the spawned task's map).
// bundle_dst: absolute destination bundle path inside the staging Payload/
//             tree (where we write the plaintext copies).
static int decrypt_bundle(const char *bundle_src, const char *bundle_dst) {
    char main_exec_name[512];
    if (find_main_exec_name(bundle_src, main_exec_name, sizeof(main_exec_name)) != 0) {
        ERR("could not identify main executable in %s", bundle_src);
        return -1;
    }
    LOG("[helper] bundle %s → main=%s\n", bundle_src, main_exec_name);
    EVT("event=bundle name=\"%s\" main=\"%s\"", bundle_src, main_exec_name);

    char exec_path[4096];
    snprintf(exec_path, sizeof(exec_path), "%s/%s", bundle_src, main_exec_name);

    pid_t target_pid = 0;
    task_t target_task = MACH_PORT_NULL;
    if (spawn_suspended(exec_path, &target_pid, &target_task) != 0) {
        EVT("event=spawn_failed name=\"%s\"", bundle_src);
        // Non-fatal: the outer run continues with whatever else it can handle.
        return 0;
    }
    LOG("[helper] spawned %d for %s\n", target_pid, bundle_src);
    EVT("event=target_ready pid=%d", target_pid);

    // 1) Dump main exec via VM region scan (works before dyld has run).
    encinfo_t main_info;
    int er = parse_macho_file(exec_path, &main_info);
    if (er == 1) {
        mach_vm_address_t main_base = 0;
        if (find_main_exec_base(target_task, &main_base) == 0) {
            char main_dst[4096];
            snprintf(main_dst, sizeof(main_dst), "%s/%s", bundle_dst, main_exec_name);
            LOG("[helper] decrypting main: %s (load=0x%llx)\n", main_exec_name,
                (unsigned long long)main_base);
            EVT("event=main name=\"%s\" size=%u", main_exec_name, main_info.cryptsize);
            if (dump_image_region(exec_path, main_dst, target_task, main_base, &main_info) == 0) {
                EVT("event=main_done name=\"%s\"", main_exec_name);
            } else {
                ERR("main exec dump failed for %s", bundle_src);
            }
        } else {
            ERR("could not locate MH_EXECUTE base in %s", bundle_src);
        }
    }

    // 2) Set exception port so we can catch dyld's crash on cross-OS bundles,
    //    then resume briefly to let dyld map frameworks.
    mach_port_t exc_port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exc_port);
    if (kr == KERN_SUCCESS) {
        kr = mach_port_insert_right(mach_task_self(), exc_port, exc_port, MACH_MSG_TYPE_MAKE_SEND);
    }
    if (kr == KERN_SUCCESS) {
        kr = task_set_exception_ports(target_task,
            EXC_MASK_CRASH | EXC_MASK_BAD_ACCESS |
            EXC_MASK_BAD_INSTRUCTION | EXC_MASK_SOFTWARE |
            EXC_MASK_ARITHMETIC | EXC_MASK_BREAKPOINT,
            exc_port, EXCEPTION_DEFAULT, ARM_THREAD_STATE64);
    }
    if (kr != KERN_SUCCESS) {
        ERR("exception port setup failed for %s: %d", bundle_src, kr);
    }

    LOG("[helper] resuming %s to load frameworks (exception-port watch)…\n", bundle_src);
    EVT("event=dyld state=resuming");
    kr = task_resume(target_task);
    if (kr == KERN_SUCCESS && exc_port != MACH_PORT_NULL) {
        struct {
            mach_msg_header_t head;
            char body[2048];
        } exc_msg;
        memset(&exc_msg, 0, sizeof(exc_msg));
        mach_msg_return_t mr = mach_msg(&exc_msg.head,
            MACH_RCV_MSG | MACH_RCV_TIMEOUT,
            0, sizeof(exc_msg), exc_port,
            2000 /* ms */, MACH_PORT_NULL);
        if (mr == MACH_RCV_TIMED_OUT) {
            LOG("[helper] %s: no crash within 2s; suspending normally\n", bundle_src);
            EVT("event=dyld state=finished");
        } else if (mr == MACH_MSG_SUCCESS) {
            LOG("[helper] %s: caught Mach exception (dyld bind-fail); task paused\n", bundle_src);
            EVT("event=dyld state=crashed");
        } else {
            ERR("%s: mach_msg wait: 0x%x", bundle_src, mr);
            EVT("event=dyld state=err code=0x%x", mr);
        }
        task_suspend(target_task);
    } else if (kr == KERN_SUCCESS) {
        usleep(400000);
        task_suspend(target_task);
    }

    // 3) Enumerate loaded images and dump every encrypted one whose path is
    //    inside this bundle (so main-app frameworks don't get re-dumped when
    //    we iterate appex plugins, since the filter restricts to bundle_src).
    if (task_alive(target_task)) {
        int n = dump_encrypted_loaded_images(target_task, bundle_src, bundle_dst);
        LOG("[helper] %s: dumped %d additional encrypted image(s)\n", bundle_src, n);
    }

    task_terminate(target_task);
    kill(target_pid, SIGKILL);
    if (exc_port != MACH_PORT_NULL) {
        mach_port_mod_refs(mach_task_self(), exc_port, MACH_PORT_RIGHT_RECEIVE, -1);
    }
    int status;
    waitpid(target_pid, &status, WNOHANG);
    return 0;
}

// ----- main ------------------------------------------------------------

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "find") == 0) {
        if (argc != 3) {
            fprintf(stderr, "usage: %s find <app-dir-name>\n", argv[0]);
            return 2;
        }
        return find_app_dir(argv[2]);
    }

    // Flags: -v (human verbose) and -e (machine @evt events) are independent.
    while (argc > 1 && argv[1][0] == '-' && argv[1][1] != 0) {
        if (strcmp(argv[1], "-v") == 0) verbose = 1;
        else if (strcmp(argv[1], "-e") == 0) events = 1;
        else if (strcmp(argv[1], "-ve") == 0 || strcmp(argv[1], "-ev") == 0) { verbose = 1; events = 1; }
        else break;
        argv++; argc--;
    }
    if (argc != 3) {
        fprintf(stderr, "usage: %s [-v] [-e] <bundle-path> <out-ipa>\n       %s find <app-dir-name>\n",
                argv[0], argv[0]);
        return 2;
    }
    const char *bundle = argv[1];
    const char *out_ipa = argv[2];

    struct stat bst;
    if (stat(bundle, &bst) < 0 || !S_ISDIR(bst.st_mode)) {
        ERR("bundle path is not a directory: %s", bundle);
        return 1;
    }

    // Identify the main executable relative to the bundle.
    char main_exec_name[512];
    if (find_main_exec_name(bundle, main_exec_name, sizeof(main_exec_name)) != 0) {
        ERR("could not identify main executable in %s", bundle);
        return 1;
    }
    LOG("[helper] main executable: %s\n", main_exec_name);
    EVT("event=start bundle=\"%s\" main=\"%s\"", bundle, main_exec_name);

    // Build staging dir and copy every file from the bundle verbatim.
    // Encrypted Mach-Os get overwritten below with plaintext.
    char staging[4096];
    snprintf(staging, sizeof(staging), "/tmp/ipadecrypt-helper-%d", getpid());
    if (mkdir(staging, 0755) != 0 && errno != EEXIST) {
        ERR("mkdir %s: %s", staging, strerror(errno));
        return 1;
    }
    char payload_dir[4096];
    snprintf(payload_dir, sizeof(payload_dir), "%s/Payload", staging);
    mkdir(payload_dir, 0755);
    char bundle_copy[4096]; snprintf(bundle_copy, sizeof(bundle_copy), "%s", bundle);
    const char *app_name = basename(bundle_copy);
    char app_dst[4096];
    snprintf(app_dst, sizeof(app_dst), "%s/%s", payload_dir, app_name);
    mkdir(app_dst, 0755);

    LOG("[helper] copying bundle → %s\n", app_dst);
    if (copy_tree(bundle, app_dst, "") != 0) {
        rm_rf(staging);
        return 1;
    }

    // Decrypt the main .app (main exec + its dyld-loaded frameworks).
    if (decrypt_bundle(bundle, app_dst) < 0) {
        rm_rf(staging);
        return 1;
    }

    // Iterate PlugIns/*.appex and decrypt each one. Each .appex is a
    // self-contained bundle with its own main exec + optional Frameworks/;
    // it wouldn't be reached by dyld while the main app is merely spawned
    // suspended, so we need its own spawn-and-dump pass.
    //
    // Note we only look at the main app's PlugIns/, not any nested appex
    // inside Watch/ - those are watchOS binaries, can't execute on iPhone.
    char plugins_src[4096];
    snprintf(plugins_src, sizeof(plugins_src), "%s/PlugIns", bundle);
    DIR *pd = opendir(plugins_src);
    if (pd) {
        struct dirent *pde;
        while ((pde = readdir(pd)) != NULL) {
            size_t nl = strlen(pde->d_name);
            if (nl < 6 || strcmp(pde->d_name + nl - 6, ".appex") != 0) continue;
            char appex_src[4096], appex_dst[4096];
            snprintf(appex_src, sizeof(appex_src), "%s/%s", plugins_src, pde->d_name);
            snprintf(appex_dst, sizeof(appex_dst), "%s/PlugIns/%s", app_dst, pde->d_name);
            LOG("[helper] decrypting plugin %s\n", pde->d_name);
            EVT("event=plugin_start name=\"%s\"", pde->d_name);
            (void)decrypt_bundle(appex_src, appex_dst);
        }
        closedir(pd);
    }

    LOG("[helper] zipping → %s\n", out_ipa);
    EVT("event=zip");
    if (zip_payload(staging, out_ipa) != 0) {
        rm_rf(staging);
        EVT("event=fail stage=zip");
        return 1;
    }
    rm_rf(staging);
    EVT("event=done");
    return 0;
}
