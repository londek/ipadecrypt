#include "decrypt.h"
#include "dump.h"
#include "dyld_patch.h"
#include "exc.h"
#include "fs.h"
#include "inject.h"
#include "log.h"
#include "macho.h"
#include "spawn.h"
#include "target.h"

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <signal.h>

// ptrace + PT_KILL aren't in any public iOS SDK header; declare here.
extern int ptrace(int, pid_t, void *, int);
#ifndef PT_KILL
#define PT_KILL 8
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

int decrypt_bundle(const char *bundle_src, const char *bundle_dst,
                   const char *bundle_id) {
    char main_name[512];
    if (spawn_find_main_name(bundle_src, main_name, sizeof(main_name)) != 0) {
        attrs_t a; attrs_init(&a);
        attrs_str(&a, "src", bundle_src);
        attrs_str(&a, "reason", "no_main_exec");
        emit(LOG_WARN, "bundle.skipped", &a,
             "no main exec in %s, skipping", bundle_src);
        return 0;
    }

    {
        attrs_t a; attrs_init(&a);
        attrs_str(&a, "src", bundle_src);
        attrs_str(&a, "main", main_name);
        emit(LOG_INFO, "bundle.begin", &a,
             "decrypting bundle %s", bundle_src);
    }

    char main_src[4096], main_dst[4096];
    snprintf(main_src, sizeof(main_src), "%s/%s", bundle_src, main_name);
    snprintf(main_dst, sizeof(main_dst), "%s/%s", bundle_dst, main_name);

    pid_t pid = 0;
    task_t task = MACH_PORT_NULL;
    int via_ptrace = 0;
    if (spawn_suspended(bundle_id, main_src, &pid, &task, &via_ptrace) != 0) {
        attrs_t a; attrs_init(&a);
        attrs_str(&a, "src", bundle_src);
        emit(LOG_ERROR, "bundle.spawn_failed", &a,
             "spawn failed for %s", bundle_src);
        return 0;
    }

    // 1) Dump the main exec from the freshly-suspended target.
    //    SBS-launched targets have dyld already past the main exec
    //    mapping, so vm_read of the encrypted region succeeds. ptrace-
    //    spawned targets (appex, or SBS-rejected main fallback) are at
    //    PT_ATTACHEXC stop; dump_image's page-fault traversal usually
    //    reaches everything before AMFI catches up.
    runtime_image_t bundle_rt;
    int have_bundle_rt = 0;
    int main_dumped = 0;
    mach_vm_address_t main_base = 0;
    if (target_find_main_base(task, &main_base) == 0 &&
        target_read_runtime_image(task, main_base, &bundle_rt) == 0) {
        have_bundle_rt = 1;
        selected_slice_t sel;
        int sr = select_runtime_slice(main_src, &bundle_rt, &sel);
        if (sr == 1 && slice_needs_dump(&sel)) {
            dump_result_t dr = dump_image(main_src, main_dst, task, main_base, &sel);
            if (dr == DUMP_OK) {
                attrs_t a; attrs_init(&a);
                attrs_str(&a, "name", main_name);
                attrs_str(&a, "kind", "main");
                attrs_str(&a, "source", "vm_read");
                attrs_uint(&a, "size", sel.selected.crypt.cryptsize);
                emit(LOG_INFO, "image.done", &a,
                     "decrypted main %s (%s)", main_name,
                     human_bytes(sel.selected.crypt.cryptsize));
                main_dumped = 1;
            } else if (!via_ptrace) {
                attrs_t a; attrs_init(&a);
                attrs_str(&a, "name", main_name);
                attrs_str(&a, "kind", "main");
                attrs_str(&a, "reason", dump_reason(dr));
                emit(LOG_WARN, "image.failed", &a,
                     "failed to dump main %s (%s)", main_name, dump_reason(dr));
            }
        } else if (sr == 1) {
            main_dumped = 1; // nothing to do (cryptid already 0)
        }
    }

    // ptrace path (appex, or SBS-rejected main): stop here. Main exec
    // is what we got from the PT_ATTACHEXC stop  resuming via
    // PT_CONTINUE would just race AMFI's runtime kill.
    if (via_ptrace) {
        ptrace(PT_KILL, pid, 0, 0);
        task_terminate(task);
        kill(pid, SIGKILL);
        int reaped;
        pid_t rw;
        do { rw = waitpid(pid, &reaped, 0); } while (rw < 0 && errno == EINTR);
        attrs_t a; attrs_init(&a);
        attrs_str(&a, "src", bundle_src);
        attrs_int(&a, "extras", 0);
        emit(LOG_INFO, "bundle.done", &a,
             "bundle done: main only (ptrace, no framework enumeration)");
        return 0;
    }

    // 2) Set exception port + patch dyld halt path BEFORE resume.
    //    force-weak, kill_svc, skip_halt patches NOP the svc/brk/halt
    //    sites that would otherwise SIGKILL the target during the
    //    long dlopen chain (needed for PythonCoding-class apps with
    //    hundreds of dynamically-loaded cross-OS extensions).
    mach_port_t exc = exc_make_port(task);
    {
        uint32_t pre_count = 0;
        char *pre_paths = NULL;
        struct dyld_image_info *pre_imgs = target_list_images(task, &pre_count, &pre_paths);
        Dl_info hi = {0};
        dladdr((void *)dlopen, &hi);
        mach_vm_address_t target_libdyld = target_find_image(task,
            pre_imgs, pre_count, hi.dli_fname);
        mach_vm_address_t helper_libdyld_v =
            (mach_vm_address_t)(uintptr_t)hi.dli_fbase;
        dyld_patch_apply(task, pre_imgs, pre_count,
            target_libdyld, helper_libdyld_v);
        free(pre_paths); free(pre_imgs);
    }

    // 3s upper bound. Mach-exception delivery short-circuits the wait,
    // so healthy targets are the only thing that pays the full timeout.
    spawn_run_and_suspend(task, exc, 3000);

    // Retry the main-exec dump if the first attempt hit unfaulted
    // pages. By now dyld has the whole image mapped.
    if (!main_dumped && have_bundle_rt && main_base != 0) {
        selected_slice_t sel;
        if (select_runtime_slice(main_src, &bundle_rt, &sel) == 1 &&
            slice_needs_dump(&sel)) {
            dump_result_t dr = dump_image(main_src, main_dst, task, main_base, &sel);
            attrs_t a; attrs_init(&a);
            attrs_str(&a, "name", main_name);
            attrs_str(&a, "kind", "main");
            attrs_str(&a, "source", "vm_read_retry");
            if (dr == DUMP_OK) {
                attrs_uint(&a, "size", sel.selected.crypt.cryptsize);
                emit(LOG_INFO, "image.done", &a,
                     "decrypted main %s (%s)", main_name,
                     human_bytes(sel.selected.crypt.cryptsize));
                main_dumped = 1;
            } else {
                attrs_str(&a, "reason", dump_reason(dr));
                emit(LOG_WARN, "image.failed", &a,
                     "failed to dump main %s (%s)", main_name, dump_reason(dr));
            }
        }
    }

    // 3) Enumerate images loaded in the (now suspended) target
    //    and dump every encrypted one whose path is inside this bundle.
    uint32_t img_count = 0;
    char *paths = NULL;
    struct dyld_image_info *imgs = target_list_images(task, &img_count, &paths);
    int extra = 0;

    const char *bs = bundle_src;
    size_t bs_len = strlen(bs);
    char bs_pri[4096];
    snprintf(bs_pri, sizeof(bs_pri), "/private%s", bs);
    size_t bs_alt_len = strlen(bs_pri);

    for (uint32_t i = 0; i < img_count && imgs; i++) {
        const char *ip = imgs[i].imageFilePath;
        if (!ip) continue;
        const char *rel = NULL;
        if (strncmp(ip, bs, bs_len) == 0) rel = ip + bs_len;
        else if (strncmp(ip, bs_pri, bs_alt_len) == 0) rel = ip + bs_alt_len;
        if (!rel) continue;
        while (*rel == '/') rel++;
        if (!*rel) continue;
        if (strcmp(rel, main_name) == 0) continue;

        char rel_src[4096], rel_dst[4096];
        snprintf(rel_src, sizeof(rel_src), "%s/%s", bundle_src, rel);
        snprintf(rel_dst, sizeof(rel_dst), "%s/%s", bundle_dst, rel);

        mach_vm_address_t base = (mach_vm_address_t)(uintptr_t)imgs[i].imageLoadAddress;
        runtime_image_t img_rt;
        if (target_read_runtime_image(task, base, &img_rt) != 0) continue;
        if (!have_bundle_rt) { bundle_rt = img_rt; have_bundle_rt = 1; }

        selected_slice_t sel;
        if (select_runtime_slice(rel_src, &img_rt, &sel) != 1) continue;
        if (!slice_needs_dump(&sel)) continue;

        {
            attrs_t a0; attrs_init(&a0);
            attrs_str(&a0, "name", rel);
            attrs_str(&a0, "kind", "framework");
            attrs_uint(&a0, "size", sel.selected.crypt.cryptsize);
            emit(LOG_DEBUG, "image.begin", &a0,
                 "decrypting %s (%s)", rel,
                 human_bytes(sel.selected.crypt.cryptsize));
        }
        dump_result_t dr = dump_image(rel_src, rel_dst, task, base, &sel);
        attrs_t a; attrs_init(&a);
        attrs_str(&a, "name", rel);
        attrs_str(&a, "kind", "framework");
        attrs_str(&a, "source", "vm_read");
        if (dr == DUMP_OK) {
            attrs_uint(&a, "size", sel.selected.crypt.cryptsize);
            emit(LOG_INFO, "image.done", &a,
                 "decrypted %s (%s)", rel,
                 human_bytes(sel.selected.crypt.cryptsize));
            extra++;
        } else {
            attrs_str(&a, "reason", dump_reason(dr));
            emit(LOG_WARN, "image.failed", &a,
                 "failed to dump %s (%s)", rel, dump_reason(dr));
        }
    }

    // 4) Inject dlopen for any encrypted bundle Mach-O dyld didn't map.
    if (have_bundle_rt) {
        extra += inject_missing_frameworks(task, exc, bundle_src,
            bundle_dst, imgs, img_count, &bundle_rt);
    }

    free(paths); free(imgs);

    mach_port_mod_refs(mach_task_self(), exc, MACH_PORT_RIGHT_RECEIVE, -1);
    task_terminate(task);
    kill(pid, SIGKILL);
    int reaped;
    pid_t rw;
    do { rw = waitpid(pid, &reaped, 0); } while (rw < 0 && errno == EINTR);

    attrs_t a; attrs_init(&a);
    attrs_str(&a, "src", bundle_src);
    attrs_int(&a, "extras", extra);
    emit(LOG_INFO, "bundle.done", &a,
         "bundle done: %d framework(s) decrypted", extra);
    return 0;
}

void decrypt_appexes(const char *bundle_src, const char *bundle_dst) {
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
            decrypt_bundle(s, t, NULL);
        }
        closedir(d);
    }
}

// ----- in-process zip writer (replaces the external `zip` binary) -----------
//
// We build the IPA ourselves with libz (always present in the iOS shared
// cache) instead of spawning /usr/bin/zip, so the helper has no on-device
// package dependency and still works as a standalone CLI. Output is a normal
// DEFLATE zip written forward-only (data descriptors carry crc/sizes) so it
// streams to a non-seekable stdout as well as to a file. Unix modes go in the
// external attrs so the decrypted main exec keeps its +x bit. Archives are
// assumed < 4 GiB (no zip64); IPAs are well under that.

static const char *kZipExcludes[] = {
    "Payload/*/Watch/*", "Payload/*/Watch",
    "Payload/*/WatchKitSupport2/*", "Payload/*/WatchKitSupport2",
    "Payload/*/SC_Info/*", "Payload/*/SC_Info",
    "*/SC_Info/*", "*/SC_Info",
    "Payload/*/*.dSYM/*", "Payload/*/*.dSYM",
    "Payload/*/BCSymbolMaps/*", "Payload/*/BCSymbolMaps",
    "Payload/*/Symbols/*", "Payload/*/Symbols",
    "Payload/META-INF/*", "Payload/META-INF",
    "Payload/iTunesMetadata.plist", "Payload/iTunesArtwork",
    NULL
};

static int zip_excluded(const char *rel) {
    for (int i = 0; kZipExcludes[i]; i++)
        if (fnmatch(kZipExcludes[i], rel, 0) == 0) return 1;
    return 0;
}

struct zip_entry {
    char *name;
    uint32_t crc, csize, usize, offset, extattr;
    uint16_t dostime, dosdate;
    struct zip_entry *next;
};

static void zput16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static void zput32(uint8_t *p, uint32_t v) {
    p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}

static int zwrite(int fd, const void *buf, size_t n) {
    const char *p = buf;
    for (size_t off = 0; off < n; ) {
        ssize_t w = write(fd, p + off, n - off);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        off += (size_t)w;
    }
    return 0;
}

static void zip_dostime(time_t t, uint16_t *dt, uint16_t *dd) {
    struct tm tmv;
    localtime_r(&t, &tmv);
    if (tmv.tm_year < 80) tmv.tm_year = 80;  // zip epoch is 1980
    *dt = (uint16_t)((tmv.tm_hour << 11) | (tmv.tm_min << 5) | (tmv.tm_sec / 2));
    *dd = (uint16_t)(((tmv.tm_year - 80) << 9) | ((tmv.tm_mon + 1) << 5) | tmv.tm_mday);
}

static int zip_add_file(int out, const char *full, const char *rel,
                        uint64_t *cursor, struct zip_entry **head,
                        struct zip_entry **tail) {
    int fd = open(full, O_RDONLY);
    if (fd < 0) {
        // Unreadable source file: warn and skip.
        // Nothing has been written to `out` yet, so the archive stays
        // consistent. (>0 = skip, <0 = fatal output error.)
        wrn("skipping unreadable %s: %s", rel, strerror(errno));
        return 1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        wrn("skipping %s: fstat: %s", rel, strerror(errno));
        close(fd);
        return 1;
    }

    uint16_t dostime, dosdate;
    zip_dostime(st.st_mtime, &dostime, &dosdate);
    uint32_t local_off = (uint32_t)*cursor;
    size_t namelen = strlen(rel);

    uint8_t lh[30];
    zput32(lh, 0x04034b50);
    zput16(lh + 4, 20);       // version needed
    zput16(lh + 6, 0x0008);   // flag: crc/sizes in trailing data descriptor
    zput16(lh + 8, 8);        // method: deflate
    zput16(lh + 10, dostime);
    zput16(lh + 12, dosdate);
    zput32(lh + 14, 0);
    zput32(lh + 18, 0);
    zput32(lh + 22, 0);
    zput16(lh + 26, (uint16_t)namelen);
    zput16(lh + 28, 0);
    if (zwrite(out, lh, 30) || zwrite(out, rel, namelen)) { close(fd); return -1; }
    *cursor += 30 + namelen;

    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (deflateInit2(&zs, 1, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        close(fd);
        return -1;
    }
    uint8_t in[65536], out_buf[65536];
    uint32_t crc = crc32(0L, Z_NULL, 0);
    uint64_t usize = 0, csize = 0;
    int rc = 0, flush = Z_NO_FLUSH;
    do {
        ssize_t n = read(fd, in, sizeof(in));
        if (n < 0) { if (errno == EINTR) continue; rc = -1; break; }
        if (n == 0) flush = Z_FINISH;
        crc = crc32(crc, in, (uInt)n);
        usize += (uint64_t)n;
        zs.next_in = in;
        zs.avail_in = (uInt)n;
        do {
            zs.next_out = out_buf;
            zs.avail_out = sizeof(out_buf);
            deflate(&zs, flush);
            size_t produced = sizeof(out_buf) - zs.avail_out;
            if (produced && zwrite(out, out_buf, produced)) { rc = -1; break; }
            csize += produced;
        } while (zs.avail_out == 0);
    } while (rc == 0 && flush != Z_FINISH);
    deflateEnd(&zs);
    close(fd);
    if (rc != 0) return -1;
    *cursor += csize;

    uint8_t dd[16];
    zput32(dd, 0x08074b50);
    zput32(dd + 4, crc);
    zput32(dd + 8, (uint32_t)csize);
    zput32(dd + 12, (uint32_t)usize);
    if (zwrite(out, dd, 16)) return -1;
    *cursor += 16;

    struct zip_entry *e = calloc(1, sizeof(*e));
    if (!e) return -1;
    e->name = strdup(rel);
    e->crc = crc;
    e->csize = (uint32_t)csize;
    e->usize = (uint32_t)usize;
    e->offset = local_off;
    e->extattr = ((uint32_t)(st.st_mode & 0xFFFF)) << 16;
    e->dostime = dostime;
    e->dosdate = dosdate;
    if (*tail) (*tail)->next = e; else *head = e;
    *tail = e;
    return 0;
}

static int zip_walk(int out, const char *base, const char *rel,
                    uint64_t *cursor, struct zip_entry **head,
                    struct zip_entry **tail) {
    char dir[4096];
    if (rel[0]) snprintf(dir, sizeof(dir), "%s/%s", base, rel);
    else snprintf(dir, sizeof(dir), "%s", base);
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *de;
    int rc = 0;
    while (rc == 0 && (de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char child[4096], full[4096];
        if (rel[0]) snprintf(child, sizeof(child), "%s/%s", rel, de->d_name);
        else snprintf(child, sizeof(child), "%s", de->d_name);
        if (zip_excluded(child)) continue;
        snprintf(full, sizeof(full), "%s/%s", base, child);
        struct stat st;
        if (lstat(full, &st) != 0) continue;
        if (S_ISLNK(st.st_mode) && stat(full, &st) != 0) continue;  // deref
        if (S_ISDIR(st.st_mode))
            rc = zip_walk(out, base, child, cursor, head, tail);
        else if (S_ISREG(st.st_mode)) {
            // >0 means an unreadable file we skipped (non-fatal); only a
            // <0 output-stream error aborts the walk.
            int ar = zip_add_file(out, full, child, cursor, head, tail);
            if (ar < 0) rc = ar;
        }
    }
    closedir(d);
    return rc;
}

int run_zip(const char *staging, const char *ipa_path) {
    int stream_stdout = ipa_path && ipa_path[0] == '-' && ipa_path[1] == '\0';
    int out = stream_stdout
                  ? STDOUT_FILENO
                  : open(ipa_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) {
        er("open %s: %s", ipa_path, strerror(errno));
        return -1;
    }

    uint64_t cursor = 0;
    struct zip_entry *head = NULL, *tail = NULL;
    int rc = zip_walk(out, staging, "Payload", &cursor, &head, &tail);

    // No entries means staging/Payload was missing or unreadable: fail
    // loudly instead of emitting a valid-but-empty archive.
    if (rc == 0 && !head) {
        er("staging %s has no Payload contents", staging);
        rc = -1;
    }

    uint32_t cd_start = (uint32_t)cursor, cd_size = 0, count = 0;
    for (struct zip_entry *e = head; rc == 0 && e; e = e->next) {
        size_t nl = strlen(e->name);
        uint8_t ch[46];
        zput32(ch, 0x02014b50);
        zput16(ch + 4, 0x0314);   // version made by: unix, v2.0 (so extattr = mode)
        zput16(ch + 6, 20);
        zput16(ch + 8, 0x0008);
        zput16(ch + 10, 8);
        zput16(ch + 12, e->dostime);
        zput16(ch + 14, e->dosdate);
        zput32(ch + 16, e->crc);
        zput32(ch + 20, e->csize);
        zput32(ch + 24, e->usize);
        zput16(ch + 28, (uint16_t)nl);
        zput16(ch + 30, 0);
        zput16(ch + 32, 0);
        zput16(ch + 34, 0);
        zput16(ch + 36, 0);
        zput32(ch + 38, e->extattr);
        zput32(ch + 42, e->offset);
        if (zwrite(out, ch, 46) || zwrite(out, e->name, nl)) rc = -1;
        cd_size += 46 + nl;
        count++;
    }

    if (rc == 0) {
        uint8_t eo[22];
        zput32(eo, 0x06054b50);
        zput16(eo + 4, 0);
        zput16(eo + 6, 0);
        zput16(eo + 8, (uint16_t)count);
        zput16(eo + 10, (uint16_t)count);
        zput32(eo + 12, cd_size);
        zput32(eo + 16, cd_start);
        zput16(eo + 20, 0);
        if (zwrite(out, eo, 22)) rc = -1;
    }

    for (struct zip_entry *e = head; e; ) {
        struct zip_entry *n = e->next;
        free(e->name);
        free(e);
        e = n;
    }
    if (!stream_stdout) close(out);
    if (rc != 0) er("zip writer failed");
    return rc;
}
