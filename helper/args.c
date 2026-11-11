#include "args.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void args_usage(FILE *out, const char *progname) {
    fprintf(out,
"usage: %s [-v] <subcommand> [args]\n"
"\n"
"subcommands:\n"
"  decrypt [--skip-appex] [--execs-only] <bundle-id> <bundle-src> <out-ipa>\n"
"      Decrypt the installed bundle and write a plaintext IPA.\n"
"      --skip-appex  don't decrypt app extensions (PlugIns/*.appex and\n"
"                    Extensions/*.appex); they stay encrypted in the output.\n"
"      --execs-only  stream framed Mach-O records on stdout (events go to\n"
"                    stderr); no zip on device, out-ipa ignored. Frame:\n"
"                    [u32be plen][plen-byte path][u64be size][size bytes].\n"
"      bundle-id     CFBundleIdentifier; empty string skips SBS and uses\n"
"                    ptrace-only spawn (required for appex extensions).\n"
"      bundle-src    absolute path to the installed .app on disk.\n"
"      out-ipa       where to write the decrypted IPA. \"-\" streams the\n"
"                    IPA bytes to stdout (events move to stderr).\n"
"\n"
"  version\n"
"      Print build identification and exit.\n"
"\n"
"flags:\n"
"  -v, --verbose   emit LOG_DEBUG events (extra detail)\n"
"  -h, --help      print this usage and exit 0\n",
        progname);
}

static int eq(const char *a, const char *b) { return strcmp(a, b) == 0; }

// Returns 1 if `arg` was consumed as a global flag.
static int parse_global(const char *arg, global_flags_t *g) {
    if (eq(arg, "-v") || eq(arg, "--verbose")) { g->verbose = 1; return 1; }
    // Backwards-compat: -q used to silence stderr in the old dual-output
    // design. The new helper has one channel (events on stdout); -q is a
    // no-op so existing wrappers that still pass it don't error out.
    if (eq(arg, "-q") || eq(arg, "--quiet")) { return 1; }
    return 0;
}

const char *args_parse(int argc, char **argv,
                       global_flags_t *out_globals,
                       decrypt_args_t *out_decrypt) {
    out_globals->verbose = 0;
    memset(out_decrypt, 0, sizeof(*out_decrypt));

    const char *progname = (argc > 0) ? argv[0] : "helper";
    const char *pos[8] = {0};
    int n_pos = 0;
    const char *subcmd = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (eq(a, "-h") || eq(a, "--help")) {
            args_usage(stdout, progname);
            exit(0);
        }
        if (parse_global(a, out_globals)) continue;
        if (eq(a, "--skip-appex")) { out_decrypt->skip_appex = 1; continue; }
        if (eq(a, "--execs-only")) { out_decrypt->execs_only = 1; continue; }

        if (subcmd == NULL && a[0] != '-') {
            // First non-flag is the subcommand (or, in the backward-compat
            // shim, the first positional of an implicit `decrypt`).
            if (eq(a, "decrypt") || eq(a, "version")) {
                subcmd = a;
                continue;
            }
            // Implicit decrypt: positionals start here.
        }
        if (n_pos < 8) pos[n_pos++] = a;
    }

    // With --execs-only, out-ipa is meaningless; allow 2 positionals.
    int min_pos = out_decrypt->execs_only ? 2 : 3;

    if (subcmd == NULL) {
        // Backward-compat: positionals → treat as `decrypt`.
        if (n_pos != min_pos && n_pos != 3) {
            args_usage(stderr, progname);
            return NULL;
        }
        out_decrypt->bundle_id  = pos[0];
        out_decrypt->bundle_src = pos[1];
        out_decrypt->out_ipa    = (n_pos == 3) ? pos[2] : "";
        return "decrypt";
    }

    if (eq(subcmd, "version")) return "version";

    if (eq(subcmd, "decrypt")) {
        if (n_pos != min_pos && n_pos != 3) {
            fprintf(stderr, "decrypt: expected %d positional args, got %d\n", min_pos, n_pos);
            args_usage(stderr, progname);
            return NULL;
        }
        out_decrypt->bundle_id  = pos[0];
        out_decrypt->bundle_src = pos[1];
        out_decrypt->out_ipa    = (n_pos == 3) ? pos[2] : "";
        return "decrypt";
    }

    fprintf(stderr, "unknown subcommand: %s\n", subcmd);
    args_usage(stderr, progname);
    return NULL;
}
