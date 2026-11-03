package appstore

import (
	"fmt"
	"os"
	"strings"
)

// debugEnabled reports whether IPADECRYPT_DEBUG is set, turning on verbose
// diagnostics for the App Store download/version chain on stderr.
func debugEnabled() bool { return os.Getenv("IPADECRYPT_DEBUG") != "" }

func debugf(format string, args ...any) {
	if debugEnabled() {
		fmt.Fprintf(os.Stderr, "[ipadecrypt debug] "+format+"\n", args...)
	}
}

// debugDumpURL reports whether raw response bodies for this URL may be dumped.
// It allowlists the download and version-lookup endpoints and never matches the
// authenticate/login endpoints, whose bodies carry the account password.
func debugDumpURL(u string) bool {
	for _, s := range []string{"DownloadProduct", "/r/redownload", "/up/updateProduct", "MZStorePlatform", "/catalog/"} {
		if strings.Contains(u, s) {
			return true
		}
	}

	return false
}
