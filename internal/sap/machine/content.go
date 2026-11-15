package machine

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/londek/ipadecrypt/internal/sap/assets"
	"howett.net/plist"
)

const contentSIDBPath = "/var/db/fpsd/SC Info/SC Info.sidb"

// EnrollContent owns one empty, private content runtime through KBSync, the
// caller's Store request and keybag import. No native FairPlay files are read.
// Only a successfully imported SIDB escapes; every guest is closed on failure.
func EnrollContent(ctx context.Context, hardware []byte, dsid uint64, request func(context.Context, []byte) ([]byte, error)) (_ []byte, retErr error) {
	if ctx == nil || len(hardware) != 6 || dsid == 0 || request == nil {
		return nil, errors.New("invalid content enrollment input")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bundle, err := assets.Load(ctx)
	if err != nil {
		return nil, err
	}
	identifier := make([]byte, 16)
	if _, err = rand.Read(identifier); err != nil {
		return nil, err
	}
	a, err := OpenModernADI(ctx, bundle, identifier, nil)
	if err != nil {
		return nil, err
	}
	defer func() { retErr = errors.Join(retErr, a.Close()) }()
	v := &contentFS{files: map[string][]byte{}}
	defer func() {
		for _, b := range v.files {
			clear(b)
		}
	}()
	if err = v.installContentRPC(a); err != nil {
		return nil, err
	}
	version, err := plist.Marshal(map[string]any{"ProductName": "macOS", "ProductVersion": "27.0.1", "ProductBuildVersion": "26A434"}, plist.XMLFormat)
	if err != nil {
		return nil, err
	}
	v.files["/System/Library/CoreServices/SystemVersion.plist"] = version
	for _, m := range []*Machine{a.runtime, a.daemon, a.fairplay, a.kernel} {
		if m == nil {
			continue
		}
		if len(m.services.adiFiles) != 0 {
			return nil, errors.New("content guest has preexisting files")
		}
		if err = v.installStreams(m.services); err != nil {
			return nil, err
		}
		if err = v.installPOSIX(m.services); err != nil {
			return nil, err
		}
	}
	global, err := a.keyBagContext(hardware)
	if err != nil {
		return nil, err
	}
	blob, err := a.runtime.generateKBSync(storeAgentKBSyncEntry, global, dsid)
	if err != nil {
		return nil, err
	}
	defer clear(blob)
	keybag, err := request(ctx, blob)
	if err != nil {
		return nil, err
	}
	defer clear(keybag)
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = a.importKeyBag(global, keybag); err != nil {
		return nil, err
	}
	sidb := v.files[contentSIDBPath]
	if len(sidb) < 4 || len(sidb) > 16<<20 {
		return nil, fmt.Errorf("content import produced invalid SIDB size %d", len(sidb))
	}
	return append([]byte(nil), sidb...), nil
}
