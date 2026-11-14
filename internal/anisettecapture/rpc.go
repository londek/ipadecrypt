package anisettecapture

import (
	"context"
	"os"

	"github.com/londek/ipadecrypt/internal/device"
	"github.com/londek/ipadecrypt/internal/fridarpc"
)

func attachDeviceScript(ctx context.Context, client *device.Client, process, path string, event func(fridarpc.Event)) (*fridarpc.Script, error) {
	source, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	conn, err := client.DialContext(ctx, "127.0.0.1:27042")
	if err != nil {
		return nil, err
	}

	return fridarpc.AttachConn(ctx, conn, "127.0.0.1:27042", process, string(source), event)
}
