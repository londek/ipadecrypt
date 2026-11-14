package macstore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	apphttp "github.com/londek/ipadecrypt/internal/apphttp"
	store "github.com/majd/ipatool/v2/pkg/appstore"
)

const storeUserAgent = "Configurator/2.21 (Macintosh; OS X 27.0.1; 26A434) AppleWebKit/0625.2.5.11.6"

func (s *Session) hardwareID() ([]byte, error) {
	address, err := s.machine.MacAddress()
	if err != nil {
		return nil, err
	}

	hardware, err := net.ParseMAC(address)
	if err != nil || len(hardware) != 6 {
		return nil, errors.New("invalid Store hardware identity")
	}

	return hardware, nil
}

func accountHeaders(a store.Account) map[string]string {
	return map[string]string{
		"Content-Type":        "application/x-apple-plist",
		"User-Agent":          storeUserAgent,
		"iCloud-DSID":         a.DirectoryServicesID,
		"X-Dsid":              a.DirectoryServicesID,
		"X-Token":             a.PasswordToken,
		"X-Apple-Store-Front": a.StoreFront,
	}
}

func storeEndpoint(raw, path string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Path != path {
		return nil, errors.New("unrecognized Apple Store endpoint")
	}

	if path == entDownloadPath {
		if u.Host != "downloaddispatch.itunes.apple.com" {
			return nil, errors.New("unrecognized download dispatcher")
		}
	} else if !storeHost(u.Host) {
		return nil, errors.New("unrecognized Apple Store host")
	}

	return u, nil
}

func storeHost(host string) bool {
	if host == "buy.itunes.apple.com" {
		return true
	}

	pod, ok := strings.CutSuffix(host, "-buy.itunes.apple.com")

	return ok && strings.HasPrefix(pod, "p") && digits.MatchString(strings.TrimPrefix(pod, "p"))
}

// Disable guest response decoding so Store actions are returned to the TUI,
// rather than invoking native UI methods in the emulated framework.
func (s *Session) sendPlist(ctx context.Context, operation, endpoint string, headers map[string]string, payload map[string]any) (map[string]any, error) {
	request := apphttp.Request{Context: ctx, URL: endpoint, Method: "GET", Headers: headers, ResponseFormat: apphttp.ResponseFormatRaw, NoRedirects: true}
	if payload != nil {
		request.Method = "POST"
		request.Payload = &apphttp.XMLPayload{Content: payload}
	}

	client := apphttp.NewClient[[]byte](apphttp.Args{Executor: s.backend.Client(operation), CookieJar: s.jar, Timeout: apphttp.DefaultAuthenticationTimeout})

	response, err := client.Send(request)
	if err != nil {
		return nil, SafeError(err)
	}
	defer clear(response.Data)

	if response.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected Apple Store HTTP status %d", response.StatusCode)
	}

	var values map[string]any
	if len(response.Data) > 16<<20 || apphttp.DecodePropertyList(response.Data, &values) != nil {
		return nil, errors.New("invalid Apple Store response")
	}

	if err := storeInteraction(values); err != nil {
		return nil, err
	}

	return values, nil
}
