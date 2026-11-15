package appstore

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	apphttp "github.com/londek/ipadecrypt/internal/apphttp"
)

type responseFormat int

const (
	formatJSON responseFormat = iota
	// formatRaw stores the undecoded body into out, which must be a *[]byte.
	formatRaw
)

// send issues an App Store request through the emulated AppleMediaServices
// backend under the given operation label, persists cookies, and decodes the
// response into out (when non-nil) per format. The AMS guest builds and attests
// the final request from the parameter map (an *apphttp.XMLPayload) or raw
// bytes.
func (c *Client) send(op, method, url string, headers map[string]string, payload apphttp.Payload, format responseFormat, out any) (*http.Response, error) {
	return c.sendRequest(op, apphttp.Request{
		Method:  method,
		URL:     url,
		Headers: headers,
		Payload: payload,
	}, format, out)
}

// sendRequest is send for callers that need request options send does not
// expose, such as NoRedirects. On a decode failure it still returns the
// response so its headers stay inspectable.
func (c *Client) sendRequest(op string, req apphttp.Request, format responseFormat, out any) (*http.Response, error) {
	req.ResponseFormat = apphttpFormat(format)

	var raw []byte
	if rp, ok := req.Payload.(*apphttp.RawPayload); ok {
		raw = rp.Content
	}

	url := req.URL

	res, err := c.backend.Client(op).Send(req, raw)
	if err != nil {
		return nil, &apphttp.TransportError{Err: err}
	}
	defer res.Body.Close()

	if err := c.jar.Save(); err != nil {
		return nil, fmt.Errorf("save cookies: %w", err)
	}

	if out == nil {
		io.Copy(io.Discard, res.Body)
		return res, nil
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if debugEnabled() && debugDumpURL(url) {
		debugf("%s -> status=%d body=%s", url, res.StatusCode, truncateBody(data, 1500))
	}

	switch format {
	case formatRaw:
		*out.(*[]byte) = data
	case formatJSON:
		if err := json.Unmarshal(data, out); err != nil {
			return nil, fmt.Errorf("decode json: %w", err)
		}
	}

	return res, nil
}

func apphttpFormat(f responseFormat) apphttp.ResponseFormat {
	if f == formatRaw {
		return apphttp.ResponseFormatRaw
	}

	return apphttp.ResponseFormatJSON
}

func truncateBody(body []byte, max int) string {
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) <= max {
		return trimmed
	}

	return trimmed[:max] + "..."
}
