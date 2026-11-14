package appstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	apphttp "github.com/londek/ipadecrypt/internal/apphttp"
	"howett.net/plist"
)

type responseFormat int

const (
	formatXML responseFormat = iota
	formatJSON
)

var (
	documentXMLPattern = regexp.MustCompile(`(?is)<Document\b[^>]*>(.*)</Document>`)
	plistXMLPattern    = regexp.MustCompile(`(?is)<plist\b[^>]*>.*?</plist>`)
	dictXMLPattern     = regexp.MustCompile(`(?is)<dict\b[^>]*>.*</dict>`)
)

// send issues an App Store request through the emulated AppleMediaServices
// backend under the given operation label, persists cookies, and decodes the
// response into out (when non-nil) per format. The AMS guest builds and attests
// the final request from the parameter map (an *apphttp.XMLPayload) or raw
// bytes; signer, when set, provides the SAP signature used for authenticate.
func (c *Client) send(op, method, url string, headers map[string]string, payload apphttp.Payload, signer apphttp.ActionSigner, format responseFormat, out any) (*http.Response, error) {
	return c.sendRequest(op, apphttp.Request{
		Method:       method,
		URL:          url,
		Headers:      headers,
		Payload:      payload,
		ActionSigner: signer,
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
		return nil, err
	}
	defer res.Body.Close()

	if err := c.jar.Save(); err != nil {
		return nil, fmt.Errorf("save cookies: %w", err)
	}

	if debugEnabled() {
		debugf("%s %s -> %s", op, url, apphttp.DescribeResponse(res))
	}

	if res.StatusCode == http.StatusTooManyRequests {
		return res, fmt.Errorf("rate limited by Apple (HTTP %d)", res.StatusCode)
	}

	// Redirect bodies are HTML stubs; callers act on the status and Location.
	isRedirect := res.StatusCode >= http.StatusMultipleChoices && res.StatusCode < http.StatusBadRequest

	if out == nil || isRedirect {
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

	// Provisioning actions and valid plist replies take precedence over the
	// routing-header heuristic; newer Store responses may omit those markers.
	if op == "authenticate" && authenticationMachineAction(res.Header) == nil &&
		!looksLikePlist(normalizePlist(data)) {
		if err := authenticateLayerError(res); err != nil {
			return res, err
		}
	}

	switch format {
	case formatJSON:
		if err := json.Unmarshal(data, out); err != nil {
			return nil, fmt.Errorf("decode json: %w", err)
		}
	case formatXML:
		normalized := normalizePlist(data)
		if !looksLikePlist(normalized) {
			return res, &ResponseDecodeError{
				Cause:       errors.New("response is not a property list"),
				StatusCode:  res.StatusCode,
				ContentType: res.Header.Get("Content-Type"),
				Body:        truncateBody(data, 500),
				URLs:        extractURLs(data),
			}
		}

		if _, err := plist.Unmarshal(normalized, out); err != nil {
			return res, &ResponseDecodeError{
				Cause:       err,
				StatusCode:  res.StatusCode,
				ContentType: res.Header.Get("Content-Type"),
				Body:        truncateBody(data, 500),
				URLs:        extractURLs(data),
			}
		}
	}

	return res, nil
}

// looksLikePlist reports whether body is plausibly a property list: a binary
// bplist, or XML that contains a plist/dict/array/key element. HTML error
// stubs (e.g. an nginx 404 page) fail this, so they never reach the parser.
func looksLikePlist(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}

	if bytes.HasPrefix(trimmed, []byte("bplist")) {
		return true
	}

	for _, marker := range [][]byte{[]byte("<plist"), []byte("<dict"), []byte("<array"), []byte("<key")} {
		if bytes.Contains(trimmed, marker) {
			return true
		}
	}

	return false
}

func apphttpFormat(f responseFormat) apphttp.ResponseFormat {
	if f == formatJSON {
		return apphttp.ResponseFormatJSON
	}

	return apphttp.ResponseFormatXML
}

// normalizePlist unwraps Apple's various plist embeddings. Responses sometimes
// come wrapped in <Document>…</Document>, or are a bare <dict>…</dict> without
// the <plist> envelope, or are a bag of <key>/<value> pairs without any outer
// element at all.
func normalizePlist(body []byte) []byte {
	n := bytes.TrimSpace(body)
	if len(n) == 0 {
		return n
	}

	if m := documentXMLPattern.FindSubmatch(n); len(m) >= 2 {
		if inner := bytes.TrimSpace(m[1]); len(inner) > 0 {
			n = inner
		}
	}

	if m := plistXMLPattern.Find(n); len(m) > 0 {
		n = bytes.TrimSpace(m)
	}

	if m := dictXMLPattern.Find(n); len(m) > 0 {
		return bytes.TrimSpace(m)
	}

	if bytes.Contains(n, []byte("<key>")) {
		return []byte("<dict>" + string(n) + "</dict>")
	}

	return n
}

type ResponseDecodeError struct {
	Cause       error
	StatusCode  int
	ContentType string
	Body        string
	URLs        []string
}

func (e *ResponseDecodeError) Error() string {
	return fmt.Sprintf("failed to unmarshal xml: %v", e.Cause)
}

func (e *ResponseDecodeError) Unwrap() error {
	return e.Cause
}

var urlPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

func extractURLs(body []byte) []string {
	matches := urlPattern.FindAll(body, -1)

	urls := make([]string, 0, len(matches))
	for _, match := range matches {
		urls = append(urls, string(match))
	}

	return urls
}

func truncateBody(body []byte, max int) string {
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) <= max {
		return trimmed
	}

	return trimmed[:max] + "..."
}
