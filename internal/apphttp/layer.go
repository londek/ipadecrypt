package http

import (
	"fmt"
	"net/http"
	"strings"
)

// ResponseLayer classifies the routing markers observed on a Store response.
// These headers help diagnose failures; they cannot establish which server
// processed the credentials. "Server: Apple" occurs with several marker sets.
type ResponseLayer string

const (
	// LayerEdge has no recognized backend markers.
	LayerEdge ResponseLayer = "edge"
	// LayerDaiquiri has proxy markers without an application instance marker.
	LayerDaiquiri ResponseLayer = "daiquiri"
	// LayerBackendShort has X-Responding-Instance without Apple-Originating-System.
	LayerBackendShort ResponseLayer = "backend-short"
	// LayerBackendFull has Apple-Originating-System.
	LayerBackendFull ResponseLayer = "backend-full"
)

// ClassifyResponse groups a response by its routing headers.
func ClassifyResponse(h http.Header) ResponseLayer {
	switch {
	case h.Get("Apple-Originating-System") != "":
		return LayerBackendFull
	case h.Get("X-Responding-Instance") != "":
		return LayerBackendShort
	case h.Get("X-Apple-Jingle-Correlation-Key") != "" || len(h.Values("X-Daiquiri-Instance")) > 0:
		return LayerDaiquiri
	default:
		return LayerEdge
	}
}

// DescribeResponse summarizes a response for debug logs. It records only
// routing metadata; cookie values and bodies are never included.
func DescribeResponse(res *http.Response) string {
	h := res.Header

	var b strings.Builder

	fmt.Fprintf(&b, "layer=%s status=%d len=%d type=%q", ClassifyResponse(h), res.StatusCode, res.ContentLength, h.Get("Content-Type"))

	if h.Get("Location") != "" {
		b.WriteString(" location=present")
	}

	for _, name := range []string{"Apple-Originating-System", "X-Responding-Instance", "X-Apple-Jingle-Correlation-Key", "X-Apple-Request-Uuid", "X-Set-Apple-Store-Front", "Pod", "Itspod"} {
		if v := h.Get(name); v != "" {
			fmt.Fprintf(&b, " %s=%q", strings.ToLower(name), v)
		}
	}

	if n := len(h.Values("X-Daiquiri-Instance")); n > 0 {
		fmt.Fprintf(&b, " x-daiquiri-instance=%d", n)
	}

	if len(h.Values("Set-Cookie")) > 0 {
		b.WriteString(" set-cookie=present")
	}

	return b.String()
}
