package interceptor

import (
	"io"
	"net/http"
)

// OnRequestFunc is called before a request is forwarded to the upstream server.
//
// - Returning nil passes the request through to the upstream server.
//
// - Returning a non-nil [*http.Response] short-circuits the upstream: the response
// is written directly to the client. Use this for ad-blocking, mock responses, etc.
//
// Modifications to req (e.g. headers) are always forwarded when passing through.
// Hooks that encounter an internal failure should decide themselves whether to
// fail open (return nil) or return an appropriate error response (e.g. 500).
type OnRequestFunc func(req *http.Request) *http.Response

// OnResponseFunc is called after the upstream response is received and before
// it is written back to the client. The original request is available via resp.Request.
//
// - Returning nil forwards resp to the client; hooks may mutate resp in place
// (e.g. modify headers, replace Body) before returning nil.
//
// - Returning a non-nil [*http.Response] substitutes the upstream response:
// the original resp.Body is closed, the returned response is sent to the client,
// and no further OnResponse hooks are called.
type OnResponseFunc func(resp *http.Response) *http.Response

func Response(status int, contentType string, body io.ReadCloser) *http.Response {
	header := make(http.Header)
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	return &http.Response{
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          body,
		ContentLength: -1,
	}
}
