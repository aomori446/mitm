package middleware

import (
	"io"
	"net/http"

	"github.com/aomori446/mitm"
)

// RequestFunc is called before a request is forwarded to the upstream server.
type RequestFunc = mitm.RequestFunc

// ResponseFunc is called after the upstream response is received and before
// it is written back to the client. The original request is available via resp.Request.
type ResponseFunc = mitm.ResponseFunc

// Response constructs a standard *http.Response helper.
func Response(status int, contentType string, body io.ReadCloser) *http.Response {
	return mitm.Response(status, contentType, body)
}

