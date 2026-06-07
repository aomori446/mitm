package interceptor

import (
	"io"
	"net/http"
)

// OnRequestFunc is called before a request is forwarded to the upstream server.
type OnRequestFunc func(req *http.Request) (*http.Request, *http.Response)

// OnResponseFunc is called after the upstream response is received and before
// it is written back to the client. The original request is available via resp.Request.
type OnResponseFunc func(resp *http.Response) (*http.Response, error)

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
