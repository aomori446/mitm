package middleware

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"sync"
)

// DumpRequest returns a [RequestFunc] that writes each request in HTTP/1.1
// wire format (including body) to w. Intended for debugging.
func DumpRequest(w io.Writer) RequestFunc {
	var mu sync.Mutex
	return func(ctx context.Context, req *http.Request) (*http.Request, *http.Response) {
		b, err := httputil.DumpRequest(req, true)
		if err != nil {
			return req, nil
		}
		mu.Lock()
		fmt.Fprintf(w, "--- REQUEST ---\n%s\n\n", b)
		mu.Unlock()
		return req, nil
	}
}

// DumpResponse returns a [ResponseFunc] that writes each response in
// HTTP/1.1 wire format (including body) to w. Intended for debugging.
func DumpResponse(w io.Writer) ResponseFunc {
	var mu sync.Mutex
	return func(ctx context.Context, resp *http.Response) (*http.Response, error) {
		b, err := httputil.DumpResponse(resp, true)
		if err != nil {
			return resp, nil
		}
		mu.Lock()
		fmt.Fprintf(w, "--- RESPONSE ---\n%s\n\n", b)
		mu.Unlock()
		return resp, nil
	}
}

// Dump returns a pair of middlewares that write each request and response in
// HTTP/1.1 wire format to w. It is a shorthand for calling [DumpRequest]
// and [DumpResponse] with the same writer.
func Dump(w io.Writer) (RequestFunc, ResponseFunc) {
	return DumpRequest(w), DumpResponse(w)
}

