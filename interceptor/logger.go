package interceptor

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// Logger returns a pair of hooks that log each proxied request and response
// using the provided [slog.Logger].
//
// The OnRequest hook records the method and URL at the start of the request.
// The OnResponse hook records the status code, content type, and elapsed time.
//
// Usage:
//
//	onReq, onResp := interceptor.Logger(slog.Default())
//	handler.OnRequest(onReq)
//	handler.OnResponse(onResp)
func Logger(log *slog.Logger) (OnRequestFunc, OnResponseFunc) {
	type startKey struct{}

	onReq := func(ctx context.Context, req *http.Request) (*http.Request, *http.Response) {
		log.InfoContext(ctx, "request",
			"method", req.Method,
			"url", req.URL.String(),
		)
		ctx = context.WithValue(ctx, startKey{}, time.Now())
		return req.WithContext(ctx), nil
	}

	onResp := func(ctx context.Context, resp *http.Response) (*http.Response, error) {
		elapsed := ""
		if t, ok := ctx.Value(startKey{}).(time.Time); ok {
			elapsed = time.Since(t).String()
		}
		log.InfoContext(ctx, "response",
			"status", resp.StatusCode,
			"content_type", resp.Header.Get("Content-Type"),
			"elapsed", elapsed,
			"url", resp.Request.URL.String(),
		)
		return resp, nil
	}

	return onReq, onResp
}
