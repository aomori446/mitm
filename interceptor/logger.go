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
	type key struct{}
	type value struct {
		id   int
		time time.Time
	}

	var idCounter int

	onReq := func(ctx context.Context, req *http.Request) (*http.Request, *http.Response) {
		log.InfoContext(ctx,
			"request",
			"id", idCounter,
			"method", req.Method,
			"url", req.URL.String(),
		)
		ctx = context.WithValue(ctx, key{}, value{id: idCounter, time: time.Now()})
		idCounter++
		return req.WithContext(ctx), nil
	}

	onResp := func(ctx context.Context, resp *http.Response) (*http.Response, error) {
		elapsed := ""
		id := 0
		if v, ok := ctx.Value(key{}).(value); ok {
			elapsed = time.Since(v.time).String()
			id = v.id
		}
		log.InfoContext(ctx,
			"response",
			"id", id,
			"status", resp.StatusCode,
			"content_type", resp.Header.Get("Content-Type"),
			"elapsed", elapsed,
			"url", resp.Request.URL.String(),
		)
		return resp, nil
	}

	return onReq, onResp
}
