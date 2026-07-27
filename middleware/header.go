package middleware

import (
	"context"
	"net/http"
)

// SetRequestHeader returns a [RequestFunc] that sets key to value on every request.
// An existing value for key is replaced.
func SetRequestHeader(key, value string) RequestFunc {
	return func(ctx context.Context, req *http.Request) (*http.Request, *http.Response) {
		req = req.Clone(ctx)
		req.Header.Set(key, value)
		return req, nil
	}
}

// RemoveRequestHeader returns a [RequestFunc] that removes key from every request.
func RemoveRequestHeader(key string) RequestFunc {
	return func(ctx context.Context, req *http.Request) (*http.Request, *http.Response) {
		req = req.Clone(ctx)
		req.Header.Del(key)
		return req, nil
	}
}

// SetResponseHeader returns a [ResponseFunc] that sets key to value on every response.
// An existing value for key is replaced.
func SetResponseHeader(key, value string) ResponseFunc {
	return func(ctx context.Context, resp *http.Response) (*http.Response, error) {
		resp.Header.Set(key, value)
		return resp, nil
	}
}

// RemoveResponseHeader returns a [ResponseFunc] that removes key from every response.
func RemoveResponseHeader(key string) ResponseFunc {
	return func(ctx context.Context, resp *http.Response) (*http.Response, error) {
		resp.Header.Del(key)
		return resp, nil
	}
}

