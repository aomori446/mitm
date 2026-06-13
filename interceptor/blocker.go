package interceptor

import (
	"context"
	"net/http"
	"strings"
)

// BlockResponse constructs the HTTP response returned for a blocked request.
type BlockResponse func(req *http.Request) *http.Response

// Blocker returns an [OnRequestFunc] that responds with 403 Forbidden when the
// request's host matches any of the provided patterns.
//
// Patterns support a single leading wildcard:
//   - "example.com"   matches only example.com
//   - "*.example.com" matches any subdomain of example.com, but not example.com itself
func Blocker(patterns ...string) OnRequestFunc {
	return BlockerWith(RespondWith403(), patterns...)
}

// BlockerWith is like [Blocker] but uses respond instead of 403 Forbidden.
func BlockerWith(respond BlockResponse, patterns ...string) OnRequestFunc {
	return BlockerFunc(respond, func(req *http.Request) bool {
		host := req.URL.Hostname()
		for _, p := range patterns {
			if hostMatches(p, host) {
				return true
			}
		}
		return false
	})
}

// BlockerFunc returns an [OnRequestFunc] that calls respond when match returns true.
// Use this when host-pattern matching is not expressive enough, e.g. for URL path filtering.
func BlockerFunc(respond BlockResponse, match func(*http.Request) bool) OnRequestFunc {
	return func(ctx context.Context, req *http.Request) (*http.Request, *http.Response) {
		if match(req) {
			return nil, respond(req)
		}
		return req, nil
	}
}

func hostMatches(pattern, host string) bool {
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(host, pattern[1:])
	}
	return pattern == host
}
