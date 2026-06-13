package interceptor

import (
	"context"
	"net/http"
	"strings"
)

// Blocker returns an [OnRequestFunc] that responds with 403 Forbidden when the
// request's host matches any of the provided patterns.
//
// Patterns support a single leading wildcard:
//   - "example.com"   matches only example.com
//   - "*.example.com" matches any subdomain of example.com, but not example.com itself
func Blocker(patterns ...string) OnRequestFunc {
	return func(ctx context.Context, req *http.Request) (*http.Request, *http.Response) {
		host := req.URL.Hostname()
		for _, p := range patterns {
			if hostMatches(p, host) {
				return nil, Response(http.StatusForbidden, "", http.NoBody)
			}
		}
		return req, nil
	}
}

func hostMatches(pattern, host string) bool {
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(host, pattern[1:]) // pattern[1:] == ".example.com"
	}
	return pattern == host
}
