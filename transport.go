package mitm

import (
	"net"
	"net/http"
	"time"
)

type middlewareTransport struct {
	base    http.RoundTripper
	handler *Handler
}

func (t *middlewareTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	req.RequestURI = ""
	req, resp = t.handler.runRequestMiddlewares(req)
	if resp != nil {
		return resp, nil
	}

	resp, err = t.base.RoundTrip(req)
	if err != nil {
		t.handler.notifyError(req.Context(), req, err)
		return nil, err
	}

	return t.handler.runResponseMiddlewares(resp)
}

// newUpstreamTransport builds the transport used for every intercepted
// request. One transport serves every host on purpose: [http.Transport]
// already keys its connection pool by host:port, so a transport per host buys
// no isolation the pool does not already provide, while costing a map entry
// that a proxy — which sees an unbounded set of hosts over its lifetime —
// never gets back.
func newUpstreamTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		// Let ALPN decide the upstream protocol instead of pinning http/1.1.
		// An origin that speaks h2 then carries every concurrent request for
		// that host on one connection, rather than one connection per request
		// in flight. ForceAttemptHTTP2 is required because [http.Transport]
		// stops negotiating h2 on its own as soon as a dial function is set.
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,

		DisableCompression:    true,
		ResponseHeaderTimeout: 30 * time.Second,

		// A proxy runs for a long time and talks to a lot of hosts, so the idle
		// pool needs a ceiling and an expiry. IdleConnTimeout is the one field
		// whose zero value is a leak: it keeps an idle connection alive for as
		// long as the process lives.
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
}
