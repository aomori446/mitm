package mitm

import (
	"crypto/tls"
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
		DialTLSContext: (&tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 10 * time.Second},
			Config: &tls.Config{
				NextProtos: []string{"http/1.1"},
			},
		}).DialContext,
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
