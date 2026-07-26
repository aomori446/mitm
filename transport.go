package mitm

import (
	"crypto/tls"
	"net/http"
	"time"
)

type hookTransport struct {
	base    http.RoundTripper
	handler *Handler
}

func (t *hookTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	req, resp = t.handler.runRequestHooks(req)
	if resp != nil {
		return resp, nil
	}
	
	resp, err = t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	
	return t.handler.runResponseHooks(resp)
}

func (h *Handler) transportFor(host string) *http.Transport {
	if v, ok := h.transports.Load(host); ok {
		return v.(*http.Transport)
	}

	t := &http.Transport{
		DialTLSContext: (&tls.Dialer{
			Config: &tls.Config{
				NextProtos: []string{"http/1.1"},
			},
		}).DialContext,
		DisableCompression:    true,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConnsPerHost:   10,
	}

	actual, _ := h.transports.LoadOrStore(host, t)
	return actual.(*http.Transport)
}
