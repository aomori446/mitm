package mitm

import (
	"context"
	"io"
	"net/http"
	"net/http/httputil"
	"sync"
)

// OnRequestFunc is called before a request is forwarded to the upstream server.
type OnRequestFunc func(ctx context.Context, req *http.Request) (*http.Request, *http.Response)

// OnResponseFunc is called after the upstream response is received and before
// it is written back to the client. The original request is available via resp.Request.
type OnResponseFunc func(ctx context.Context, resp *http.Response) (*http.Response, error)

// Response constructs a standard *http.Response helper.
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

// Handler is an [http.Handler] that acts as a forward proxy and performs
// TLS interception (MITM) on CONNECT tunnels when a [CertManager] is provided.
type Handler struct {
	mu sync.RWMutex
	
	certMgr *CertManager // nil means plain TCP relay (no MITM)
	
	httpProxy *httputil.ReverseProxy
	
	onRequest  []OnRequestFunc
	onResponse []OnResponseFunc
	
	transports sync.Map // map[host string]*http.Transport
}

// New creates a Handler. Providing a non-nil certMgr enables TLS interception;
// passing nil falls back to a transparent TCP relay for CONNECT tunnels.
//
// The caller should set [http.Server.BaseContext] to a context that is
// canceled on shutdown so that long-lived CONNECT tunnels are torn down
// promptly when the server stops.
func New(certMgr *CertManager) *Handler {
	h := &Handler{
		certMgr: certMgr,
	}
	h.httpProxy = &httputil.ReverseProxy{
		Rewrite:   func(*httputil.ProxyRequest) {},
		Transport: &hookTransport{base: http.DefaultTransport, handler: h},
	}
	return h
}

// OnRequest registers fn as a request interceptor hook.
// Hooks are called in registration order before each upstream request.
func (h *Handler) OnRequest(fn OnRequestFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onRequest = append(h.onRequest, fn)
}

// OnResponse registers fn as a response interceptor hook.
// Hooks are called in registration order after each upstream response.
func (h *Handler) OnResponse(fn OnResponseFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onResponse = append(h.onResponse, fn)
}

// ServeHTTP implements [http.Handler]. CONNECT requests initiate a tunnel;
// all other methods run OnRequest hooks then are proxied via the reverse proxy.
func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		h.handleCONNECT(w, req)
		return
	}
	
	h.httpProxy.ServeHTTP(w, req)
}

func (h *Handler) runRequestHooks(req *http.Request) (*http.Request, *http.Response) {
	h.mu.RLock()
	hooks := h.onRequest
	h.mu.RUnlock()
	
	for _, fn := range hooks {
		newReq, newResp := fn(req.Context(), req)
		if newResp != nil {
			return nil, newResp
		}
		req = newReq
	}
	return req, nil
}

func (h *Handler) runResponseHooks(resp *http.Response) (*http.Response, error) {
	ctx := context.Background()
	if resp.Request != nil {
		ctx = resp.Request.Context()
	}
	
	h.mu.RLock()
	hooks := h.onResponse
	h.mu.RUnlock()
	
	for _, fn := range hooks {
		newResp, err := fn(ctx, resp)
		if err != nil {
			return newResp, err
		}
		resp = newResp
	}
	return resp, nil
}
