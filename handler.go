package mitm

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"
)

// RequestFunc is called before a request is forwarded to the upstream server.
type RequestFunc func(ctx context.Context, req *http.Request) (*http.Request, *http.Response)

// ResponseFunc is called after the upstream response is received and before
// it is written back to the client. The original request is available via resp.Request.
type ResponseFunc func(ctx context.Context, resp *http.Response) (*http.Response, error)

// HandshakeErrorFunc is called when a client TLS handshake fails during CONNECT tunnel interception.
type HandshakeErrorFunc func(ctx context.Context, host string, err error, duration time.Duration)

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
	
	requestMiddlewares        []RequestFunc
	responseMiddlewares       []ResponseFunc
	handshakeErrorMiddlewares []HandshakeErrorFunc

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
		Transport: &middlewareTransport{base: http.DefaultTransport, handler: h},
	}
	return h
}

// CertManager returns the current CertManager in a thread-safe manner.
func (h *Handler) CertManager() *CertManager {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.certMgr
}

// SetCertManager replaces the active CertManager in a thread-safe manner.
func (h *Handler) SetCertManager(certMgr *CertManager) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.certMgr = certMgr
}

// UseRequest registers fn as a request middleware.
// Middlewares are called in registration order before each upstream request.
func (h *Handler) UseRequest(fn RequestFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.requestMiddlewares = append(h.requestMiddlewares, fn)
}

// UseResponse registers fn as a response middleware.
// Middlewares are called in registration order after each upstream response.
func (h *Handler) UseResponse(fn ResponseFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.responseMiddlewares = append(h.responseMiddlewares, fn)
}

// UseHandshakeError registers fn as a handshake error middleware callback.
func (h *Handler) UseHandshakeError(fn HandshakeErrorFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handshakeErrorMiddlewares = append(h.handshakeErrorMiddlewares, fn)
}

func (h *Handler) notifyHandshakeError(ctx context.Context, host string, err error, duration time.Duration) {
	h.mu.RLock()
	mws := h.handshakeErrorMiddlewares
	h.mu.RUnlock()

	for _, fn := range mws {
		fn(ctx, host, err, duration)
	}
}

// ServeHTTP implements [http.Handler]. CONNECT requests initiate a tunnel;
// all other methods run request middlewares then are proxied via the reverse proxy.
func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		h.handleCONNECT(w, req)
		return
	}
	
	h.httpProxy.ServeHTTP(w, req)
}

// ListenAndServe starts an HTTP proxy server on the given network address.
// It uses ctx as the BaseContext for all incoming connections and shuts down
// gracefully when ctx is canceled.
func (h *Handler) ListenAndServe(ctx context.Context, addr string) error {
	server := &http.Server{
		Addr:        addr,
		Handler:     h,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	err := server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (h *Handler) runRequestMiddlewares(req *http.Request) (*http.Request, *http.Response) {
	h.mu.RLock()
	mws := h.requestMiddlewares
	h.mu.RUnlock()
	
	for _, fn := range mws {
		newReq, newResp := fn(req.Context(), req)
		if newResp != nil {
			return nil, newResp
		}
		req = newReq
	}
	return req, nil
}

func (h *Handler) runResponseMiddlewares(resp *http.Response) (*http.Response, error) {
	ctx := context.Background()
	if resp.Request != nil {
		ctx = resp.Request.Context()
	}
	
	h.mu.RLock()
	mws := h.responseMiddlewares
	h.mu.RUnlock()
	
	for _, fn := range mws {
		newResp, err := fn(ctx, resp)
		if err != nil {
			return newResp, err
		}
		resp = newResp
	}
	return resp, nil
}
