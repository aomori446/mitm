package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	
	"github.com/aomori446/mitm/cert"
	"github.com/aomori446/mitm/interceptor"
	"golang.org/x/sync/errgroup"
)

// Handler is an [http.Handler] that acts as a forward proxy and performs
// TLS interception (MITM) on CONNECT tunnels when a [cert.Manager] is provided.
type Handler struct {
	ctx context.Context
	
	certMgr *cert.Manager // nil means plain TCP relay (no MITM)
	
	httpProxy  *httputil.ReverseProxy
	onRequest  []interceptor.OnRequestFunc
	onResponse []interceptor.OnResponseFunc
}

// New creates a Handler. Providing a non-nil certMgr enables TLS interception;
// passing nil falls back to a transparent TCP relay for CONNECT tunnels.
func New(ctx context.Context, certMgr *cert.Manager) *Handler {
	return &Handler{
		ctx:     ctx,
		certMgr: certMgr,
		httpProxy: &httputil.ReverseProxy{
			Rewrite: func(preq *httputil.ProxyRequest) {
				preq.Out.URL.Scheme = "http"
				preq.Out.URL.Host = preq.In.Host
			},
		},
	}
}

// HandleRequest registers fn as a request interceptor hook.
// Hooks are called in registration order before each upstream request.
func (h *Handler) HandleRequest(fn interceptor.OnRequestFunc) {
	h.onRequest = append(h.onRequest, fn)
}

// HandleResponse registers fn as a response interceptor hook.
// Hooks are called in registration order after each upstream response.
func (h *Handler) HandleResponse(fn interceptor.OnResponseFunc) {
	h.onResponse = append(h.onResponse, fn)
}

// ServeHTTP implements [http.Handler]. CONNECT requests initiate a tunnel;
// all other methods are proxied directly via the reverse proxy.
func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		h.handleCONNECT(w, req.Host)
	} else {
		h.httpProxy.ServeHTTP(w, req)
	}
}

func (h *Handler) handleCONNECT(w http.ResponseWriter, dstAddr string) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Proxy error: hijacking not supported", http.StatusInternalServerError)
		return
	}
	downstream, _, err := hijacker.Hijack()
	if err != nil {
		slog.Error("Hijack failed", "error", err)
		return
	}
	defer downstream.Close()
	
	if _, err = downstream.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		slog.Error("Send 200 Established failed", "error", err)
		return
	}
	
	if h.certMgr == nil {
		h.handleCONNECTWithoutMITM(downstream, dstAddr)
		return
	}
	
	h.handleCONNECTWithMITM(downstream, dstAddr)
}

func (h *Handler) handleCONNECTWithoutMITM(downstream net.Conn, dstAddr string) {
	upstream, err := net.Dial("tcp", dstAddr)
	if err != nil {
		slog.Error("Dial failed", "error", err)
		return
	}
	defer upstream.Close()
	
	if err = TCPRelay(h.ctx, downstream, upstream); err != nil {
		slog.Error("Relay failed", "error", err)
	}
}

func (h *Handler) handleCONNECTWithMITM(downstream net.Conn, dstAddr string) {
	tlsDownstream := tls.Server(downstream, h.certMgr.TLSConfig())
	if err := tlsDownstream.Handshake(); err != nil {
		slog.Error("TLS handshake with client failed", "addr", downstream.RemoteAddr().String(), "error", err)
		return
	}
	defer tlsDownstream.Close()
	
	br := bufio.NewReader(tlsDownstream)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			break
		}
		
		// OnRequest hooks
		if resp := h.runRequestHooks(req); resp != nil {
			_ = resp.Write(tlsDownstream)
			continue
		}
		
		resp, err := h.mitmRoundTrip(req, dstAddr)
		if err != nil {
			slog.Error("MITM round trip failed", "error", err)
			errResp := interceptor.Response(http.StatusBadGateway, "", http.NoBody)
			errResp.Write(tlsDownstream)
			break
		}
		
		// OnResponse hooks
		if hookResp := h.runResponseHooks(resp); hookResp != nil {
			resp = hookResp
		}
		
		err = resp.Write(tlsDownstream)
		resp.Body.Close()
		if err != nil {
			break
		}
	}
}

func (h *Handler) mitmRoundTrip(req *http.Request, dstAddr string) (*http.Response, error) {
	upstream, err := net.Dial("tcp", dstAddr)
	if err != nil {
		return nil, err
	}
	
	hostname, _, err := net.SplitHostPort(dstAddr)
	if err != nil {
		return nil, err
	}
	
	tlsUpstream := tls.Client(upstream, &tls.Config{
		ServerName: hostname,
	})
	
	if err = tlsUpstream.Handshake(); err != nil {
		tlsUpstream.Close()
		return nil, err
	}
	
	if err = req.Write(tlsUpstream); err != nil {
		tlsUpstream.Close()
		return nil, err
	}
	
	resp, err := http.ReadResponse(bufio.NewReader(tlsUpstream), req)
	if err != nil {
		tlsUpstream.Close()
		return nil, err
	}
	
	resp.Body = struct {
		io.Reader
		io.Closer
	}{
		Reader: resp.Body,
		Closer: tlsUpstream,
	}
	return resp, nil
}

// runRequestHooks runs OnRequest hooks in registration order.
// Returns the first non-nil response to short-circuit the request,
// or nil if all hooks passed through.
func (h *Handler) runRequestHooks(req *http.Request) *http.Response {
	for _, fn := range h.onRequest {
		if resp := fn(req); resp != nil {
			return resp
		}
	}
	return nil
}

func (h *Handler) runResponseHooks(resp *http.Response) *http.Response {
	for _, fn := range h.onResponse {
		if resp = fn(resp); resp != nil {
			return resp
		}
	}
	return nil
}

type halfCloser interface {
	CloseWrite() error
}

// TCPRelay bidirectionally copies data between client and server until either
// side closes the connection or ctx is cancelled.
func TCPRelay(ctx context.Context, client, server net.Conn) error {
	var errGroup errgroup.Group
	
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	
	halfClosed := make(chan struct{}, 2)
	defer close(halfClosed)
	go func() {
		<-halfClosed
		<-halfClosed
		cancel()
	}()
	
	errGroup.Go(func() error {
		<-ctx.Done()
		client.Close()
		server.Close()
		return ctx.Err()
	})
	
	// server → client
	errGroup.Go(func() error {
		_, err := io.Copy(client, server)
		if conn, ok := client.(halfCloser); ok {
			conn.CloseWrite()
		} else {
			client.Close()
		}
		halfClosed <- struct{}{}
		return err
	})
	
	// client → server
	errGroup.Go(func() error {
		_, err := io.Copy(server, client)
		if conn, ok := server.(halfCloser); ok {
			conn.CloseWrite()
		} else {
			server.Close()
		}
		halfClosed <- struct{}{}
		return err
	})
	
	return errGroup.Wait()
}
