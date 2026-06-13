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
	"sync"
	"time"
	
	"golang.org/x/sync/singleflight"
	
	"github.com/aomori446/mitm/cert"
	"github.com/aomori446/mitm/interceptor"
)

// Handler is an [http.Handler] that acts as a forward proxy and performs
// TLS interception (MITM) on CONNECT tunnels when a [cert.Manager] is provided.
type Handler struct {
	certMgr *cert.Manager // nil means plain TCP relay (no MITM)
	
	httpProxy  *httputil.ReverseProxy
	onRequest  []interceptor.OnRequestFunc
	onResponse []interceptor.OnResponseFunc
	
	transports     sync.Map
	transportGroup singleflight.Group
}

// New creates a Handler. Providing a non-nil certMgr enables TLS interception;
// passing nil falls back to a transparent TCP relay for CONNECT tunnels.
//
// The caller should set [http.Server.BaseContext] to a context that is
// canceled on shutdown so that long-lived CONNECT tunnels are torn down
// promptly when the server stops.
func New(certMgr *cert.Manager) *Handler {
	h := &Handler{
		certMgr: certMgr,
	}
	h.httpProxy = &httputil.ReverseProxy{
		Rewrite: func(preq *httputil.ProxyRequest) {
			preq.Out.URL.Scheme = "http"
			preq.Out.URL.Host = preq.In.Host
		},
		ModifyResponse: func(resp *http.Response) error {
			newResp, err := h.runResponseHooks(resp.Request.Context(), resp)
			if err != nil {
				return err
			}
			*resp = *newResp
			return nil
		},
	}
	return h
}

// OnRequest registers fn as a request interceptor hook.
// Hooks are called in registration order before each upstream request.
func (h *Handler) OnRequest(fn interceptor.OnRequestFunc) {
	h.onRequest = append(h.onRequest, fn)
}

// OnResponse registers fn as a response interceptor hook.
// Hooks are called in registration order after each upstream response.
func (h *Handler) OnResponse(fn interceptor.OnResponseFunc) {
	h.onResponse = append(h.onResponse, fn)
}

// ServeHTTP implements [http.Handler]. CONNECT requests initiate a tunnel;
// all other methods run OnRequest hooks then are proxied via the reverse proxy.
func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		h.handleCONNECT(req.Context(), w, req.Host)
		return
	}
	
	newReq, newResp := h.runRequestHooks(req.Context(), req)
	if newResp != nil {
		defer newResp.Body.Close()
		for k, v := range newResp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(newResp.StatusCode)
		io.Copy(w, newResp.Body)
		return
	}
	
	h.httpProxy.ServeHTTP(w, newReq)
}

func (h *Handler) handleCONNECT(ctx context.Context, w http.ResponseWriter, dstAddr string) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Proxy error: hijacking not supported", http.StatusInternalServerError)
		slog.Error("Hijacking not supported by ResponseWriter")
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
		h.handleCONNECTWithoutMITM(ctx, downstream, dstAddr)
		return
	}
	
	h.handleCONNECTWithMITM(ctx, downstream, dstAddr)
}

func (h *Handler) handleCONNECTWithoutMITM(ctx context.Context, downstream net.Conn, dstAddr string) {
	upstream, err := net.Dial("tcp", dstAddr)
	if err != nil {
		slog.Error("Dial failed", "error", err)
		writeErrorToConn(downstream, http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	
	if err = TCPRelay(ctx, downstream, upstream); err != nil {
		slog.Error("Relay failed", "error", err)
	}
}

func (h *Handler) handleCONNECTWithMITM(ctx context.Context, downstream net.Conn, dstAddr string) {
	tlsDownstream := tls.Server(downstream, h.certMgr.TLSConfig())
	if err := tlsDownstream.Handshake(); err != nil {
		slog.Error("TLS handshake with client failed", "addr", downstream.RemoteAddr().String(), "error", err)
		writeErrorToConn(downstream, http.StatusBadGateway)
		return
	}
	defer tlsDownstream.Close()
	
	hostname, _, err := net.SplitHostPort(dstAddr)
	if err != nil {
		slog.Error("Failed to parse dstAddr", "addr", dstAddr, "error", err)
		return
	}
	
	// Unblock ReadRequest when ctx is cancelled (e.g. server shutdown).
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			tlsDownstream.SetDeadline(time.Now())
		case <-done:
		}
	}()
	
	transport := h.transportFor(dstAddr, hostname)
	
	br := bufio.NewReader(tlsDownstream)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			break
		}
		
		req.URL.Scheme = "https"
		req.URL.Host = dstAddr
		req.RequestURI = ""
		req = req.WithContext(ctx)
		
		newReq, newResp := h.runRequestHooks(ctx, req)
		if newResp != nil {
			newResp.Write(tlsDownstream)
			newResp.Body.Close()
			continue
		}
		
		resp, err := transport.RoundTrip(newReq)
		if err != nil {
			slog.Error("MITM round trip failed", "error", err)
			errResp := interceptor.Response(http.StatusBadGateway, "", http.NoBody)
			errResp.Write(tlsDownstream)
			break
		}
		
		resp, err = h.runResponseHooks(ctx, resp)
		if err != nil {
			slog.Error("response hook aborted the chain", "error", err)
			resp.Body.Close()
			errResp := interceptor.Response(http.StatusBadGateway, "", http.NoBody)
			errResp.Write(tlsDownstream)
			break
		}
		
		err = resp.Write(tlsDownstream)
		resp.Body.Close()
		if err != nil {
			break
		}
	}
}

// transportFor returns the shared [http.Transport] for dstAddr, creating one if needed.
// Connections are reused across CONNECT sessions to the same host.
func (h *Handler) transportFor(dstAddr, hostname string) *http.Transport {
	if v, ok := h.transports.Load(dstAddr); ok {
		return v.(*http.Transport)
	}
	v, _, _ := h.transportGroup.Do(dstAddr, func() (any, error) {
		t := &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := net.Dial("tcp", dstAddr)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(conn, &tls.Config{
					ServerName: hostname,
					NextProtos: []string{"http/1.1"},
				})
				if err = tlsConn.Handshake(); err != nil {
					tlsConn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
			DisableCompression:    true,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
		}
		actual, _ := h.transports.LoadOrStore(dstAddr, t)
		return actual, nil
	})
	return v.(*http.Transport)
}

func (h *Handler) runRequestHooks(ctx context.Context, req *http.Request) (*http.Request, *http.Response) {
	for _, fn := range h.onRequest {
		newReq, newResp := fn(ctx, req)
		if newResp != nil {
			return nil, newResp
		}
		req = newReq
	}
	return req, nil
}

func (h *Handler) runResponseHooks(ctx context.Context, resp *http.Response) (*http.Response, error) {
	for _, fn := range h.onResponse {
		newResp, err := fn(ctx, resp)
		if err != nil {
			return newResp, err
		}
		resp = newResp
	}
	return resp, nil
}
