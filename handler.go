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

	"github.com/aomori446/mitm/cert"
	"github.com/aomori446/mitm/interceptor"
)

// Handler is an [http.Handler] that acts as a forward proxy and performs
// TLS interception (MITM) on CONNECT tunnels when a [cert.Manager] is provided.
type Handler struct {
	ctx context.Context
	
	certMgr *cert.Manager // nil means plain TCP relay (no MITM)
	
	httpProxy  *httputil.ReverseProxy
	onRequest  []interceptor.OnRequestFunc
	onResponse []interceptor.OnResponseFunc
	
	// transports caches one *http.Transport per dstAddr so that upstream
	// TLS connections are reused across CONNECT sessions to the same host.
	transports sync.Map
}

// New creates a Handler. Providing a non-nil certMgr enables TLS interception;
// passing nil falls back to a transparent TCP relay for CONNECT tunnels.
func New(ctx context.Context, certMgr *cert.Manager) *Handler {
	h := &Handler{
		ctx:     ctx,
		certMgr: certMgr,
	}
	h.httpProxy = &httputil.ReverseProxy{
		Rewrite: func(preq *httputil.ProxyRequest) {
			preq.Out.URL.Scheme = "http"
			preq.Out.URL.Host = preq.In.Host
		},
		// ModifyResponse runs OnResponse hooks for plain-HTTP traffic.
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
		h.handleCONNECT(w, req.Host)
		return
	}
	
	// OnRequest hooks — a non-nil newResp short-circuits the upstream request.
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

func (h *Handler) handleCONNECT(w http.ResponseWriter, dstAddr string) {
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
		h.handleCONNECTWithoutMITM(downstream, dstAddr)
		return
	}
	
	h.handleCONNECTWithMITM(downstream, dstAddr)
}

func (h *Handler) handleCONNECTWithoutMITM(downstream net.Conn, dstAddr string) {
	upstream, err := net.Dial("tcp", dstAddr)
	if err != nil {
		slog.Error("Dial failed", "error", err)
		writeErrorToConn(downstream, http.StatusBadGateway)
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
		writeErrorToConn(downstream, http.StatusBadGateway)
		return
	}
	defer tlsDownstream.Close()
	
	hostname, _, err := net.SplitHostPort(dstAddr)
	if err != nil {
		slog.Error("Failed to parse dstAddr", "addr", dstAddr, "error", err)
		return
	}
	
	transport := h.transportFor(dstAddr, hostname)
	
	br := bufio.NewReader(tlsDownstream)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			break
		}
		
		// http.Transport.RoundTrip requires a fully-qualified URL and empty RequestURI.
		req.URL.Scheme = "https"
		req.URL.Host = dstAddr
		req.RequestURI = ""
		
		// OnRequest hooks
		newReq, newResp := h.runRequestHooks(h.ctx, req)
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
		
		// OnResponse hooks
		resp, err = h.runResponseHooks(h.ctx, resp)
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
func (h *Handler) transportFor(dstAddr, hostname string) *http.Transport {
	v, _ := h.transports.LoadOrStore(dstAddr, &http.Transport{
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
		// Disable automatic gzip so the client controls content negotiation.
		DisableCompression: true,
		// Avoid hanging forever if the upstream is slow to respond.
		ResponseHeaderTimeout: 30 * time.Second,
		// Allow more idle connections per host for sessions with many parallel resources.
		MaxIdleConnsPerHost: 10,
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


