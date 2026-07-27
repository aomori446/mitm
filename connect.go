package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"time"
)

func (h *Handler) handleCONNECT(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	host := req.Host
	
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
		h.handleCONNECTWithoutMITM(ctx, downstream, host)
		return
	}
	
	h.handleCONNECTWithMITM(ctx, downstream, host)
}

func (h *Handler) handleCONNECTWithoutMITM(ctx context.Context, downstream net.Conn, host string) {
	upstream, err := new(net.Dialer).DialContext(ctx, "tcp", host)
	if err != nil {
		slog.Error("Dial failed", "error", err, "dstAddr", host)
		writeErrorToConn(downstream, http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	
	if err = tcpRelay(ctx, downstream, upstream); err != nil {
		slog.Error("Relay failed", "error", err)
	}
}

func (h *Handler) handleCONNECTWithMITM(ctx context.Context, downstream net.Conn, host string) {
	tlsDownstream := tls.Server(downstream, h.certMgr.TLSConfig())
	if err := tlsDownstream.Handshake(); err != nil {
		slog.Error("TLS handshake with client failed", "addr", downstream.RemoteAddr().String(), "error", err)
		writeErrorToConn(downstream, http.StatusBadGateway)
		return
	}
	defer tlsDownstream.Close()
	
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			tlsDownstream.SetReadDeadline(time.Now())
		case <-done:
		}
	}()
	
	mitmTransport := &middlewareTransport{
		base:    h.transportFor(host),
		handler: h,
	}
	
	br := bufio.NewReader(tlsDownstream)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			break
		}
		
		req.URL.Scheme = "https"
		req.URL.Host = host
		req = req.WithContext(ctx)
		
		resp, err := mitmTransport.RoundTrip(req)
		if err != nil {
			slog.Error("MITM round trip failed", "error", err)
			errResp := Response(http.StatusBadGateway, "", http.NoBody)
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
