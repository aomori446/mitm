package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"golang.org/x/net/http2"
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

	certMgr := h.CertManager()
	if certMgr == nil {
		h.handleCONNECTWithoutMITM(ctx, downstream, host)
		return
	}

	h.handleCONNECTWithMITM(ctx, downstream, host, certMgr)
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

func (h *Handler) handleCONNECTWithMITM(ctx context.Context, downstream net.Conn, host string, certMgr *CertManager) {
	start := time.Now()
	tlsDownstream := tls.Server(downstream, certMgr.TLSConfig())
	if err := tlsDownstream.Handshake(); err != nil {
		if !isEOFOrClosed(err) {
			slog.Error("TLS handshake with client failed", "addr", downstream.RemoteAddr().String(), "error", err)
			h.notifyHandshakeError(ctx, host, err, time.Since(start))
		}
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

	if tlsDownstream.ConnectionState().NegotiatedProtocol == "h2" {
		h.serveHTTP2(ctx, tlsDownstream, host)
		return
	}

	mitmTransport := &middlewareTransport{
		base:    h.upstream,
		handler: h,
	}

	br := bufio.NewReader(tlsDownstream)

	// Buffer the write side. [http.Response.Write] emits the status line and
	// each header field as several small Writes, and every Write on a
	// [tls.Conn] becomes its own TLS record, with its own header, MAC and
	// syscall. Unbuffered, a plain response with a dozen headers costs about
	// fifty records and close to three times its own size on the wire. Bodies
	// larger than the buffer still pass straight through, so this does not
	// break up the big copies.
	bw := bufio.NewWriter(tlsDownstream)
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
			errResp.Write(bw)
			bw.Flush()
			break
		}

		err = resp.Write(bw)
		resp.Body.Close()
		if err == nil {
			err = bw.Flush()
		}
		if err != nil {
			break
		}

		// A response with no known length is delimited by the connection
		// closing, and [http.Response.Write] says so with "Connection: close".
		// Keeping the tunnel open after that leaves the client waiting for an
		// EOF that never arrives — it burns one of the client's few connections
		// per origin, and once they are all stuck the origin goes unreachable.
		// Synthetic responses from request middlewares hit this every time,
		// since they rarely carry a Content-Length.
		if resp.Close || req.Close {
			break
		}
	}
}

func isEOFOrClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "EOF") ||
		strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "connection reset by peer")
}

// serveHTTP2 serves an intercepted tunnel whose client negotiated h2.
//
// The HTTP/1.1 loop cannot be reused: h2 carries concurrent streams over one
// connection, identified by stream id rather than by order, so requests are no
// longer answered one at a time in the order they arrived. [http2.Server] owns
// that multiplexing, along with header compression and flow control, and calls
// the handler once per stream.
//
// The handler is a [httputil.ReverseProxy] rather than a hand-written copy loop
// so that hop-by-hop headers, streaming, trailers and informational responses
// keep the behaviour net/http already defines. Rewrite only points the request
// at the intercepted origin: it deliberately does not add X-Forwarded-For,
// because an interception proxy is supposed to be invisible to the origin.
func (h *Handler) serveHTTP2(ctx context.Context, conn *tls.Conn, host string) {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = host
		},
		Transport: &middlewareTransport{base: h.upstream, handler: h},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			slog.Error("MITM round trip failed", "error", err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}

	// ServeConn returns when the connection ends. Cancellation is already
	// wired: the caller's watcher sets a read deadline on ctx.Done, which
	// fails the next frame read and unwinds this.
	(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{
		Context: ctx,
		Handler: proxy,
	})
}
