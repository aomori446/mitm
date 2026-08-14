package mitm_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"bufio"
	"github.com/aomori446/mitm"
)

// This file is a measurement harness, not a correctness suite. Every benchmark
// drives a real proxy over loopback TCP with real TLS on both hops that the
// benchmark controls, so the numbers reflect syscalls and crypto actually
// performed rather than a simulation of them.

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

// ---------------------------------------------------------------- CA fixture

var caOnce struct {
	sync.Once
	mgr  *mitm.CertManager
	pool *x509.CertPool
	err  error
}

// testCA builds one CA for the whole process. Generating it per benchmark would
// charge every measurement for an unrelated key generation.
func testCA(tb testing.TB) (*mitm.CertManager, *x509.CertPool) {
	tb.Helper()
	caOnce.Do(func() {
		dir, err := os.MkdirTemp("", "mitm-bench-ca")
		if err != nil {
			caOnce.err = err
			return
		}
		certFile := filepath.Join(dir, "ca.crt")
		keyFile := filepath.Join(dir, "ca.key")
		if err := mitm.GenerateCA(certFile, keyFile); err != nil {
			caOnce.err = err
			return
		}
		mgr, err := mitm.NewCertManager(certFile, keyFile)
		if err != nil {
			caOnce.err = err
			return
		}
		pem, err := os.ReadFile(certFile)
		if err != nil {
			caOnce.err = err
			return
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			caOnce.err = fmt.Errorf("append CA to pool")
			return
		}
		caOnce.mgr, caOnce.pool = mgr, pool
	})
	if caOnce.err != nil {
		tb.Fatalf("test CA: %v", caOnce.err)
	}
	return caOnce.mgr, caOnce.pool
}

// ------------------------------------------------------------- proxy fixture

// startProxy runs a Handler on loopback and returns its address. The caller's
// middlewares are registered before the listener accepts anything.
func startProxy(tb testing.TB, setup func(*mitm.Handler)) string {
	tb.Helper()
	mgr, _ := testCA(tb)
	h := mitm.New(mgr)
	if setup != nil {
		setup(h)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := &http.Server{
		Handler:     h,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	go srv.Serve(ln)
	tb.Cleanup(func() {
		cancel()
		srv.Close()
	})
	return ln.Addr().String()
}

// syntheticResponder short-circuits every request with a response of the given
// body size and a realistic header count, so the benchmark exercises the
// client-facing half of the proxy without an upstream in the measurement.
func syntheticResponder(bodySize int) mitm.RequestFunc {
	body := strings.Repeat("x", bodySize)
	headers := http.Header{}
	for k, v := range map[string]string{
		"Content-Type":              "text/html; charset=utf-8",
		"Date":                      "Mon, 02 Jan 2006 15:04:05 GMT",
		"Server":                    "bench",
		"Cache-Control":             "max-age=0, private, must-revalidate",
		"Vary":                      "Accept-Encoding, Cookie",
		"X-Frame-Options":           "SAMEORIGIN",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Strict-Transport-Security": "max-age=31536000",
		"X-Request-Id":              "0123456789abcdef0123456789abcdef",
		"Etag":                      `W/"1a2b3c4d5e6f"`,
		"Last-Modified":             "Mon, 02 Jan 2006 15:04:05 GMT",
	} {
		headers.Set(k, v)
	}

	return func(_ context.Context, _ *http.Request) (*http.Request, *http.Response) {
		h := headers.Clone()
		return nil, &http.Response{
			StatusCode:    http.StatusOK,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        h,
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
		}
	}
}

// ------------------------------------------------------- TLS record counting

// recordCounter tallies TLS records and bytes in the server→client direction.
// Records are found by walking the record headers in the byte stream: read
// boundaries are unreliable because TCP coalesces, but record framing is exact,
// so the count is a direct measure of how many times the proxy called Write on
// the TLS connection. Bytes are the wire cost of those records, which is the
// part of the record overhead that a real network link has to carry and which a
// loopback timing measurement cannot show.
type recordCounter struct {
	net.Conn
	counting  atomic.Bool
	records   atomic.Int64
	wireBytes atomic.Int64
	remaining int
	hdr       [5]byte
	hdrLen    int
}

func (c *recordCounter) reset() {
	c.records.Store(0)
	c.wireBytes.Store(0)
}

func (c *recordCounter) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.counting.Load() {
		c.wireBytes.Add(int64(n))
		c.scan(p[:n])
	}
	return n, err
}

func (c *recordCounter) scan(data []byte) {
	for len(data) > 0 {
		if c.remaining > 0 {
			skip := min(c.remaining, len(data))
			c.remaining -= skip
			data = data[skip:]
			continue
		}
		need := 5 - c.hdrLen
		got := min(need, len(data))
		copy(c.hdr[c.hdrLen:], data[:got])
		c.hdrLen += got
		data = data[got:]
		if c.hdrLen == 5 {
			c.records.Add(1)
			c.remaining = int(c.hdr[3])<<8 | int(c.hdr[4])
			c.hdrLen = 0
		}
	}
}

// ------------------------------------------------------------ tunnel dialing

// dialTunnel opens a CONNECT tunnel through the proxy and completes the inner
// TLS handshake, returning the TLS connection and its record counter.
func dialTunnel(tb testing.TB, proxyAddr, host string, cfg *tls.Config) (*tls.Conn, *recordCounter) {
	tb.Helper()
	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		tb.Fatalf("dial proxy: %v", err)
	}

	target := host + ":443"
	if _, err := fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		raw.Close()
		tb.Fatalf("write CONNECT: %v", err)
	}

	// The proxy writes the 200 in a single Write and then stays silent until
	// it sees a ClientHello, so one Read cannot over-consume into TLS bytes.
	var buf [256]byte
	n, err := raw.Read(buf[:])
	if err != nil {
		raw.Close()
		tb.Fatalf("read CONNECT reply: %v", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 200") {
		raw.Close()
		tb.Fatalf("unexpected CONNECT reply: %q", buf[:n])
	}

	counter := &recordCounter{Conn: raw}
	counter.counting.Store(true)
	conn := tls.Client(counter, cfg)
	if err := conn.Handshake(); err != nil {
		conn.Close()
		tb.Fatalf("inner TLS handshake: %v", err)
	}
	return conn, counter
}

// exchange writes one request over the tunnel and fully drains the response.
func exchange(tb testing.TB, conn *tls.Conn, br *bufio.Reader, host string) *http.Response {
	tb.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://"+host+"/index.html", nil)
	if err != nil {
		tb.Fatalf("new request: %v", err)
	}
	req.Header.Set("User-Agent", "mitm-bench/1")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if err := req.Write(conn); err != nil {
		tb.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		tb.Fatalf("read response: %v", err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		tb.Fatalf("drain body: %v", err)
	}
	resp.Body.Close()
	return resp
}

// -------------------------------------------------------------- benchmark: A

// BenchmarkTunnelHandshake measures the cost of establishing one intercepted
// tunnel: CONNECT, inner TLS handshake, one request/response, close. The client
// keeps a session cache across iterations, so the reported resume rate shows
// whether the proxy lets clients skip the full handshake.
func BenchmarkTunnelHandshake(b *testing.B) {
	const host = "bench.example.com"
	_, pool := testCA(b)
	addr := startProxy(b, func(h *mitm.Handler) {
		h.UseRequest(syntheticResponder(1024))
	})

	cfg := &tls.Config{
		RootCAs:            pool,
		ServerName:         host,
		ClientSessionCache: tls.NewLRUClientSessionCache(64),
	}

	var resumed, records, wire int64
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		conn, counter := dialTunnel(b, addr, host, cfg)
		if conn.ConnectionState().DidResume {
			resumed++
		}
		br := bufio.NewReader(conn)
		exchange(b, conn, br, host)
		conn.Close()
		records += counter.records.Load()
		wire += counter.wireBytes.Load()
	}
	b.StopTimer()

	n := float64(b.N)
	b.ReportMetric(float64(resumed)/n*100, "%resumed")
	b.ReportMetric(float64(records)/n, "records/op")
	b.ReportMetric(float64(wire)/n, "wireB/op")
}

// -------------------------------------------------------------- benchmark: B

// BenchmarkTunnelRequest measures steady-state request/response over an already
// established tunnel, and counts the TLS records the proxy emits per response.
// Records are a proxy for write syscalls: each Write on a tls.Conn produces one
// record with its own header, MAC and syscall.
func BenchmarkTunnelRequest(b *testing.B) {
	const host = "bench.example.com"
	_, pool := testCA(b)

	for _, size := range []int{0, 1 << 10, 64 << 10} {
		b.Run(fmt.Sprintf("body=%s", byteLabel(size)), func(b *testing.B) {
			addr := startProxy(b, func(h *mitm.Handler) {
				h.UseRequest(syntheticResponder(size))
			})
			cfg := &tls.Config{RootCAs: pool, ServerName: host}
			conn, counter := dialTunnel(b, addr, host, cfg)
			defer conn.Close()
			br := bufio.NewReader(conn)

			// Warm the tunnel so the first iteration is not charged for
			// post-handshake tickets still in flight.
			exchange(b, conn, br, host)

			counter.reset()
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				exchange(b, conn, br, host)
			}
			b.StopTimer()
			counter.counting.Store(false)

			b.ReportMetric(float64(counter.records.Load())/float64(b.N), "records/op")
			b.ReportMetric(float64(counter.wireBytes.Load())/float64(b.N), "wireB/op")
		})
	}
}

func byteLabel(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%dMiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%dKiB", n>>10)
	default:
		return fmt.Sprintf("%dB", n)
	}
}
