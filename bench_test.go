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
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bufio"

	"github.com/aomori446/mitm"
	"golang.org/x/net/http2"
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
func syntheticResponder(bodySize int, originLatency time.Duration) mitm.RequestFunc {
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
		// Stand in for the origin's round trip. Without it every response is
		// instant, and a benchmark of concurrency measures nothing: whether
		// requests overlap only matters when they take time.
		if originLatency > 0 {
			time.Sleep(originLatency)
		}
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

// openTunnel opens a CONNECT tunnel through the proxy and completes the inner
// TLS handshake, returning the TLS connection and its record counter.
func openTunnel(proxyAddr, host string, cfg *tls.Config) (*tls.Conn, *recordCounter, error) {
	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial proxy: %w", err)
	}

	target := host + ":443"
	if _, err := fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		raw.Close()
		return nil, nil, fmt.Errorf("write CONNECT: %w", err)
	}

	// The proxy writes the 200 in a single Write and then stays silent until
	// it sees a ClientHello, so one Read cannot over-consume into TLS bytes.
	var buf [256]byte
	n, err := raw.Read(buf[:])
	if err != nil {
		raw.Close()
		return nil, nil, fmt.Errorf("read CONNECT reply: %w", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 200") {
		raw.Close()
		return nil, nil, fmt.Errorf("unexpected CONNECT reply: %q", buf[:n])
	}

	counter := &recordCounter{Conn: raw}
	counter.counting.Store(true)
	conn := tls.Client(counter, cfg)
	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("inner TLS handshake: %w", err)
	}
	return conn, counter, nil
}

func dialTunnel(tb testing.TB, proxyAddr, host string, cfg *tls.Config) (*tls.Conn, *recordCounter) {
	tb.Helper()
	conn, counter, err := openTunnel(proxyAddr, host, cfg)
	if err != nil {
		tb.Fatal(err)
	}
	return conn, counter
}

// newHTTP2Client returns a client whose single h2 connection runs inside a
// CONNECT tunnel, plus the record counter for that tunnel.
func newHTTP2Client(tb testing.TB, proxyAddr, host string, pool *x509.CertPool) (*http.Client, func() *recordCounter) {
	tb.Helper()
	var mu sync.Mutex
	var counters []*recordCounter

	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: host,
			NextProtos: []string{"h2"},
		},
		DialTLSContext: func(_ context.Context, _, _ string, cfg *tls.Config) (net.Conn, error) {
			conn, counter, err := openTunnel(proxyAddr, host, cfg)
			if err != nil {
				return nil, err
			}
			if conn.ConnectionState().NegotiatedProtocol != "h2" {
				conn.Close()
				return nil, fmt.Errorf("proxy did not negotiate h2, got %q",
					conn.ConnectionState().NegotiatedProtocol)
			}
			mu.Lock()
			counters = append(counters, counter)
			mu.Unlock()
			return conn, nil
		},
	}
	tb.Cleanup(tr.CloseIdleConnections)

	sum := func() *recordCounter {
		mu.Lock()
		defer mu.Unlock()
		if len(counters) != 1 {
			tb.Fatalf("expected exactly one h2 connection, got %d", len(counters))
		}
		return counters[0]
	}
	return &http.Client{Transport: tr}, sum
}

// getOnce issues one request through client and drains the response.
func getOnce(tb testing.TB, client *http.Client, host string) {
	tb.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://"+host+"/index.html", nil)
	if err != nil {
		tb.Fatalf("new request: %v", err)
	}
	req.Header.Set("User-Agent", "mitm-bench/1")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := client.Do(req)
	if err != nil {
		tb.Fatalf("h2 request: %v", err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		tb.Fatalf("drain body: %v", err)
	}
	resp.Body.Close()
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
		h.UseRequest(syntheticResponder(1024, 0))
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
				h.UseRequest(syntheticResponder(size, 0))
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

// -------------------------------------------------------------- benchmark: C

// BenchmarkTunnelRequestHTTP2 is BenchmarkTunnelRequest over a client that
// negotiated h2, so the two can be read side by side from one run. The headers
// are identical; what differs is HPACK, which sends a repeated header as an
// index into a table rather than as text.
func BenchmarkTunnelRequestHTTP2(b *testing.B) {
	const host = "bench.example.com"
	_, pool := testCA(b)

	for _, size := range []int{0, 1 << 10, 64 << 10} {
		b.Run(fmt.Sprintf("body=%s", byteLabel(size)), func(b *testing.B) {
			addr := startProxy(b, func(h *mitm.Handler) {
				h.UseRequest(syntheticResponder(size, 0))
			})
			client, counter := newHTTP2Client(b, addr, host, pool)

			// Warm the connection: the first request pays for the h2 preface
			// and seeds the HPACK table that later requests index into.
			getOnce(b, client, host)

			c := counter()
			c.reset()
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				getOnce(b, client, host)
			}
			b.StopTimer()

			b.ReportMetric(float64(c.records.Load())/float64(b.N), "records/op")
			b.ReportMetric(float64(c.wireBytes.Load())/float64(b.N), "wireB/op")
		})
	}
}

// -------------------------------------------------------------- benchmark: D

// BenchmarkPageLoad models what a browser actually does with a page: fetch many
// small resources from one origin, as concurrently as the protocol allows.
//
// Over HTTP/1.1 that means opening several tunnels and running each serially,
// because a connection answers one request at a time in order. Over h2 it means
// one tunnel carrying every request at once. The origin latency is what makes
// the difference visible — with instant responses there is nothing to overlap.
func BenchmarkPageLoad(b *testing.B) {
	const (
		host          = "bench.example.com"
		resources     = 50
		originLatency = 20 * time.Millisecond
		h1Conns       = 6 // what browsers open per origin
	)
	_, pool := testCA(b)
	addr := startProxy(b, func(h *mitm.Handler) {
		h.UseRequest(syntheticResponder(2048, originLatency))
	})

	b.Run("h1-6-tunnels", func(b *testing.B) {
		cfg := &tls.Config{RootCAs: pool, ServerName: host, NextProtos: []string{"http/1.1"}}
		conns := make([]*tls.Conn, h1Conns)
		readers := make([]*bufio.Reader, h1Conns)
		for i := range conns {
			conns[i], _ = dialTunnel(b, addr, host, cfg)
			readers[i] = bufio.NewReader(conns[i])
			defer conns[i].Close()
			exchange(b, conns[i], readers[i], host)
		}

		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			var wg sync.WaitGroup
			queue := make(chan int, resources)
			for r := range resources {
				queue <- r
			}
			close(queue)
			for i := range conns {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					for range queue {
						exchange(b, conns[i], readers[i], host)
					}
				}(i)
			}
			wg.Wait()
		}
	})

	b.Run("h2-1-tunnel", func(b *testing.B) {
		client, _ := newHTTP2Client(b, addr, host, pool)
		getOnce(b, client, host)

		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			var wg sync.WaitGroup
			wg.Add(resources)
			for range resources {
				go func() {
					defer wg.Done()
					getOnce(b, client, host)
				}()
			}
			wg.Wait()
		}
	})
}

// ------------------------------------------------------------------- correctness

// TestProtocolNegotiation checks that both paths through the tunnel produce the
// same response. A client that asks for h2 must get h2, and a client that does
// not offer ALPN at all must still be served by the HTTP/1.1 loop — adding h2
// must not strand older clients.
func TestProtocolNegotiation(t *testing.T) {
	const host = "bench.example.com"
	_, pool := testCA(t)
	addr := startProxy(t, func(h *mitm.Handler) {
		h.UseRequest(syntheticResponder(1024, 0))
	})

	t.Run("no-alpn-falls-back-to-http1.1", func(t *testing.T) {
		conn, _ := dialTunnel(t, addr, host, &tls.Config{RootCAs: pool, ServerName: host})
		defer conn.Close()
		if got := conn.ConnectionState().NegotiatedProtocol; got != "" {
			t.Fatalf("negotiated %q, want none", got)
		}
		resp := exchange(t, conn, bufio.NewReader(conn), host)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		if got := resp.Header.Get("Etag"); got != `W/"1a2b3c4d5e6f"` {
			t.Errorf("Etag = %q, header did not survive the h1 path", got)
		}
		if resp.ContentLength != 1024 {
			t.Errorf("ContentLength = %d, want 1024", resp.ContentLength)
		}
	})

	t.Run("h2-is-negotiated-and-served", func(t *testing.T) {
		client, counter := newHTTP2Client(t, addr, host, pool)
		req, err := http.NewRequest(http.MethodGet, "https://"+host+"/index.html", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("h2 request: %v", err)
		}
		defer resp.Body.Close()

		if resp.ProtoMajor != 2 {
			t.Errorf("response proto = %s, want HTTP/2", resp.Proto)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		if got := resp.Header.Get("Etag"); got != `W/"1a2b3c4d5e6f"` {
			t.Errorf("Etag = %q, header did not survive the h2 path", got)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if len(body) != 1024 {
			t.Errorf("body = %d bytes, want 1024", len(body))
		}
		counter() // asserts exactly one h2 connection carried all of it
	})
}

// ----------------------------------------------------------------- upstream

// startOrigin runs a TLS origin the proxy can actually reach, and returns the
// host name to address it by plus a transport that trusts it.
//
// Everything else in this file short-circuits at a request middleware and never
// performs an upstream round trip, because the default upstream transport
// verifies against the system roots and no test can put a certificate there.
// The transport returned here is installed with SetUpstreamTransport: it trusts
// the origin's own certificate and sends every host to it, so the proxy dials
// "example.com:443" and lands on the local server.
func startOrigin(tb testing.TB, enableHTTP2 bool, handler http.Handler) (string, *http.Transport) {
	tb.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = enableHTTP2
	srv.StartTLS()
	tb.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	addr := srv.Listener.Addr().String()

	return "example.com", &http.Transport{
		// httptest's certificate is issued for example.com, so the proxy's own
		// verification of the origin stays real; only the address is redirected.
		TLSClientConfig:   &tls.Config{RootCAs: pool},
		ForceAttemptHTTP2: enableHTTP2,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
}

// TestUpstreamRoundTrip drives a request all the way through: client, tunnel,
// proxy, real origin, and back. It is the first test that reaches an upstream
// at all, and so the first that can show response middlewares running on a
// response the proxy did not invent — over both the h1 and the h2 client path.
func TestUpstreamRoundTrip(t *testing.T) {
	_, pool := testCA(t)

	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin-Path", r.URL.Path)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "from the origin")
	})
	host, upstream := startOrigin(t, false, origin)

	addr := startProxy(t, func(h *mitm.Handler) {
		h.SetUpstreamTransport(upstream)
		h.UseResponse(func(_ context.Context, resp *http.Response) (*http.Response, error) {
			resp.Header.Set("X-Response-Middleware", "ran")
			return resp, nil
		})
	})

	check := func(t *testing.T, resp *http.Response, body string) {
		t.Helper()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		if got := resp.Header.Get("X-Origin-Path"); got != "/index.html" {
			t.Errorf("X-Origin-Path = %q, the origin was not actually reached", got)
		}
		if got := resp.Header.Get("X-Response-Middleware"); got != "ran" {
			t.Errorf("X-Response-Middleware = %q, the response middleware did not run", got)
		}
		if body != "from the origin" {
			t.Errorf("body = %q, want the origin's body", body)
		}
	}

	t.Run("http1.1-client", func(t *testing.T) {
		conn, _ := dialTunnel(t, addr, host, &tls.Config{RootCAs: pool, ServerName: host})
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/index.html", nil)
		if err := req.Write(conn); err != nil {
			t.Fatalf("write request: %v", err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		check(t, resp, string(body))
	})

	t.Run("h2-client", func(t *testing.T) {
		client, _ := newHTTP2Client(t, addr, host, pool)
		resp, err := client.Get("https://" + host + "/index.html")
		if err != nil {
			t.Fatalf("h2 request: %v", err)
		}
		defer resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Errorf("client proto = %s, want HTTP/2", resp.Proto)
		}
		body, _ := io.ReadAll(resp.Body)
		check(t, resp, string(body))
	})
}
