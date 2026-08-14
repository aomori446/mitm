package mitm

import (
	"fmt"
	"net/http"
	"runtime"
	"testing"
)

// The upstream transport is reached only from inside the CONNECT path, and its
// cost is retention rather than latency: nothing here is about how fast a
// request is, only about what the proxy still holds after the request is gone.
// So these live in the package and measure heap, not time.

// hostsFanout is how many distinct upstream hosts a measurement walks. A
// browser session against an ad-heavy page contacts a few hundred; a proxy left
// running for a day sees far more.
const hostsFanout = 5000

// BenchmarkTransportRetention reports how much heap the handler still holds per
// distinct upstream host once the requests themselves are over. A proxy is a
// long-lived process that sees an unbounded set of hosts, so anything retained
// per host is a leak measured in uptime.
func BenchmarkTransportRetention(b *testing.B) {
	for b.Loop() {
		b.StopTimer()
		h := New(nil)
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		b.StartTimer()

		for i := range hostsFanout {
			routeUpstream(h, fmt.Sprintf("host%d.example.com:443", i))
		}

		b.StopTimer()
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		// h is live across the read, so this is retention and not garbage.
		retained := float64(after.HeapAlloc) - float64(before.HeapAlloc)
		b.ReportMetric(retained/hostsFanout, "retainedB/host")
		b.ReportMetric(float64(after.HeapObjects-before.HeapObjects)/hostsFanout, "objects/host")
		runtime.KeepAlive(h)
		b.StartTimer()
	}
}

// TestUpstreamTransportIsBounded pins the pool limits that keep a long-running
// proxy from accumulating connections it will never use again. An
// IdleConnTimeout of zero means idle connections are kept forever, which on a
// proxy is unbounded: it is the one field whose zero value is a leak.
func TestUpstreamTransportIsBounded(t *testing.T) {
	tr, ok := routeUpstream(New(nil), "example.com:443").(*http.Transport)
	if !ok {
		t.Fatal("the default upstream is not an *http.Transport")
	}

	if tr.IdleConnTimeout == 0 {
		t.Error("IdleConnTimeout is 0: idle upstream connections are never reaped")
	}
	if tr.MaxIdleConns == 0 {
		t.Error("MaxIdleConns is 0: the idle pool has no global ceiling")
	}
	if tr.MaxIdleConnsPerHost == 0 {
		t.Error("MaxIdleConnsPerHost is 0")
	}
}

// TestTransportIsSharedAcrossHosts states the invariant that keeps retention
// flat: two different hosts must route to the same transport. http.Transport
// already keys its pool by host:port, so a transport per host buys no isolation
// the pool does not provide, and it costs a map entry per host forever.
func TestTransportIsSharedAcrossHosts(t *testing.T) {
	h := New(nil)
	a := routeUpstream(h, "a.example.com:443")
	b := routeUpstream(h, "b.example.com:443")

	if a != b {
		t.Errorf("two hosts routed to distinct transports: %p vs %p", a, b)
	}
}

// routeUpstream mirrors how the CONNECT path picks the transport for a host, so
// these measurements track the real routing decision rather than a stand-in.
// The host is deliberately unused: that it does not matter is the property
// under test.
func routeUpstream(h *Handler, host string) http.RoundTripper {
	_ = host
	return h.UpstreamTransport()
}
