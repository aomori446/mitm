# Performance work — plan and state

Working notes for an in-progress performance pass on the CONNECT/MITM path.
Delete this file when the pass is finished.

Branch: `perf/tls-and-write-path` (branched from `main` @ `223350b`).
The repo's own convention is committing straight to `main`; this branch was cut
only to keep the pass reviewable. Fast-forward `main` onto it whenever.

## Working agreement

- **One change at a time.** Apply a single fix, measure it, report, stop.
  Do not chain changes before reporting.
- After each change: a short report with a before/after table, then state what
  the next change is and wait.
- Benchmark on the Mac while iterating. Run the VPS pass **at the end**, once
  the changes are settled.
- Only claim a win the measurement supports. Deterministic counters
  (records, wire bytes, allocs, resumption rate) outrank wall-clock time.

## Measurement setup

`bench_test.go` (package `mitm_test`) drives a real `Handler` over loopback TCP
with real TLS on the client hop.

- `BenchmarkTunnelHandshake` — CONNECT, handshake, one exchange, close. Reports
  `%resumed`.
- `BenchmarkTunnelRequest` — steady-state requests over an established tunnel at
  body sizes 0B / 1KiB / 64KiB.
- Both report `records/op` and `wireB/op`, recovered by walking TLS record
  framing in the client's byte stream. Exact counts, not timings, so they stay
  meaningful on a noisy box and they price network cost that loopback timing
  cannot show.

`transport_internal_test.go` (package `mitm`) measures retention rather than
latency: heap held per distinct upstream host, plus guard tests on the upstream
transport's pool bounds.

### Always interleave A/B

Two separate `-count N` runs are **not** comparable — the M4 drifts between
runs. It produced a bogus "+2.5% regression" on a change that mechanically
cannot touch the per-request path, and moved `TunnelHandshake` by -29% between
methodologies with identical code.

Build two test binaries and alternate them:

```bash
cp connect.go /tmp/after.go && git checkout connect.go
go test -c -o /tmp/A.test ./          # before
cp /tmp/after.go connect.go
go test -c -o /tmp/B.test ./          # after
for i in $(seq 1 10); do
  /tmp/A.test -test.run XXX -test.bench . -test.benchtime 2s -test.count 1 >> A.txt 2>&1
  /tmp/B.test -test.run XXX -test.bench . -test.benchtime 2s -test.count 1 >> B.txt 2>&1
done
benchstat before=A.txt after=B.txt
```

Absolute numbers are only comparable **within** one such comparison.

### VPS (final pass only)

`ssh sakura` — Debian 12, x86_64, **1 vCPU, 457 MB RAM, no swap**. Idle, steal
time 0.05%. No Go installed; cross-compile and copy:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/mitm.linux.test ./
scp /tmp/mitm.linux.test sakura:~/mitm-bench/
ssh sakura 'cd ~/mitm-bench && ./mitm.linux.test -test.run XXX -test.bench . -test.benchtime 2s -test.count 10'
```

What the VPS is good for: deterministic counters (they matched the Mac byte for
byte) and steady-state request timing (±2–6%).

What it is **not** good for: `TunnelHandshake` wall-clock. It throws outliers of
10–50 ms against a 1.7 ms typical, in 3 of 10 runs. Ruled out by measurement:
memory pressure (`GOMEMLIMIT=128MiB` did not help) and TIME_WAIT/port exhaustion
(`time-wait` stayed at 1 throughout). The cause is the benchmark's client and
proxy contending for one core. Do not report that number.

`netem` was considered and **rejected**: `lo` MTU is 65536, so a ~1.6 KB
response is one packet and `netem delay` adds no extra round trip — it would
prove nothing. `rate` would be the meaningful knob, but `wireB/op` already gives
the exact byte count, from which the cost at any link speed follows directly.
`sudo` on the VPS needs the `debian` user's own password (that user is in group
27/sudo); root SSH by key is disabled.

## Done

- [x] **1 — Share one `tls.Config`** (`a9e7c85`, `cert.go`)
      `TLSConfig()` built a fresh config per connection; a `tls.Config` owns the
      session ticket keys, so every client got a ticket nobody could decrypt.
      Resumption 0.00% → 99.94%; handshake wire bytes −12.7%; allocs −10.2%;
      tunnel setup −11.2% on the M4.

- [x] **2 — Buffer the response write** (`1fbf4c8`, `connect.go`)
      `resp.Write` on a raw `tls.Conn` turned each header field into its own TLS
      record. Records per response 51 → 1; wire bytes 1610 → 510; allocs/request
      130 → 65; steady-state request 154.1 µs → 40.4 µs. Most of the time saved
      is context switches — the client no longer wakes fifty times per response.

- [x] **3 — Upstream transport lifecycle** (`transport.go`, `handler.go`,
      `connect.go`, `transport_internal_test.go`)
      `h.transports` (a `sync.Map` keyed by host) only ever grew: every host ever
      seen kept a `*http.Transport` and its pool forever. `IdleConnTimeout` was
      unset, so its zero value kept idle connections alive indefinitely, with no
      `MaxIdleConns` ceiling. `tls.Dialer` had no `Timeout`.

      Replaced with one shared bounded transport built in `New`. Retention per
      distinct host 1092 B → 0.33 B and 8.38 objects → 0.001; at 5000 hosts that
      is 5.5 MB retained versus none. The guard tests failed before the change
      and pass after.

- [x] **4 — HTTP/2 on the client side** (`cert.go`, `connect.go`)
      The proxy forced every site down to HTTP/1.1 even when the client spoke
      h2. Now the forged config offers `["h2", "http/1.1"]`, and a tunnel that
      negotiates h2 is handed to `http2.Server.ServeConn` with a
      `httputil.ReverseProxy` handler; anything else still runs the HTTP/1.1
      loop. Added `golang.org/x/net`.

      Header-only response 510 -> 45 wire bytes (HPACK). Page load of 50
      resources at 20 ms origin latency: 191.4 ms over six h1 tunnels -> 24.3 ms
      over one h2 tunnel (7.9x). Costs a single serialized request 37.8 ->
      78.7 us and 65 -> 139 allocs; h2 framing only pays off under concurrency.

- [x] **5a — Expose the upstream transport** (`handler.go`)
      `UpstreamTransport` / `SetUpstreamTransport`, guarded by the existing
      mutex. No performance change of its own; it unblocks measuring anything
      upstream, and it is what users need for proxy chaining and private roots.
      `TestUpstreamRoundTrip` is the first test that reaches a real origin, and
      the first to show a response middleware running on a response the proxy
      did not invent — over both the h1 and h2 client paths.

- [x] **5b — HTTP/2 upstream** (`transport.go`)
      `newUpstreamTransport` still pins `NextProtos: ["http/1.1"]` on the
      upstream dial, so the proxy opens a separate h1 connection per concurrent
      request even when the origin offers h2. Dropping the pin needs
      `ForceAttemptHTTP2: true`, because `http.Transport` does not enable h2
      automatically once `DialTLSContext` is set. Consider dropping
      `DialTLSContext` entirely in favour of `DialContext` + `TLSClientConfig`,
      which also makes `TLSHandshakeTimeout` apply — it does not today.

      Dropped `DialTLSContext` for `DialContext` + `TLSClientConfig` +
      `ForceAttemptHTTP2` (needed, because `http.Transport` stops negotiating h2
      by itself once a dial function is set). `TLSHandshakeTimeout` now applies;
      it did not before.

      `BenchmarkUpstreamProtocol`, 50 concurrent requests at 20 ms origin
      latency, client side held constant at one h2 tunnel:

        upstream dials per op   40.1 -> 0     (one connection, reused)
        wall time              33.79ms -> 23.65ms (-30.0%)
        allocations            43.0k -> 7.8k  (-82.0%)
        memory                 7.89MiB -> 2.38MiB (-69.8%)

- [x] **6 — Pool the reverse proxy's copy buffers** (`handler.go`, `connect.go`)
      The hypothesis recorded here was wrong, and worth recording as wrong: the
      memory was not `http2.Server`'s `MaxUploadBufferPerConnection` /
      `MaxUploadBufferPerStream`. Those are flow-control window sizes, not
      preallocated buffers, and tuning them would have changed nothing.

      An alloc profile put 67% of h2 allocations in
      `httputil.ReverseProxy.copyBuffer`: with no `BufferPool` set, ReverseProxy
      allocates a fresh 32 KiB copy buffer for **every response**. Introduced by
      change 4 on the h2 path, and present in `h.httpProxy` since long before
      this pass. Both now share one `sync.Pool`.

      Interleaved A/B, eight rounds per side:

        h2 request, per op        45.89KiB -> 13.79KiB  (-69.9%)
        page load (h2)             2634KiB ->   758KiB  (-71.2%)
        upstream fanout (h2)       2556KiB ->   855KiB  (-66.6%)
        upstream fanout (h1 pin)  8.11MiB  ->  6.78MiB  (-16.4%)
        h2 request wall time        80.3us ->   76.8us  (-4.3%)

      h2's memory premium over h1 is now about 4 KiB per request rather than
      36 KiB.

- [x] **VPS pass** — whole suite on `sakura`, eight runs. All four tests pass on
      linux/amd64.

      Every deterministic counter matched the Mac exactly: records/op
      (7/1/1/17/1/2/10), wireB/op (3016/510/1537/66400/45/1100/65822), upstream
      dials (40.7 pinned vs 0 over h2), resumption 99.94% against 99.96%.
      Retention 0.074 B/host against the Mac's 0.33 — both zero in practice.

      The one result the Mac could not have shown: **the upstream h2 fix is
      worth far more on a weak machine.** Fifty concurrent requests took
      174.9 ms pinned to http/1.1 against 30.0 ms over h2 — 5.8x, where the M4
      showed 1.4x. Opening forty TLS connections per iteration is CPU-bound, and
      one Broadwell core feels that in a way ten M4 cores do not. Steady-state
      requests are only 1.7x slower on the VPS, and the latency-bound page load
      is the same on both (188.1 ms vs 191.2 ms over h1), which is the sanity
      check that the difference really is handshake CPU.

      `TunnelHandshake` wall-clock was again unusable (±177%), as expected.

## Next

## Found but not scheduled

- **The plain-HTTP path ignores the upstream transport.** `h.httpProxy` still
  uses `http.DefaultTransport`, so `SetUpstreamTransport` does not affect
  non-CONNECT requests. Worth aligning in 5b, once the transport handles plain
  http:// as well as it handles https.

- **Idle tunnels are never timed out** (`connect.go`, the `ReadRequest` loop).
  Exits only on error or close, so an idle keep-alive tunnel holds two
  goroutines, a `bufio.Reader`/`Writer` and a `tls.Conn`'s buffers (~32 KB+)
  indefinitely. Wants a `SetReadDeadline` per iteration.

- **Large bodies do not fill TLS records.** After change 2, a 64 KiB body still
  costs 17 records because `bufio.Writer`'s default buffer is 4096, averaging
  ~3.9 KB per record against TLS's 16 KB ceiling.
  `bufio.NewWriterSize(tlsDownstream, 16<<10)` would get it to about 5 — at 16 KB
  of memory per tunnel, which fights the idle-tunnel item above. Deliberately
  skipped. Note h2 already does better here: 10 records for the same body.

- **`forgeCert` thundering herd** (`cert.go`). Concurrent first connections to
  one host each forge a certificate (~hundreds of µs, P-256); `LoadOrStore`
  dedupes the storing but not the work. Wants `singleflight` or a per-host
  `sync.Once`. Also: an empty SNI caches a certificate under `""` with no SAN.

- **Middleware slices are read under `RLock` twice per request**
  (`handler.go:183`, `handler.go:197`). Tiny, but registration is a startup-time
  activity — `atomic.Pointer[[]RequestFunc]` would remove the contention
  entirely.

- **`DumpRequest`/`DumpResponse` read the whole body into memory**
  (`middleware/dump.go`). Documented as debug-only; worth saying in the doc
  comment that large uploads will blow up.

- **`DisableCompression: true` is correct, not a bug** (`transport.go:41`). It
  only stops Go adding its own `Accept-Encoding`; the client's own header is
  forwarded, so compression still happens and the proxy avoids a
  decompress/recompress round trip.

- **The repo is not `gofmt`-clean** — blank lines carry trailing whitespace
  throughout. Left alone deliberately; reformatting would bury these diffs.
