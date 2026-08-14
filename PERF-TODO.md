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

## Next

- [ ] **4 — HTTP/2** (`connect.go`, `transport.go`) ← next
      The proxy currently forces every site down to HTTP/1.1 even when client
      and origin both speak h2. `transport.go` pins `NextProtos: ["http/1.1"]`
      upstream, and the client side runs an `http.ReadRequest` loop that can only
      parse h1.

      Note on why the h1 loop is *not* worth parallelising: HTTP/1.1 has no
      request ID (clients match responses by order), the request body shares the
      byte stream with the next request (so request N+1 cannot even be read
      before N's body is drained), and browsers disabled pipelining years ago —
      so a tunnel never has more than one request outstanding. Cross-connection
      concurrency already exists: a browser opens ~6 tunnels per origin and
      `http.Server` gives each its own goroutine.

      Fix: advertise `NextProtos: ["h2", "http/1.1"]` on the forged config; after
      the handshake, when `ConnectionState().NegotiatedProtocol == "h2"`, hand
      the conn to `http2.Server.ServeConn` with an `http.Handler` running the
      existing middleware + `RoundTrip`, instead of the `ReadRequest` loop. Keep
      the h1 loop for h1 clients. Drop the upstream `NextProtos` pin. Needs
      `golang.org/x/net/http2`; middleware signatures are unaffected since it is
      still `*http.Request` / `*http.Response`.

      Buys real per-connection concurrency (stream IDs, so ordering is not
      required), HPACK — the measured 510 wire bytes per response should drop to
      tens of bytes since repeated headers become index references — and one TLS
      handshake instead of six, which compounds with change 1.

## Found but not scheduled

- **Idle tunnels are never timed out** (`connect.go`, the `ReadRequest` loop).
  Exits only on error or close, so an idle keep-alive tunnel holds two
  goroutines, a `bufio.Reader`/`Writer` and a `tls.Conn`'s buffers (~32 KB+)
  indefinitely. Wants a `SetReadDeadline` per iteration.

- **Large bodies do not fill TLS records.** After change 2, a 64 KiB body still
  costs 17 records because `bufio.Writer`'s default buffer is 4096, averaging
  ~3.9 KB per record against TLS's 16 KB ceiling.
  `bufio.NewWriterSize(tlsDownstream, 16<<10)` would get it to about 5 — at 16 KB
  of memory per tunnel, which fights the idle-tunnel item above. Deliberately
  skipped.

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
