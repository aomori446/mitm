# Performance notes

What the benchmarks measure, how to run them so the numbers mean something, and
the things that were measured and deliberately left alone.

## Benchmarks

`bench_test.go` drives a real `Handler` over loopback TCP with real TLS on the
client hop. `cert_internal_test.go` and `transport_internal_test.go` measure
things that are not requests: certificate forging, and what the handler retains.

| | measures |
|---|---|
| `TunnelHandshake` | CONNECT, handshake, one exchange, close. Reports `%resumed`. |
| `TunnelRequest` | steady state over an established HTTP/1.1 tunnel |
| `TunnelRequestHTTP2` | the same over h2, so the two read side by side |
| `PageLoad` | 50 resources at 20 ms origin latency: six h1 tunnels against one h2 tunnel |
| `UpstreamProtocol` | 50 concurrent requests, upstream pinned to http/1.1 against ALPN |
| `IdleTunnelCost` | goroutines and bytes held by a tunnel with nothing in flight |
| `ForgeCertStampede` | 16 connections arriving together for an unseen host |
| `TransportRetention` | heap the handler keeps per distinct upstream host |

`records/op` and `wireB/op` come from walking TLS record framing in the client's
byte stream. They are exact counts rather than timings, so they stay meaningful
on a noisy machine, and they price network cost that a loopback timing cannot
show. Prefer them over wall clock when the two disagree.

## Running them

**Always interleave A/B.** Two separate `-count N` runs are not comparable: this
was measured producing a "+2.5% regression" on a change that mechanically could
not touch the per-request path.

```bash
cp connect.go /tmp/after.go && git checkout connect.go
go test -c -o /tmp/A.test ./
cp /tmp/after.go connect.go && go test -c -o /tmp/B.test ./
for i in $(seq 1 10); do
  /tmp/A.test -test.run XXX -test.bench . -test.benchtime 2s -test.count 1 >> A.txt 2>&1
  /tmp/B.test -test.run XXX -test.bench . -test.benchtime 2s -test.count 1 >> B.txt 2>&1
done
benchstat before=A.txt after=B.txt
```

Absolute numbers are comparable only within one such comparison.

On a second machine (cross-compile; no Go needed there):

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/mitm.linux.test ./
```

Every deterministic counter has matched exactly across darwin/arm64 and
linux/amd64. Timings do not: a weak single core showed the upstream h2 change
worth 5.8x where a ten-core machine showed 1.4x, because opening forty TLS
connections is CPU-bound. `TunnelHandshake` wall clock is unusable on one core —
it throws 10–50 ms outliers against a 1.7 ms typical, from the benchmark's
client and proxy contending for the same core. Its `%resumed` is still good.

## Measured, and deliberately not changed

- **The handler's RWMutex.** A mutex profile of fifty concurrent h2 streams put
  `middlewareTransport.RoundTrip` at 4.88 ms of 603.85 ms of total delay, 0.81%.
  What contention exists is `bufio.(*Writer).Flush` in the h2 framer, at 23.7%.
  A copy-on-write snapshot would restructure all of the handler's mutable state
  for under one percent of an already small cost.

- **A larger write buffer for HTTP/1.1 bodies.** A 64 KiB body still costs 17
  TLS records, because `bufio.Writer`'s default 4096 averages ~3.9 KB per record
  against TLS's 16 KB ceiling. `bufio.NewWriterSize(tlsDownstream, 16<<10)` would
  get it to about 5 — at 16 KB of memory per tunnel, against an idle-tunnel cost
  the proxy works to keep down. h2 already manages 10 records for the same body.

- **`DisableCompression: true` is correct.** It only stops Go adding its own
  `Accept-Encoding`. The client's own header is forwarded, so compression still
  happens and the proxy avoids decompressing and recompressing every response.

- **HTTP/2 costs a serialized request about 2x.** Framing, flow control and
  HPACK state are fixed overhead that only concurrency pays back. It is the
  right default because browsers are concurrent, but a client issuing one
  request at a time is slower through h2 than through HTTP/1.1.

- **HTTP/1.1 pipelining is not worth implementing.** HTTP/1.1 has no request id,
  so clients match responses by order; the request body shares the byte stream
  with the next request, so request N+1 cannot be read before N's body is
  drained; and browsers disabled pipelining years ago. Concurrency across
  connections already exists — a browser opens about six tunnels per origin and
  `http.Server` gives each its own goroutine. HTTP/2 is the answer instead, and
  is what the proxy now offers.
