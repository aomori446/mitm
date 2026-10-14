# mitm

[![Go Reference](https://pkg.go.dev/badge/github.com/aomori446/mitm.svg)](https://pkg.go.dev/github.com/aomori446/mitm)
[![CI](https://github.com/aomori446/mitm/actions/workflows/ci.yml/badge.svg)](https://github.com/aomori446/mitm/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/aomori446/mitm)](https://github.com/aomori446/mitm/blob/main/go.mod)
[![Latest Tag](https://img.shields.io/github/v/tag/aomori446/mitm?sort=semver)](https://github.com/aomori446/mitm/tags)
[![License](https://img.shields.io/github/license/aomori446/mitm)](https://github.com/aomori446/mitm/blob/main/LICENSE)

A Man-in-the-Middle (MITM) HTTP/HTTPS proxy library for Go.

## Use Cases

- Debugging HTTP/HTTPS APIs: see exactly what an app sends and receives
- Rewriting requests and responses to test edge cases and error handling
- Mocking or blocking upstream services during development

## Features

- Transparent TCP relay or full TLS interception per CONNECT tunnel
- Unified request/response middleware pipeline for both plain-HTTP and HTTPS traffic
- Upstream TLS connection pooling with cross-session reuse
- Per-host certificate forging and caching, signed once however many connections
  arrive for a host at the same time
- Certificates for clients that send no SNI, forged for the CONNECT target
- Built-in middlewares for common use cases

## Installation

```sh
go get github.com/aomori446/mitm
```

## Quick Start

Generate a CA certificate and key once (see [Generating a CA Certificate](#generating-a-ca-certificate)):

```sh
go run github.com/aomori446/mitm/examples/genca@latest -cert testdata/ca.crt -key testdata/ca.key
```

Then start the proxy:

```go
package main

import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/aomori446/mitm"
)

func main() {
    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer stop()

    certMgr, err := mitm.NewCertManager("testdata/ca.crt", "testdata/ca.key")
    if err != nil {
        log.Fatal(err)
    }

    handler := mitm.New(certMgr)

    // Starts proxy server with built-in graceful shutdown on ctx cancellation
    if err := handler.ListenAndServe(ctx, ":8080"); err != nil {
        log.Fatal(err)
    }
}
```

Point your browser's proxy settings to `localhost:8080` and install `testdata/ca.crt` as a trusted CA.

> **Note**: `mitm.Handler` also implements `http.Handler`, so you can plug it into a custom `http.Server` or multiplexer if needed.

## Middlewares

Register middlewares to inspect or modify traffic:

```go
handler.UseRequest(func(ctx context.Context, req *http.Request) (*http.Request, *http.Response) {
    // Return a modified request, or short-circuit with a synthetic response.
    return req, nil
})

handler.UseResponse(func(ctx context.Context, resp *http.Response) (*http.Response, error) {
    // Return a modified response, or return an error to abort.
    return resp, nil
})

handler.UseError(func(ctx context.Context, req *http.Request, err error) {
    // The upstream round trip failed, so no response middleware runs for req.
})

handler.UseHandshakeError(func(ctx context.Context, host string, err error, d time.Duration) {
    // A client TLS handshake against the forged certificate failed —
    // usually the client does not trust the CA.
})
```

Middlewares are called in registration order. A non-nil `*http.Response` from a `UseRequest` middleware
short-circuits the upstream request and sends the response directly to the client. `mitm.Response`
builds one:

```go
return req, mitm.Response(http.StatusForbidden, "text/plain", io.NopCloser(strings.NewReader("blocked")))
```

Every request that reaches the upstream is followed by exactly one of the response middlewares or the
error middlewares, so state keyed on the request can always be released.

Handshake errors that are just EOF, connection reset, or a closed connection are treated as ordinary
client probes and do not reach `UseHandshakeError`.

## Built-in Middlewares

All middlewares live in `github.com/aomori446/mitm/middleware`.

### Logger

```go
onReq, onResp := middleware.Logger(slog.Default())
handler.UseRequest(onReq)
handler.UseResponse(onResp)
```

Logs method, URL, status code, content-type, and elapsed time.

### Blocker

```go
// Block by host pattern → 403 Forbidden
handler.UseRequest(middleware.Blocker("ads.example.com", "*.doubleclick.net"))

// Block with a content-appropriate empty response
handler.UseRequest(middleware.BlockerWith(
    middleware.RespondWithAuto(), // pixel / empty JS / empty CSS / empty HTML
    "*.googlesyndication.com",
))

// Block by custom match function
handler.UseRequest(middleware.BlockerFunc(
    middleware.RespondWithEmptyJS(),
    func(req *http.Request) bool {
        return strings.HasSuffix(req.URL.Path, "/analytics.js")
    },
))
```

Available `BlockResponse` helpers:

| Helper | Response |
|---|---|
| `RespondWith403()` | 403 Forbidden |
| `RespondWithPixel()` | 1×1 transparent GIF |
| `RespondWithEmptyJS()` | `//` (empty JS) |
| `RespondWithEmptyCSS()` | empty CSS |
| `RespondWithEmptyHTML()` | `<html></html>` |
| `RespondWithAuto()` | inferred from URL extension |

### Header

```go
handler.UseRequest(middleware.SetRequestHeader("Authorization", "Bearer token"))
handler.UseRequest(middleware.RemoveRequestHeader("Cookie"))
handler.UseResponse(middleware.SetResponseHeader("X-Frame-Options", "DENY"))
handler.UseResponse(middleware.RemoveResponseHeader("Server"))
```

### Dump

```go
onReq, onResp := middleware.Dump(os.Stderr)
handler.UseRequest(onReq)
handler.UseResponse(onResp)
```

Writes each request and response in HTTP/1.1 wire format to the provided writer.

Each body is read into memory in full to be written out and replayed, so a large
upload or download passing through the proxy is held in memory whole. Scope this
to the traffic being investigated rather than leaving it on a busy proxy.
`DumpRequest` and `DumpResponse` are available separately if only one direction
is wanted.

## Configuration

### Upstream transport

```go
handler.SetUpstreamTransport(&http.Transport{
    Proxy:           http.ProxyURL(corporateProxy),
    TLSClientConfig: &tls.Config{RootCAs: privateRoots},
})
```

Replaces the round tripper used for every proxied request: to reach origins
through another proxy, to trust a private certificate authority, or to observe
upstream traffic in a test. It applies to plain HTTP as well as to intercepted
tunnels, and takes effect on the next round trip rather than only on new
tunnels. Middlewares still run around whatever is set here — this replaces only
the round trip itself.

The default is tuned for a proxy: one pooled transport for every host, with an
idle timeout and a ceiling so a long-lived process does not accumulate
connections it will never use again.

### Tunnel idle timeout

```go
handler.SetTunnelIdleTimeout(90 * time.Second)
```

Bounds how long an intercepted tunnel may sit with no request in flight before
the proxy closes it. It bounds only the wait for the next request; a request
already arriving, however slowly, is not idle. The default of zero disables the
bound, which means a client that opens a tunnel and goes quiet holds its
goroutines and buffers until it disconnects. Only tunnels opened after the call
are affected.

### Certificate manager

```go
handler.SetCertManager(newCertMgr)
```

Swaps the CA in use — for rotating to a freshly generated one without restarting
the proxy. `handler.CertManager()` reads the current one back. Both are safe to
call while the proxy is serving.

## Generating a CA Certificate

`GenerateCA` writes a new CA certificate and key, and is what the `genca`
example wraps:

```go
mitm.GenerateCA("testdata/ca.crt", "testdata/ca.key")
```

Or from the command line:

```sh
go run ./examples/genca -cert testdata/ca.crt -key testdata/ca.key
```

## Running the Example Proxy

```sh
go run ./examples/proxy -addr :8080 -ca-cert testdata/ca.crt -ca-key testdata/ca.key
```

## Project Structure

```
cert.go        CA loading, per-host cert forging and caching
connect.go     CONNECT tunnel handling (MITM & TCP relay)
handler.go     Core proxy handler (ServeHTTP, ListenAndServe, middlewares)
relay.go       Bidirectional TCP relay for transparent tunnelling
transport.go   Upstream connection pooling and middleware transport
middleware/    Middleware types and built-in middlewares
examples/      Runnable reference implementations
PERF.md        What the benchmarks measure, and what was measured and left alone
```

## Security Note

The generated CA can sign a certificate for any host, so anyone holding
`ca.key` can impersonate any site to a machine that trusts the CA. Keep the key
private, trust the CA only on machines you control, and remove it from the trust
store when you are done. Only intercept traffic you are authorized to inspect.

## Requirements

- Go 1.26+

## License

(C) 2026 Aomori446, [MIT License](https://github.com/aomori446/mitm/blob/main/LICENSE)