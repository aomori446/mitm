# mitm

A Man-in-the-Middle (MITM) HTTP/HTTPS proxy library for Go.

## Features

- Transparent TCP relay or full TLS interception per CONNECT tunnel
- Unified request/response middleware pipeline for both plain-HTTP and HTTPS traffic
- Upstream TLS connection pooling with cross-session reuse
- Built-in middlewares for common use cases

## Installation

```sh
go get github.com/aomori446/mitm
```

## Quick Start

```go
package main

import (
    "context"
    "os"
    "os/signal"
    "syscall"

    "github.com/aomori446/mitm"
)

func main() {
    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer stop()

    certMgr, _ := mitm.NewCertManager("testdata/ca.crt", "testdata/ca.key")

    handler := mitm.New(certMgr)

    // Starts proxy server with built-in graceful shutdown on ctx cancellation
    handler.ListenAndServe(ctx, ":8080")
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
```

Middlewares are called in registration order. A non-nil `*http.Response` from a `UseRequest` middleware
short-circuits the upstream request and sends the response directly to the client.

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

## Generating a CA Certificate

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
relay.go       TCPRelay for transparent tunnelling
transport.go   Upstream connection pooling and middleware transport
middleware/    Middleware types and built-in middlewares
examples/      Runnable reference implementations
```

## Requirements

- Go 1.21+

## License

(C) 2026 Aomori446, [MIT License](https://github.com/aomori446/mitm/blob/main/LICENSE)