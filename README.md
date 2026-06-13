# mitm

A Man-in-the-Middle (MITM) HTTP/HTTPS proxy library for Go.

## Features

- Transparent TCP relay or full TLS interception per CONNECT tunnel
- Unified request/response hook pipeline for both plain-HTTP and HTTPS traffic
- Upstream TLS connection pooling with cross-session reuse
- Built-in interceptors for common use cases

## Installation

```sh
go get github.com/aomori446/mitm
```

## Quick Start

```go
package main

import (
    "context"
    "net/http"

    "github.com/aomori446/mitm"
    "github.com/aomori446/mitm/cert"
)

func main() {
    certMgr, _ := cert.NewManager("certs/ca.crt", "certs/ca.key")

    handler := mitm.New(certMgr)

    http.ListenAndServe(":8080", handler)
}
```

Point your browser's proxy settings to `localhost:8080` and install `certs/ca.crt` as a trusted CA.

## Hooks

Register hooks to inspect or modify traffic:

```go
handler.OnRequest(func(ctx context.Context, req *http.Request) (*http.Request, *http.Response) {
    // Return a modified request, or short-circuit with a synthetic response.
    return req, nil
})

handler.OnResponse(func(ctx context.Context, resp *http.Response) (*http.Response, error) {
    // Return a modified response, or return an error to abort.
    return resp, nil
})
```

Hooks are called in registration order. A non-nil `*http.Response` from an `OnRequest` hook
short-circuits the upstream request and sends the response directly to the client.

## Built-in Interceptors

All interceptors live in `github.com/aomori446/mitm/interceptor`.

### Logger

```go
onReq, onResp := interceptor.Logger(slog.Default())
handler.OnRequest(onReq)
handler.OnResponse(onResp)
```

Logs method, URL, status code, content-type, and elapsed time.

### Blocker

```go
// Block by host pattern → 403 Forbidden
handler.OnRequest(interceptor.Blocker("ads.example.com", "*.doubleclick.net"))

// Block with a content-appropriate empty response
handler.OnRequest(interceptor.BlockerWith(
    interceptor.RespondWithAuto(), // pixel / empty JS / empty CSS / empty HTML
    "*.googlesyndication.com",
))

// Block by custom match function
handler.OnRequest(interceptor.BlockerFunc(
    interceptor.RespondWithEmptyJS(),
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
handler.OnRequest(interceptor.SetRequestHeader("Authorization", "Bearer token"))
handler.OnRequest(interceptor.RemoveRequestHeader("Cookie"))
handler.OnResponse(interceptor.SetResponseHeader("X-Frame-Options", "DENY"))
handler.OnResponse(interceptor.RemoveResponseHeader("Server"))
```

### Dump

```go
onReq, onResp := interceptor.Dump(os.Stderr)
handler.OnRequest(onReq)
handler.OnResponse(onResp)
```

Writes each request and response in HTTP/1.1 wire format to the provided writer.

## Generating a CA Certificate

```sh
go run ./examples/genca -cert certs/ca.crt -key certs/ca.key
```

## Running the Example Proxy

```sh
go run ./examples/proxy -addr :8080 -ca-cert certs/ca.crt -ca-key certs/ca.key
```

## Project Structure

```
cert/          CA loading, per-host cert forging and caching
interceptor/   Hook types and built-in interceptors
examples/      Runnable reference implementations
handler.go     Core proxy handler (ServeHTTP, CONNECT, hooks)
relay.go       TCPRelay for transparent tunnelling
```

## Requirements

- Go 1.21+
