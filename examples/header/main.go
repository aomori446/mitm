// Command header demonstrates the Header interceptor helpers:
// injecting headers into upstream requests and stripping or adding
// headers on responses.
//
// Usage:
//
//	go run ./examples/header -ca-cert testdata/ca.crt -ca-key testdata/ca.key
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/aomori446/mitm"
	"github.com/aomori446/mitm/interceptor"
)

func main() {
	addr := flag.String("addr", ":8080", "proxy listen address")
	caCert := flag.String("ca-cert", "testdata/ca.crt", "path to CA certificate file")
	caKey := flag.String("ca-key", "testdata/ca.key", "path to CA private key file")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	certMgr, err := mitm.NewCertManager(*caCert, *caKey)
	if err != nil {
		log.Fatal(err)
	}

	handler := mitm.New(certMgr)

	// Inject a custom header into every upstream request.
	handler.OnRequest(interceptor.SetRequestHeader("X-Proxy", "mitm"))

	// Strip a tracking header from every upstream request.
	handler.OnRequest(interceptor.RemoveRequestHeader("Cookie"))

	// Add security headers to every response.
	handler.OnResponse(interceptor.SetResponseHeader("X-Frame-Options", "DENY"))
	handler.OnResponse(interceptor.SetResponseHeader("X-Content-Type-Options", "nosniff"))

	// Remove server fingerprinting headers from every response.
	handler.OnResponse(interceptor.RemoveResponseHeader("X-Powered-By"))
	handler.OnResponse(interceptor.RemoveResponseHeader("Server"))

	server := &http.Server{
		Addr:    *addr,
		Handler: handler,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}

	go func() {
		<-ctx.Done()
		server.Shutdown(ctx)
	}()

	err = server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
