// Command blocker demonstrates how to block specific hosts using the
// Blocker interceptor. Requests to matched hosts receive a 403 Forbidden
// response instead of being forwarded upstream.
//
// Usage:
//
//	go run ./examples/blocker -ca-cert certs/ca.crt -ca-key certs/ca.key
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
	"github.com/aomori446/mitm/cert"
	"github.com/aomori446/mitm/interceptor"
)

func main() {
	addr := flag.String("addr", ":8080", "proxy listen address")
	caCert := flag.String("ca-cert", "certs/ca.crt", "path to CA certificate file")
	caKey := flag.String("ca-key", "certs/ca.key", "path to CA private key file")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	certMgr, err := cert.NewManager(*caCert, *caKey)
	if err != nil {
		log.Fatal(err)
	}

	handler := mitm.New(certMgr)

	// Block exact hosts and wildcard subdomains.
	handler.OnRequest(interceptor.Blocker(
		"ads.example.com",
		"*.tracking.io",
	))

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
