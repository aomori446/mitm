// Command logger demonstrates how to attach the Logger interceptor to a
// MITM proxy to log every proxied request and response.
//
// Each request line includes the method and URL.
// Each response line includes the status code, content-type, elapsed time, and URL.
//
// Usage:
//
//	go run ./examples/logger -ca-cert certs/ca.crt -ca-key certs/ca.key
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"log/slog"
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

	// Attach the Logger interceptor.
	onReq, onResp := interceptor.Logger(slog.Default())
	handler.OnRequest(onReq)
	handler.OnResponse(onResp)

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
