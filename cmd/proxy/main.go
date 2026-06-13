// Command proxy is a reference implementation of a MITM HTTP/HTTPS proxy
// built on top of github.com/aomori446/mitm.
//
// Usage:
//
//	go run ./cmd/proxy -ca-cert certs/ca.crt -ca-key certs/ca.key
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/aomori446/mitm"
	"github.com/aomori446/mitm/cert"
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

	handler := mitm.New(ctx, certMgr)

	server := &http.Server{Addr: *addr, Handler: handler}

	go func() {
		<-ctx.Done()
		server.Shutdown(ctx)
	}()

	err = server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
