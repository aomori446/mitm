// Command dump demonstrates the Dump interceptor, which prints every
// proxied request and response in HTTP/1.1 wire format to stderr.
//
// Usage:
//
//	go run ./examples/dump -ca-cert testdata/ca.crt -ca-key testdata/ca.key
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/aomori446/mitm"
	"github.com/aomori446/mitm/middleware"
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

	// Dump every request and response to stderr.
	onReq, onResp := middleware.Dump(os.Stderr)
	handler.UseRequest(onReq)
	handler.UseResponse(onResp)

	if err := handler.ListenAndServe(ctx, *addr); err != nil {
		log.Fatal(err)
	}
}
