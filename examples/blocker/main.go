// Command blocker demonstrates the Blocker interceptor with various response helpers.
//
// Usage:
//
//	go run ./examples/blocker -ca-cert testdata/ca.crt -ca-key testdata/ca.key
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

	// Block ad hosts by pattern, returning a content-appropriate empty response
	// (pixel for images, empty JS for scripts, etc.) instead of 403.
	handler.UseRequest(middleware.BlockerWith(
		middleware.RespondWithAuto(),
		"ads.example.com",
		"*.doubleclick.net",
	))

	// Block by custom match function — useful when host patterns are not enough.
	handler.UseRequest(middleware.BlockerFunc(
		middleware.RespondWithEmptyJS(),
		func(req *http.Request) bool {
			return strings.HasSuffix(req.URL.Path, "/analytics.js")
		},
	))

	if err := handler.ListenAndServe(ctx, *addr); err != nil {
		log.Fatal(err)
	}
}
