// Command blocker demonstrates the Blocker interceptor with various response helpers.
//
// Usage:
//
//	go run ./examples/blocker -ca-cert testdata/ca.crt -ca-key testdata/ca.key
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
	"strings"
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

	// Block ad hosts by pattern, returning a content-appropriate empty response
	// (pixel for images, empty JS for scripts, etc.) instead of 403.
	handler.OnRequest(interceptor.BlockerWith(
		interceptor.RespondWithAuto(),
		"ads.example.com",
		"*.doubleclick.net",
	))

	// Block by custom match function — useful when host patterns are not enough.
	handler.OnRequest(interceptor.BlockerFunc(
		interceptor.RespondWithEmptyJS(),
		func(req *http.Request) bool {
			return strings.HasSuffix(req.URL.Path, "/analytics.js")
		},
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
