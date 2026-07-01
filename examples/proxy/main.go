// Command proxy is a minimal MITM HTTP/HTTPS proxy built on github.com/aomori446/mitm.
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

	server := &http.Server{
		Addr:    *addr,
		Handler: handler,
		// BaseContext ensures req.Context() is derived from the signal context,
		// so CONNECT tunnels are torn down promptly on shutdown.
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
