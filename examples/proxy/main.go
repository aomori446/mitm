// Command proxy demonstrates how to build a MITM HTTP/HTTPS proxy using
// github.com/aomori446/mitm, with a Logger interceptor attached.
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

	onReq, onResp := interceptor.Logger(slog.Default())
	handler.OnRequest(onReq)
	handler.OnResponse(onResp)

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
