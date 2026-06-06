// Command proxy is a reference implementation of a MITM HTTP/HTTPS proxy
// built on top of github.com/aomori446/mitm.
//
// Usage:
//
//	go run ./cmd/proxy
package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	
	"github.com/aomori446/mitm"
	"github.com/aomori446/mitm/cert"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()
	
	certMgr, err := cert.NewManager("certs/ca.crt", "certs/ca.key")
	if err != nil {
		log.Fatal(err)
	}
	
	handler := mitm.New(ctx, certMgr)
	
	server := &http.Server{Addr: ":8081", Handler: handler}
	
	go func() {
		<-ctx.Done()
		server.Shutdown(ctx)
	}()
	
	err = server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
