package mitm

import (
	"context"
	"io"
	"net"
	"net/http"

	"github.com/aomori446/mitm/interceptor"
	"golang.org/x/sync/errgroup"
)

type halfCloser interface {
	CloseWrite() error
}

// TCPRelay bidirectionally copies data between client and server until either
// side closes the connection or ctx is canceled.
func TCPRelay(ctx context.Context, client, server net.Conn) error {
	var errGroup errgroup.Group

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	halfClosed := make(chan struct{}, 2)
	defer close(halfClosed)
	go func() {
		<-halfClosed
		<-halfClosed
		cancel()
	}()

	errGroup.Go(func() error {
		<-ctx.Done()
		client.Close()
		server.Close()
		return ctx.Err()
	})

	// server → client
	errGroup.Go(func() error {
		_, err := io.Copy(client, server)
		if conn, ok := client.(halfCloser); ok {
			conn.CloseWrite()
		} else {
			client.Close()
		}
		halfClosed <- struct{}{}
		return err
	})

	// client → server
	errGroup.Go(func() error {
		_, err := io.Copy(server, client)
		if conn, ok := server.(halfCloser); ok {
			conn.CloseWrite()
		} else {
			server.Close()
		}
		halfClosed <- struct{}{}
		return err
	})

	return errGroup.Wait()
}

// writeErrorToConn writes a minimal HTTP error response directly to a raw connection.
// This is used after a CONNECT tunnel is established (when http.ResponseWriter is no
// longer available) to signal errors to the client instead of silently closing.
func writeErrorToConn(conn net.Conn, status int) {
	resp := interceptor.Response(status, "", http.NoBody)
	resp.Write(conn)
}
