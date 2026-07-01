// Command genca generates a self-signed ECDSA CA certificate and private key
// for use with the MITM proxy.
//
// Usage:
//
//	go run ./cmd/genca                        # writes testdata/ca.crt and testdata/ca.key
//	go run ./cmd/genca -cert my.crt -key my.key
package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/aomori446/mitm"
)

func main() {
	certOut := flag.String("cert", "testdata/ca.crt", "output path for CA certificate")
	keyOut := flag.String("key", "testdata/ca.key", "output path for CA private key")
	flag.Parse()

	for _, p := range []string{*certOut, *keyOut} {
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			log.Fatalf("create dir: %v", err)
		}
	}

	if err := mitm.GenerateCA(*certOut, *keyOut); err != nil {
		log.Fatalf("generate CA: %v", err)
	}

	log.Printf("CA certificate written to %s", *certOut)
	log.Printf("CA private key  written to %s", *keyOut)
}
