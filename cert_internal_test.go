package mitm

import (
	"crypto/tls"
	"net"
	"path/filepath"
	"sync"
	"testing"
)

// newTestCertManager builds a CertManager over a throwaway CA.
func newTestCertManager(tb testing.TB) *CertManager {
	tb.Helper()
	dir := tb.TempDir()
	certFile := filepath.Join(dir, "ca.crt")
	keyFile := filepath.Join(dir, "ca.key")
	if err := GenerateCA(certFile, keyFile); err != nil {
		tb.Fatalf("generate CA: %v", err)
	}
	m, err := NewCertManager(certFile, keyFile)
	if err != nil {
		tb.Fatalf("new cert manager: %v", err)
	}
	return m
}

// stampede is how many connections arrive together for a host nobody has asked
// for yet. Browsers open several at once to a host they have just resolved.
const stampede = 16

// BenchmarkForgeCertStampede measures what a burst of first connections to one
// host costs. Signing is the expensive part, and the cache alone does not
// prevent the burst from signing the same certificate once per connection: it
// only decides which copy is kept.
func BenchmarkForgeCertStampede(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		m := newTestCertManager(b)
		hello := &tls.ClientHelloInfo{ServerName: "stampede.example.com"}
		b.StartTimer()

		var wg sync.WaitGroup
		wg.Add(stampede)
		for range stampede {
			go func() {
				defer wg.Done()
				if _, err := m.getCertificate(hello); err != nil {
					b.Errorf("getCertificate: %v", err)
				}
			}()
		}
		wg.Wait()
	}
}

// TestGetCertificateCachesPerHost checks that a host is served the same
// certificate every time, including when the requests race.
func TestGetCertificateCachesPerHost(t *testing.T) {
	m := newTestCertManager(t)
	hello := &tls.ClientHelloInfo{ServerName: "cached.example.com"}

	first, err := m.getCertificate(hello)
	if err != nil {
		t.Fatalf("getCertificate: %v", err)
	}

	certs := make([]*tls.Certificate, stampede)
	var wg sync.WaitGroup
	wg.Add(stampede)
	for i := range certs {
		go func() {
			defer wg.Done()
			c, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "cached.example.com"})
			if err != nil {
				t.Errorf("getCertificate: %v", err)
				return
			}
			certs[i] = c
		}()
	}
	wg.Wait()

	for i, c := range certs {
		if c != first {
			t.Fatalf("caller %d got a different certificate (%p) than the cached one (%p)", i, c, first)
		}
	}

	other, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"})
	if err != nil {
		t.Fatalf("getCertificate: %v", err)
	}
	if other == first {
		t.Error("two different hosts were served the same certificate")
	}
	if got := other.Leaf.DNSNames; len(got) != 1 || got[0] != "other.example.com" {
		t.Errorf("DNSNames = %v, want [other.example.com]", got)
	}
}

// TestGetCertificateWithoutSNI covers the clients that send no SNI. A client
// addressing an IP address is the common case — SNI carries host names only —
// and it used to be served a certificate with no subject alternative name at
// all, cached under the empty string, which no client that checks would accept.
func TestGetCertificateWithoutSNI(t *testing.T) {
	m := newTestCertManager(t)

	t.Run("falls-back-to-the-connect-target", func(t *testing.T) {
		cert, err := m.getCertificate(&tls.ClientHelloInfo{
			Conn: &tunnelConn{host: "origin.example.com:443"},
		})
		if err != nil {
			t.Fatalf("getCertificate: %v", err)
		}
		if got := cert.Leaf.DNSNames; len(got) != 1 || got[0] != "origin.example.com" {
			t.Errorf("DNSNames = %v, want [origin.example.com]", got)
		}
	})

	t.Run("an-ip-target-becomes-an-ip-san", func(t *testing.T) {
		cert, err := m.getCertificate(&tls.ClientHelloInfo{
			Conn: &tunnelConn{host: "192.0.2.10:443"},
		})
		if err != nil {
			t.Fatalf("getCertificate: %v", err)
		}
		if len(cert.Leaf.IPAddresses) != 1 || !cert.Leaf.IPAddresses[0].Equal(net.ParseIP("192.0.2.10")) {
			t.Errorf("IPAddresses = %v, want [192.0.2.10]", cert.Leaf.IPAddresses)
		}
		if len(cert.Leaf.DNSNames) != 0 {
			t.Errorf("DNSNames = %v, want none for an IP target", cert.Leaf.DNSNames)
		}
	})

	t.Run("no-name-at-all-is-an-error", func(t *testing.T) {
		cert, err := m.getCertificate(&tls.ClientHelloInfo{})
		if cert != nil || err == nil {
			t.Fatalf("got (%v, %v), want (nil, error)", cert, err)
		}
		if _, ok := m.cachedCerts.Load(""); ok {
			t.Error("a certificate was cached under the empty host name")
		}
	})
}

// TestCertManagerRotatesExpiringCerts checks the cache does not hand out a
// certificate that is about to expire.
func TestCertManagerRotatesExpiringCerts(t *testing.T) {
	m := newTestCertManager(t)
	const host = "expiring.example.com"

	fresh, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: host})
	if err != nil {
		t.Fatalf("getCertificate: %v", err)
	}

	// Age the cached copy past the one-hour margin.
	stale := *fresh
	leaf := *fresh.Leaf
	leaf.NotAfter = leaf.NotBefore
	stale.Leaf = &leaf
	m.cachedCerts.Store(host, &stale)

	got, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: host})
	if err != nil {
		t.Fatalf("getCertificate: %v", err)
	}
	if got == &stale {
		t.Error("an expiring certificate was served from the cache")
	}
}
