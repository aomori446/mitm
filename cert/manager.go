// Package cert provides TLS certificate management for MITM proxies.
// It handles loading a CA certificate, forging per-host leaf certificates
// on demand, and caching them for reuse within the same process.
package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// Manager loads a CA certificate and key, then forges per-host leaf
// certificates on the fly for use in a MITM TLS handshake.
type Manager struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	cache  sync.Map // map[string]*cachedCert
}

// cachedCert pairs a forged leaf certificate with its cache expiry time.
type cachedCert struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

// NewManager loads a CA certificate and private key from PEM files and
// returns a Manager ready to forge leaf certificates.
func NewManager(certFile, keyFile string) (*Manager, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &Manager{
		caCert: caCert,
		caKey:  caKey,
	}, nil
}

// GetCert returns a forged leaf TLS certificate for host, creating and
// caching it on first access. Expired entries are evicted and re-forged.
func (m *Manager) GetCert(host string) (*tls.Certificate, error) {
	if v, ok := m.cache.Load(host); ok {
		if cc := v.(*cachedCert); time.Now().Before(cc.expiresAt) {
			return cc.cert, nil
		}
		m.cache.Delete(host)
	}

	cert, err := m.forgeCert(host)
	if err != nil {
		return nil, err
	}

	cc := &cachedCert{
		cert:      cert,
		expiresAt: time.Now().Add(23 * time.Hour), // evict 1 h before the cert's NotAfter
	}
	actual, _ := m.cache.LoadOrStore(host, cc)
	return actual.(*cachedCert).cert, nil
}

// TLSConfig returns a *tls.Config that dynamically forges a certificate for
// the SNI hostname presented by the client.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return m.GetCert(info.ServerName)
		},
	}
}

func (m *Manager) forgeCert(host string) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"mitm proxy"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, m.caCert, &priv.PublicKey, m.caKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
	return cert, nil
}

// GenerateCA creates a new self-signed ECDSA CA certificate and writes the
// PEM-encoded certificate and private key to certOut and keyOut respectively.
func GenerateCA(certOut, keyOut string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "MITM Proxy CA",
			Organization: []string{"mitm proxy"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certFile, err := os.Create(certOut)
	if err != nil {
		return err
	}
	defer certFile.Close()
	if err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	keyFile, err := os.Create(keyOut)
	if err != nil {
		return err
	}
	defer keyFile.Close()
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	return pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
