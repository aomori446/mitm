package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type CertManager struct {
	caCert      *x509.Certificate
	caKey       *ecdsa.PrivateKey
	leafKey     *ecdsa.PrivateKey
	cachedCerts sync.Map // map[host string]*tls.Certificate
	forging     singleflight.Group

	tlsConfig *tls.Config
}

func NewCertManager(certFile, keyFile string) (*CertManager, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	m := &CertManager{
		caCert:  caCert,
		caKey:   caKey,
		leafKey: leafKey,
	}
	m.tlsConfig = &tls.Config{
		GetCertificate: m.getCertificate,
		// Offer h2 first. A client that takes it multiplexes its concurrent
		// requests over this one tunnel and compresses their headers, instead
		// of opening a handful of tunnels that each repeat every header in
		// full. Clients that do not speak it, or do not use ALPN at all, land
		// on http/1.1 and are served by the HTTP/1.1 loop as before.
		NextProtos: []string{"h2", "http/1.1"},
	}
	return m, nil
}

// TLSConfig returns the [tls.Config] used for every intercepted client
// connection. The same value is returned on every call, deliberately: a
// [tls.Config] owns the session ticket keys, so handing out a fresh config per
// connection leaves every client unable to decrypt the ticket it was issued and
// forces a full handshake every time. Callers must treat it as read-only.
func (m *CertManager) TLSConfig() *tls.Config {
	return m.tlsConfig
}

func (m *CertManager) getCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := certificateNameFor(info)
	if host == "" {
		// Nothing to put in the certificate. One carrying neither a subject
		// alternative name nor a usable common name is rejected by every client
		// that checks, so fail the handshake and say why rather than cache a
		// certificate that cannot work.
		return nil, errors.New("mitm: no server name from SNI or from the CONNECT target")
	}

	if cert, ok := m.cachedCert(host); ok {
		return cert, nil
	}

	// Forge once per host however many connections arrive together. A browser
	// opens several at a time to a host it has just resolved, and without this
	// each of them signs its own copy of the same certificate before one of
	// them wins the race to store it.
	v, err, _ := m.forging.Do(host, func() (any, error) {
		if cert, ok := m.cachedCert(host); ok {
			return cert, nil
		}
		cert, err := m.forgeCert(host)
		if err != nil {
			return nil, err
		}
		m.cachedCerts.Store(host, cert)
		return cert, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*tls.Certificate), nil
}

// certificateNameFor picks the name to issue a certificate for. SNI is the
// normal source, but a client addressing an IP address does not send SNI at
// all — SNI carries host names only — so fall back to the authority from the
// CONNECT request, which [tunnelConn] carries down to here.
func certificateNameFor(info *tls.ClientHelloInfo) string {
	if info.ServerName != "" {
		return info.ServerName
	}
	tc, ok := info.Conn.(*tunnelConn)
	if !ok {
		return ""
	}
	if host, _, err := net.SplitHostPort(tc.host); err == nil {
		return host
	}
	return tc.host
}

// cachedCert returns the stored certificate for host while it has more than an
// hour left to run, so that a connection is never handed one about to expire.
func (m *CertManager) cachedCert(host string) (*tls.Certificate, bool) {
	v, ok := m.cachedCerts.Load(host)
	if !ok {
		return nil, false
	}
	cert := v.(*tls.Certificate)
	if time.Now().Add(time.Hour).Before(cert.Leaf.NotAfter) {
		return cert, true
	}
	m.cachedCerts.Delete(host)
	return nil, false
}

func (m *CertManager) forgeCert(host string) (*tls.Certificate, error) {
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

	certDER, err := x509.CreateCertificate(rand.Reader, template, m.caCert, &m.leafKey.PublicKey, m.caKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  m.leafKey,
		Leaf:        template,
	}
	return cert, nil
}

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
