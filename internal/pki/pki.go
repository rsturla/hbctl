package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	caFile         = "ca.crt"
	caKeyFile      = "ca.key"
	serverCertFile = "server.crt"
	serverKeyFile  = "server.key"
)

func Bootstrap(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create pki dir: %w", err)
	}

	caPath := filepath.Join(dir, caFile)
	if _, err := os.Stat(caPath); err == nil {
		return nil
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject: pkix.Name{
			Organization: []string{"hummingbird"},
			CommonName:   "hummingbird-ca",
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}

	if err := writePEM(caPath, "CERTIFICATE", caCertDER); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	defer clear(caKeyDER)
	if err := writePEM(filepath.Join(dir, caKeyFile), "EC PRIVATE KEY", caKeyDER); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}

	dnsNames, ips := discoverSANs()

	serverTemplate := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject: pkix.Name{
			Organization: []string{"hummingbird"},
			CommonName:   "hb-agent",
		},
		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create server cert: %w", err)
	}

	if err := writePEM(filepath.Join(dir, serverCertFile), "CERTIFICATE", serverCertDER); err != nil {
		return fmt.Errorf("write server cert: %w", err)
	}
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return fmt.Errorf("marshal server key: %w", err)
	}
	defer clear(serverKeyDER)
	if err := writePEM(filepath.Join(dir, serverKeyFile), "EC PRIVATE KEY", serverKeyDER); err != nil {
		return fmt.Errorf("write server key: %w", err)
	}

	return nil
}

func LoadServerTLS(dir string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(dir, serverCertFile),
		filepath.Join(dir, serverKeyFile),
	)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}

	caPEM, err := os.ReadFile(filepath.Join(dir, caFile))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func GenerateClientCert(dir, cn string) (certPEM, keyPEM []byte, err error) {
	caCertPEM, err := os.ReadFile(filepath.Join(dir, caFile))
	if err != nil {
		return nil, nil, fmt.Errorf("read CA cert: %w", err)
	}
	caKeyPEM, err := os.ReadFile(filepath.Join(dir, caKeyFile))
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key: %w", err)
	}
	defer clear(caKeyPEM)

	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return nil, nil, fmt.Errorf("decode CA cert PEM: no PEM block found")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, nil, fmt.Errorf("decode CA key PEM: no PEM block found")
	}
	defer clear(caKeyBlock.Bytes)
	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate client key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject: pkix.Name{
			Organization: []string{"hummingbird"},
			CommonName:   cn,
		},
		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create client cert: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal client key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})

	return certPEM, keyPEM, nil
}

func discoverSANs() (dnsNames []string, ips []net.IP) {
	dnsNames = []string{"localhost", "hb-agent"}
	ips = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

	if hostname, err := os.Hostname(); err == nil && hostname != "" && hostname != "localhost" {
		dnsNames = append(dnsNames, hostname)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return dnsNames, ips
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.IsLinkLocalUnicast() {
				continue
			}
			ips = append(ips, ipNet.IP)
		}
	}

	return dnsNames, ips
}

func SignCSR(dir string, csrPEM []byte) ([]byte, error) {
	caCertPEM, err := os.ReadFile(filepath.Join(dir, caFile))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	caKeyPEM, err := os.ReadFile(filepath.Join(dir, caKeyFile))
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	defer clear(caKeyPEM)

	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return nil, fmt.Errorf("decode CA cert PEM: no PEM block found")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, fmt.Errorf("decode CA key PEM: no PEM block found")
	}
	defer clear(caKeyBlock.Bytes)
	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}

	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil {
		return nil, fmt.Errorf("decode CSR PEM: no PEM block found")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject: pkix.Name{
			Organization: []string{"hummingbird"},
			CommonName:   fmt.Sprintf("bootstrap-%d", time.Now().UnixMilli()),
		},
		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

func GenerateCSR(cn string) (csrPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"hummingbird"},
			CommonName:   cn,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return csrPEM, keyPEM, nil
}

func newSerial() *big.Int {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return serial
}

func writePEM(path, pemType string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return pem.Encode(f, &pem.Block{Type: pemType, Bytes: der})
}
