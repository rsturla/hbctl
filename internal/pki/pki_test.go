package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrap_GeneratesCerts(t *testing.T) {
	dir := t.TempDir()

	if err := Bootstrap(dir); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	for _, name := range []string{caFile, caKeyFile, serverCertFile, serverKeyFile} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
			continue
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s permissions = %o, want 0600", name, info.Mode().Perm())
		}
	}
}

func TestBootstrap_Idempotent(t *testing.T) {
	dir := t.TempDir()

	if err := Bootstrap(dir); err != nil {
		t.Fatalf("first Bootstrap: %v", err)
	}

	caBefore, _ := os.ReadFile(filepath.Join(dir, caFile))

	if err := Bootstrap(dir); err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}

	caAfter, _ := os.ReadFile(filepath.Join(dir, caFile))

	if string(caBefore) != string(caAfter) {
		t.Error("Bootstrap regenerated CA on second call")
	}
}

func TestBootstrap_CreatesNestedDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deep", "nested", "pki")

	if err := Bootstrap(dir); err != nil {
		t.Fatalf("Bootstrap with nested dir: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, caFile)); err != nil {
		t.Errorf("CA cert not created in nested dir: %v", err)
	}
}

func TestBootstrap_CACertProperties(t *testing.T) {
	dir := t.TempDir()
	if err := Bootstrap(dir); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	caPEM, _ := os.ReadFile(filepath.Join(dir, caFile))
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	if !ca.IsCA {
		t.Error("CA cert IsCA = false")
	}
	if ca.Subject.CommonName != "hummingbird-ca" {
		t.Errorf("CA CN = %q, want hummingbird-ca", ca.Subject.CommonName)
	}
	if ca.Subject.Organization[0] != "hummingbird" {
		t.Errorf("CA Org = %q, want hummingbird", ca.Subject.Organization[0])
	}
	if ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA missing KeyUsageCertSign")
	}
	if ca.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("CA missing KeyUsageCRLSign")
	}
	if ca.MaxPathLen != 1 {
		t.Errorf("CA MaxPathLen = %d, want 1", ca.MaxPathLen)
	}
}

func TestBootstrap_ServerCertProperties(t *testing.T) {
	dir := t.TempDir()
	if err := Bootstrap(dir); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	certPEM, _ := os.ReadFile(filepath.Join(dir, serverCertFile))
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}

	if cert.Subject.CommonName != "hb-agent" {
		t.Errorf("server CN = %q, want hb-agent", cert.Subject.CommonName)
	}

	if !containsString(cert.DNSNames, "localhost") {
		t.Error("DNSNames missing localhost")
	}
	if !containsString(cert.DNSNames, "hb-agent") {
		t.Error("DNSNames missing hb-agent")
	}
	if len(cert.DNSNames) < 2 {
		t.Errorf("DNSNames = %v, want at least localhost and hb-agent", cert.DNSNames)
	}

	if !containsIP(cert.IPAddresses, net.ParseIP("127.0.0.1")) {
		t.Error("IPAddresses missing 127.0.0.1")
	}
	if len(cert.IPAddresses) < 2 {
		t.Errorf("IPAddresses = %v, want at least 127.0.0.1 and ::1", cert.IPAddresses)
	}

	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Error("server cert missing ServerAuth ExtKeyUsage")
	}

	if cert.IsCA {
		t.Error("server cert should not be CA")
	}

	caPEM, _ := os.ReadFile(filepath.Join(dir, caFile))
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("server cert not valid against CA: %v", err)
	}
}

func TestLoadServerTLS(t *testing.T) {
	dir := t.TempDir()
	if err := Bootstrap(dir); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	tlsCfg, err := LoadServerTLS(dir)
	if err != nil {
		t.Fatalf("LoadServerTLS: %v", err)
	}

	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Error("expected RequireAndVerifyClientCert")
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Error("expected TLS 1.3 minimum")
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(tlsCfg.Certificates))
	}
}

func TestLoadServerTLS_MissingCert(t *testing.T) {
	dir := t.TempDir()

	_, err := LoadServerTLS(dir)
	if err == nil {
		t.Error("expected error for missing cert files")
	}
}

func TestLoadServerTLS_CorruptCA(t *testing.T) {
	dir := t.TempDir()
	if err := Bootstrap(dir); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	os.WriteFile(filepath.Join(dir, caFile), []byte("not a cert"), 0o600)

	_, err := LoadServerTLS(dir)
	if err == nil {
		t.Error("expected error for corrupt CA")
	}
}

func TestLoadServerTLS_CorruptServerCert(t *testing.T) {
	dir := t.TempDir()
	if err := Bootstrap(dir); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	os.WriteFile(filepath.Join(dir, serverCertFile), []byte("garbage"), 0o600)

	_, err := LoadServerTLS(dir)
	if err == nil {
		t.Error("expected error for corrupt server cert")
	}
}

func TestGenerateClientCert(t *testing.T) {
	dir := t.TempDir()
	if err := Bootstrap(dir); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	certPEM, keyPEM, err := GenerateClientCert(dir, "test-client")
	if err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode client cert PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}

	if cert.Subject.CommonName != "test-client" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "test-client")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Error("expected ClientAuth ExtKeyUsage")
	}
	if cert.IsCA {
		t.Error("client cert should not be CA")
	}

	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("client cert/key pair invalid: %v", err)
	}

	caPEM, _ := os.ReadFile(filepath.Join(dir, caFile))
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("client cert not valid against CA: %v", err)
	}
}

func TestGenerateClientCert_UniqueSerials(t *testing.T) {
	dir := t.TempDir()
	if err := Bootstrap(dir); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	serials := make(map[string]bool)
	for i := 0; i < 10; i++ {
		certPEM, _, err := GenerateClientCert(dir, "client")
		if err != nil {
			t.Fatalf("GenerateClientCert[%d]: %v", i, err)
		}
		block, _ := pem.Decode(certPEM)
		cert, _ := x509.ParseCertificate(block.Bytes)
		serial := cert.SerialNumber.String()
		if serials[serial] {
			t.Errorf("duplicate serial %s at iteration %d", serial, i)
		}
		serials[serial] = true
	}
}

func TestGenerateClientCert_MissingCA(t *testing.T) {
	dir := t.TempDir()

	_, _, err := GenerateClientCert(dir, "test")
	if err == nil {
		t.Error("expected error for missing CA")
	}
}

func TestGenerateClientCert_CorruptCAKey(t *testing.T) {
	dir := t.TempDir()
	if err := Bootstrap(dir); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	os.WriteFile(filepath.Join(dir, caKeyFile), []byte("not a key"), 0o600)

	_, _, err := GenerateClientCert(dir, "test")
	if err == nil {
		t.Error("expected error for corrupt CA key")
	}
}

func TestGenerateClientCert_CorruptCACert(t *testing.T) {
	dir := t.TempDir()
	if err := Bootstrap(dir); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// Write valid PEM wrapper but garbage DER inside
	badCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	os.WriteFile(filepath.Join(dir, caFile), badCert, 0o600)

	_, _, err := GenerateClientCert(dir, "test")
	if err == nil {
		t.Error("expected error for corrupt CA cert")
	}
}

func TestClientCertRejectedByDifferentCA(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	if err := Bootstrap(dir1); err != nil {
		t.Fatalf("Bootstrap dir1: %v", err)
	}
	if err := Bootstrap(dir2); err != nil {
		t.Fatalf("Bootstrap dir2: %v", err)
	}

	certPEM, _, err := GenerateClientCert(dir1, "client-from-ca1")
	if err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	ca2PEM, _ := os.ReadFile(filepath.Join(dir2, caFile))
	ca2Pool := x509.NewCertPool()
	ca2Pool.AppendCertsFromPEM(ca2PEM)

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     ca2Pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err == nil {
		t.Error("client cert from CA1 should not verify against CA2")
	}
}

func TestServerCertKeyAlgorithm(t *testing.T) {
	dir := t.TempDir()
	if err := Bootstrap(dir); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	keyPEM, _ := os.ReadFile(filepath.Join(dir, serverKeyFile))
	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse server key: %v", err)
	}

	if key.Curve != elliptic.P256() {
		t.Errorf("server key curve = %v, want P-256", key.Curve)
	}
}

func FuzzGenerateClientCert_CN(f *testing.F) {
	f.Add("admin")
	f.Add("hb-operator")
	f.Add("")
	f.Add("a]b[c{d}e")
	f.Add("CN=evil,O=attacker")
	f.Add(string(make([]byte, 1000)))

	dir := f.TempDir()
	if err := Bootstrap(dir); err != nil {
		f.Fatalf("Bootstrap: %v", err)
	}

	f.Fuzz(func(t *testing.T, cn string) {
		certPEM, keyPEM, err := GenerateClientCert(dir, cn)
		if err != nil {
			return
		}

		if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
			t.Errorf("generated cert/key pair invalid for CN=%q: %v", cn, err)
		}

		block, _ := pem.Decode(certPEM)
		if block == nil {
			t.Errorf("failed to decode PEM for CN=%q", cn)
			return
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Errorf("failed to parse cert for CN=%q: %v", cn, err)
			return
		}

		if cert.Subject.CommonName != cn {
			t.Errorf("CN = %q, want %q", cert.Subject.CommonName, cn)
		}
	})
}

func FuzzWritePEM(f *testing.F) {
	f.Add("CERTIFICATE", []byte{0x30, 0x82, 0x01})
	f.Add("EC PRIVATE KEY", []byte{0x30, 0x77})
	f.Add("RSA PRIVATE KEY", []byte{0xff, 0xfe, 0xfd})

	f.Fuzz(func(t *testing.T, pemType string, data []byte) {
		// PEM type must be uppercase letters, digits, and spaces per RFC 7468.
		// pem.Encode accepts anything but pem.Decode fails on control chars,
		// colons, hyphens, etc. Only test with valid PEM types.
		if pemType == "" {
			return
		}
		for _, c := range pemType {
			if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' ') {
				return
			}
		}

		path := filepath.Join(t.TempDir(), "test.pem")
		err := writePEM(path, pemType, data)
		if err != nil {
			return
		}

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read back: %v", err)
		}

		block, _ := pem.Decode(content)
		if block == nil {
			t.Fatalf("failed to decode written PEM for type=%q", pemType)
		}
		if block.Type != pemType {
			t.Errorf("PEM type = %q, want %q", block.Type, pemType)
		}
		if len(block.Bytes) != len(data) {
			t.Errorf("PEM data length = %d, want %d", len(block.Bytes), len(data))
		}
	})
}

func BenchmarkBootstrap(b *testing.B) {
	for b.Loop() {
		dir := b.TempDir()
		if err := Bootstrap(dir); err != nil {
			b.Fatalf("Bootstrap: %v", err)
		}
	}
}

func BenchmarkGenerateClientCert(b *testing.B) {
	dir := b.TempDir()
	if err := Bootstrap(dir); err != nil {
		b.Fatalf("Bootstrap: %v", err)
	}

	for b.Loop() {
		_, _, err := GenerateClientCert(dir, "bench-client")
		if err != nil {
			b.Fatalf("GenerateClientCert: %v", err)
		}
	}
}

func BenchmarkLoadServerTLS(b *testing.B) {
	dir := b.TempDir()
	if err := Bootstrap(dir); err != nil {
		b.Fatalf("Bootstrap: %v", err)
	}

	for b.Loop() {
		_, err := LoadServerTLS(dir)
		if err != nil {
			b.Fatalf("LoadServerTLS: %v", err)
		}
	}
}

func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func containsIP(ips []net.IP, target net.IP) bool {
	for _, ip := range ips {
		if ip.Equal(target) {
			return true
		}
	}
	return false
}

func TestDiscoverSANs(t *testing.T) {
	dnsNames, ips := discoverSANs()

	if !containsString(dnsNames, "localhost") {
		t.Error("missing localhost")
	}
	if !containsString(dnsNames, "hb-agent") {
		t.Error("missing hb-agent")
	}
	if !containsIP(ips, net.ParseIP("127.0.0.1")) {
		t.Error("missing 127.0.0.1")
	}
	if len(ips) < 3 {
		t.Logf("only %d IPs discovered (may be expected in CI): %v", len(ips), ips)
	}

	hostname, _ := os.Hostname()
	if hostname != "" && hostname != "localhost" {
		if !containsString(dnsNames, hostname) {
			t.Errorf("missing hostname %q in DNSNames %v", hostname, dnsNames)
		}
	}
}

func TestSignCSR(t *testing.T) {
	dir := t.TempDir()
	if err := Bootstrap(dir); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	csrPEM, keyPEM, err := GenerateCSR("test-csr-client")
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}

	certPEM, err := SignCSR(dir, csrPEM)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}

	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("cert/key pair invalid: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	if !strings.HasPrefix(cert.Subject.CommonName, "bootstrap-") {
		t.Errorf("CN = %q, want bootstrap-*", cert.Subject.CommonName)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Error("missing ClientAuth ExtKeyUsage")
	}

	caPEM, _ := os.ReadFile(filepath.Join(dir, caFile))
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("signed cert not valid against CA: %v", err)
	}
}

func TestSignCSR_InvalidCSR(t *testing.T) {
	dir := t.TempDir()
	Bootstrap(dir)

	_, err := SignCSR(dir, []byte("garbage"))
	if err == nil {
		t.Error("expected error for garbage CSR")
	}
}

func TestSignCSR_MissingCA(t *testing.T) {
	_, err := SignCSR(t.TempDir(), []byte("anything"))
	if err == nil {
		t.Error("expected error for missing CA")
	}
}

func TestGenerateCSR(t *testing.T) {
	csrPEM, keyPEM, err := GenerateCSR("my-client")
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}

	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		t.Fatal("invalid CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if csr.Subject.CommonName != "my-client" {
		t.Errorf("CSR CN = %q", csr.Subject.CommonName)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		t.Fatal("invalid key PEM")
	}
}

func FuzzSignCSR(f *testing.F) {
	validCSR, _, _ := GenerateCSR("valid")

	f.Add(validCSR)
	f.Add([]byte("not a csr"))
	f.Add([]byte{})
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----"))
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----"))
	f.Add([]byte{0x30, 0x82, 0x01, 0x00})
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"))

	dir := f.TempDir()
	if err := Bootstrap(dir); err != nil {
		f.Fatalf("Bootstrap: %v", err)
	}

	f.Fuzz(func(t *testing.T, csrPEM []byte) {
		certPEM, err := SignCSR(dir, csrPEM)
		if err != nil {
			return
		}
		if len(certPEM) == 0 {
			t.Fatal("empty cert from successful SignCSR")
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			t.Fatal("SignCSR returned invalid PEM")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			t.Fatalf("SignCSR produced unparseable cert: %v", err)
		}
	})
}

func FuzzGenerateCSR(f *testing.F) {
	f.Add("admin")
	f.Add("")
	f.Add("CN=evil,O=attacker")
	f.Add(string(make([]byte, 5000)))
	f.Add("\x00\xff\xfe")

	f.Fuzz(func(t *testing.T, cn string) {
		csrPEM, keyPEM, err := GenerateCSR(cn)
		if err != nil {
			return
		}
		if len(csrPEM) == 0 || len(keyPEM) == 0 {
			t.Fatal("empty output from GenerateCSR")
		}
		csrBlock, _ := pem.Decode(csrPEM)
		if csrBlock == nil {
			t.Fatal("invalid CSR PEM")
		}
		csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
		if err != nil {
			t.Fatalf("invalid CSR: %v", err)
		}
		if err := csr.CheckSignature(); err != nil {
			t.Fatalf("CSR signature invalid: %v", err)
		}
	})
}

// Verify that a self-signed keypair generated outside Bootstrap is rejected as a client.
func TestSelfSignedClientRejectedByCA(t *testing.T) {
	dir := t.TempDir()
	if err := Bootstrap(dir); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	rogueKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rogueCert := &x509.Certificate{
		SerialNumber: newSerial(),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	rogueDER, err := x509.CreateCertificate(rand.Reader, rogueCert, rogueCert, &rogueKey.PublicKey, rogueKey)
	if err != nil {
		t.Fatalf("create rogue cert: %v", err)
	}

	cert, _ := x509.ParseCertificate(rogueDER)
	caPEM, _ := os.ReadFile(filepath.Join(dir, caFile))
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err == nil {
		t.Error("self-signed rogue cert should not verify against agent CA")
	}
}
