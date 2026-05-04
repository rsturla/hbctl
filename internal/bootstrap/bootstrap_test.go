package bootstrap

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/rsturla/hbctl/internal/pki"
)

func setupBootstrap(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()

	if err := pki.Bootstrap(dir); err != nil {
		t.Fatalf("pki bootstrap: %v", err)
	}

	token := generateToken(t)
	if err := WriteTokenHash(dir, token); err != nil {
		t.Fatalf("write token hash: %v", err)
	}

	return dir, token
}

func generateToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func generateCSR(t *testing.T) []byte {
	t.Helper()
	csr, _, err := pki.GenerateCSR("test-client")
	if err != nil {
		t.Fatalf("generate CSR: %v", err)
	}
	return csr
}

func TestBootstrap_Success(t *testing.T) {
	dir, token := setupBootstrap(t)
	mgr := NewManager(dir)
	csr := generateCSR(t)

	if !mgr.Enabled() {
		t.Fatal("bootstrap should be enabled")
	}

	result, err := mgr.Bootstrap(token, csr, "10.0.0.1:54321")
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	if len(result.CACert) == 0 {
		t.Error("CACert empty")
	}
	if len(result.ClientCert) == 0 {
		t.Error("ClientCert empty")
	}
}

func TestBootstrap_CertValidAgainstCA(t *testing.T) {
	dir, token := setupBootstrap(t)
	mgr := NewManager(dir)

	csrPEM, keyPEM, err := pki.GenerateCSR("bootstrap-test")
	if err != nil {
		t.Fatalf("generate CSR: %v", err)
	}

	result, err := mgr.Bootstrap(token, csrPEM, "10.0.0.1:54321")
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// Verify the cert+key pair works
	if _, err := tls.X509KeyPair(result.ClientCert, keyPEM); err != nil {
		t.Fatalf("cert/key pair invalid: %v", err)
	}

	// Verify cert is signed by the CA
	block, _ := pem.Decode(result.ClientCert)
	cert, _ := x509.ParseCertificate(block.Bytes)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(result.CACert)

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("cert not valid against CA: %v", err)
	}
}

func TestBootstrap_ConsumesToken(t *testing.T) {
	dir, token := setupBootstrap(t)
	mgr := NewManager(dir)
	csr := generateCSR(t)

	_, err := mgr.Bootstrap(token, csr, "10.0.0.1:54321")
	if err != nil {
		t.Fatalf("first Bootstrap: %v", err)
	}

	if mgr.Enabled() {
		t.Error("bootstrap should be disabled after consumption")
	}

	_, err = mgr.Bootstrap(token, csr, "10.0.0.2:54321")
	if err == nil {
		t.Error("second Bootstrap should fail")
	}
}

func TestBootstrap_TokenHashDeleted(t *testing.T) {
	dir, token := setupBootstrap(t)
	mgr := NewManager(dir)

	_, _ = mgr.Bootstrap(token, generateCSR(t), "10.0.0.1:54321")

	if _, err := os.Stat(filepath.Join(dir, tokenHashFile)); !os.IsNotExist(err) {
		t.Error("token hash file should be deleted after consumption")
	}

	if _, err := os.Stat(filepath.Join(dir, consumedFile)); err != nil {
		t.Error("consumed marker should exist")
	}
}

func TestBootstrap_WrongToken(t *testing.T) {
	dir, _ := setupBootstrap(t)
	mgr := NewManager(dir)

	_, err := mgr.Bootstrap("wrong-token", generateCSR(t), "10.0.0.1:54321")
	if err == nil {
		t.Error("expected error for wrong token")
	}

	if !mgr.Enabled() {
		t.Error("bootstrap should still be enabled after 1 failed attempt")
	}
}

func TestBootstrap_GenericErrorMessage(t *testing.T) {
	dir, _ := setupBootstrap(t)
	mgr := NewManager(dir)

	_, err := mgr.Bootstrap("wrong", generateCSR(t), "10.0.0.1:54321")
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "bootstrap authentication failed" {
		t.Errorf("error should be generic, got: %q", err.Error())
	}
}

func TestBootstrap_RateLimiting(t *testing.T) {
	dir, _ := setupBootstrap(t)
	mgr := NewManager(dir)
	csr := generateCSR(t)

	for i := 0; i < maxAttempts; i++ {
		_, _ = mgr.Bootstrap("wrong", csr, "10.0.0.1:54321")
	}

	if mgr.Enabled() {
		t.Error("bootstrap should be disabled after max failed attempts")
	}

	_, err := mgr.Bootstrap("anything", csr, "10.0.0.1:54321")
	if err == nil {
		t.Error("expected error after lockout")
	}
}

func TestBootstrap_RateLimitDeletesHash(t *testing.T) {
	dir, _ := setupBootstrap(t)
	mgr := NewManager(dir)
	csr := generateCSR(t)

	for i := 0; i < maxAttempts; i++ {
		_, _ = mgr.Bootstrap("wrong", csr, "10.0.0.1:54321")
	}

	if _, err := os.Stat(filepath.Join(dir, tokenHashFile)); !os.IsNotExist(err) {
		t.Error("token hash should be deleted after lockout")
	}
}

func TestBootstrap_NotEnabled(t *testing.T) {
	dir := t.TempDir()
	_ = pki.Bootstrap(dir)
	mgr := NewManager(dir)

	if mgr.Enabled() {
		t.Error("bootstrap should not be enabled without token hash")
	}

	_, err := mgr.Bootstrap("any", generateCSR(t), "10.0.0.1:54321")
	if err == nil {
		t.Error("expected error when not enabled")
	}
}

func TestBootstrap_AlreadyConsumed(t *testing.T) {
	dir, token := setupBootstrap(t)
	mgr := NewManager(dir)

	_, _ = mgr.Bootstrap(token, generateCSR(t), "10.0.0.1:54321")

	mgr2 := NewManager(dir)
	if mgr2.Enabled() {
		t.Error("new manager should see consumed state")
	}
}

func TestBootstrap_EmptyCSR(t *testing.T) {
	dir, token := setupBootstrap(t)
	mgr := NewManager(dir)

	_, err := mgr.Bootstrap(token, nil, "10.0.0.1:54321")
	if err == nil {
		t.Error("expected error for empty CSR")
	}

	if !mgr.Enabled() {
		t.Error("bootstrap should still be enabled — empty CSR is not an auth failure")
	}
}

func TestBootstrap_InvalidCSR(t *testing.T) {
	dir, token := setupBootstrap(t)
	mgr := NewManager(dir)

	_, err := mgr.Bootstrap(token, []byte("not a csr"), "10.0.0.1:54321")
	if err == nil {
		t.Error("expected error for invalid CSR")
	}
}

func TestBootstrap_CorrectTokenAfterFailedAttempt(t *testing.T) {
	dir, token := setupBootstrap(t)
	mgr := NewManager(dir)
	csr := generateCSR(t)

	_, _ = mgr.Bootstrap("wrong", csr, "10.0.0.1:54321")

	result, err := mgr.Bootstrap(token, csr, "10.0.0.1:54321")
	if err != nil {
		t.Fatalf("correct token after failure: %v", err)
	}
	if len(result.ClientCert) == 0 {
		t.Error("should get cert with correct token")
	}
}

func TestCAFingerprint(t *testing.T) {
	dir := t.TempDir()
	_ = pki.Bootstrap(dir)

	fp, err := CAFingerprint(dir)
	if err != nil {
		t.Fatalf("CAFingerprint: %v", err)
	}

	if len(fp) != 7+64 {
		t.Errorf("fingerprint length = %d, want %d", len(fp), 7+64)
	}
	if fp[:7] != "sha256:" {
		t.Errorf("fingerprint prefix = %q", fp[:7])
	}

	fp2, _ := CAFingerprint(dir)
	if fp != fp2 {
		t.Error("fingerprint should be deterministic")
	}
}

func TestServerFingerprint(t *testing.T) {
	dir := t.TempDir()
	_ = pki.Bootstrap(dir)

	fp, err := ServerFingerprint(dir)
	if err != nil {
		t.Fatalf("ServerFingerprint: %v", err)
	}

	if len(fp) != 7+64 {
		t.Errorf("fingerprint length = %d, want %d", len(fp), 7+64)
	}

	caFP, _ := CAFingerprint(dir)
	if fp == caFP {
		t.Error("server fingerprint should differ from CA fingerprint")
	}
}

func TestCAFingerprint_MissingCA(t *testing.T) {
	_, err := CAFingerprint(t.TempDir())
	if err == nil {
		t.Error("expected error for missing CA")
	}
}

func TestWriteTokenHash(t *testing.T) {
	dir := t.TempDir()
	if err := WriteTokenHash(dir, "my-secret"); err != nil {
		t.Fatalf("WriteTokenHash: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, tokenHashFile))
	if len(data) == 0 {
		t.Fatal("token hash file empty")
	}

	info, _ := os.Stat(filepath.Join(dir, tokenHashFile))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestTLSDir(t *testing.T) {
	mgr := NewManager("/test/dir")
	if mgr.TLSDir() != "/test/dir" {
		t.Errorf("TLSDir = %q", mgr.TLSDir())
	}
}

func FuzzBootstrap_Token(f *testing.F) {
	f.Add("")
	f.Add("correct-token")
	f.Add("wrong")
	f.Add(string(make([]byte, 10000)))
	f.Add("\x00\x00\x00")
	f.Add("sha256:abcdef")
	f.Add("Bearer token")

	dir := f.TempDir()
	_ = pki.Bootstrap(dir)

	realToken := "the-real-token-for-fuzz-testing"
	_ = WriteTokenHash(dir, realToken)

	csrPEM, _, _ := pki.GenerateCSR("fuzz-client")

	f.Fuzz(func(t *testing.T, token string) {
		mgr := NewManager(dir)
		if !mgr.Enabled() {
			return
		}
		result, err := mgr.Bootstrap(token, csrPEM, "fuzz:0")
		if token == realToken {
			if err != nil {
				return
			}
			if result == nil {
				t.Fatal("nil result for correct token")
			}
		}
		// Must not panic regardless of input
	})
}

// FuzzBootstrap_CSR removed — CSR signing is fuzzed by FuzzSignCSR in internal/pki/
