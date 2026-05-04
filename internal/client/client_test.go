package client

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rsturla/hbctl/internal/pki"
)

func TestConnect_MissingCerts(t *testing.T) {
	t.Parallel()

	_, _, err := Connect(Config{Endpoint: "127.0.0.1:50000", TLSDir: "/nonexistent"})
	if err == nil {
		t.Error("expected error for missing certs")
	}
}

func TestConnect_MissingClientCert(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pki.Bootstrap(dir)

	_, _, err := Connect(Config{Endpoint: "127.0.0.1:50000", TLSDir: dir})
	if err == nil {
		t.Error("expected error for missing client.crt")
	}
}

func TestConnect_ValidCerts(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pki.Bootstrap(dir)

	certPEM, keyPEM, err := pki.GenerateClientCert(dir, "test")
	if err != nil {
		t.Fatalf("generate client cert: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "client.crt"), certPEM, 0o600)
	os.WriteFile(filepath.Join(dir, "client.key"), keyPEM, 0o600)

	c, conn, err := Connect(Config{Endpoint: "127.0.0.1:50000", TLSDir: dir})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.Close()

	if c == nil {
		t.Error("client should not be nil")
	}
}

func TestLoadClientTLS_MinVersion(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pki.Bootstrap(dir)

	certPEM, keyPEM, _ := pki.GenerateClientCert(dir, "test")
	os.WriteFile(filepath.Join(dir, "client.crt"), certPEM, 0o600)
	os.WriteFile(filepath.Join(dir, "client.key"), keyPEM, 0o600)

	tlsCfg, err := loadClientTLS(dir)
	if err != nil {
		t.Fatalf("loadClientTLS: %v", err)
	}

	if tlsCfg.MinVersion != 0x0304 {
		t.Errorf("MinVersion = %x, want TLS 1.3 (0x0304)", tlsCfg.MinVersion)
	}
}
