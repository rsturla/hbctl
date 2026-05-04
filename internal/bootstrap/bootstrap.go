package bootstrap

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rsturla/hbctl/internal/pki"
)

const (
	tokenHashFile = "bootstrap-token-hash"
	consumedFile  = "bootstrap-consumed"
	maxAttempts   = 3
)

type Result struct {
	CACert     []byte
	ClientCert []byte
}

type Manager struct {
	mu       sync.Mutex
	tlsDir   string
	attempts int
}

func NewManager(tlsDir string) *Manager {
	return &Manager{tlsDir: tlsDir}
}

func (m *Manager) TLSDir() string {
	return m.tlsDir
}

func (m *Manager) Enabled() bool {
	_, err := os.Stat(filepath.Join(m.tlsDir, tokenHashFile))
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(m.tlsDir, consumedFile))
	return err != nil
}

func (m *Manager) Bootstrap(token string, csrPEM []byte, peerAddr string) (*Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.Enabled() {
		return nil, fmt.Errorf("bootstrap not available")
	}

	if m.attempts >= maxAttempts {
		m.consume("locked out after too many failed attempts")
		return nil, fmt.Errorf("bootstrap locked: too many failed attempts")
	}

	storedHash, err := os.ReadFile(filepath.Join(m.tlsDir, tokenHashFile))
	if err != nil {
		return nil, fmt.Errorf("read token hash: %w", err)
	}
	defer clear(storedHash)

	hashStr := strings.TrimSpace(string(storedHash))
	hashStr = strings.TrimPrefix(hashStr, "sha256:")
	expected, err := hex.DecodeString(hashStr)
	if err != nil {
		return nil, fmt.Errorf("decode token hash: %w", err)
	}
	defer clear(expected)

	actual := sha256.Sum256([]byte(token))
	defer clear(actual[:])
	if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
		m.attempts++
		remaining := maxAttempts - m.attempts
		slog.Warn("bootstrap auth failed",
			"peer", peerAddr,
			"attempt", m.attempts,
			"remaining", remaining,
		)
		if m.attempts >= maxAttempts {
			m.consume("locked out after too many failed attempts")
		}
		return nil, fmt.Errorf("bootstrap authentication failed")
	}

	if len(csrPEM) == 0 {
		return nil, fmt.Errorf("CSR required")
	}

	caCert, err := os.ReadFile(filepath.Join(m.tlsDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	clientCert, err := pki.SignCSR(m.tlsDir, csrPEM)
	if err != nil {
		return nil, fmt.Errorf("sign CSR: %w", err)
	}

	block, _ := pem.Decode(clientCert)
	if block == nil {
		m.consume("CSR signing produced invalid cert")
		return nil, fmt.Errorf("internal error: invalid signed certificate")
	}
	cert, _ := x509.ParseCertificate(block.Bytes)

	m.consume("consumed")

	slog.Info("bootstrap successful",
		"peer", peerAddr,
		"client_cn", cert.Subject.CommonName,
		"client_serial", cert.SerialNumber.String(),
		"client_expiry", cert.NotAfter.Format(time.RFC3339),
	)

	return &Result{
		CACert:     caCert,
		ClientCert: clientCert,
	}, nil
}

func (m *Manager) consume(reason string) {
	path := filepath.Join(m.tlsDir, consumedFile)
	os.WriteFile(path, []byte(reason+"\n"), 0o600)
	os.Remove(filepath.Join(m.tlsDir, tokenHashFile))
	slog.Info("bootstrap token consumed", "reason", reason)
}

func CAFingerprint(tlsDir string) (string, error) {
	caPEM, err := os.ReadFile(filepath.Join(tlsDir, "ca.crt"))
	if err != nil {
		return "", fmt.Errorf("read CA cert: %w", err)
	}

	block, _ := pem.Decode(caPEM)
	if block == nil {
		return "", fmt.Errorf("decode CA cert PEM")
	}

	h := sha256.Sum256(block.Bytes)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

func ServerFingerprint(tlsDir string) (string, error) {
	certPEM, err := os.ReadFile(filepath.Join(tlsDir, "server.crt"))
	if err != nil {
		return "", fmt.Errorf("read server cert: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("decode server cert PEM")
	}

	h := sha256.Sum256(block.Bytes)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

func WriteTokenHash(tlsDir, token string) error {
	h := sha256.Sum256([]byte(token))
	hash := "sha256:" + hex.EncodeToString(h[:])
	path := filepath.Join(tlsDir, tokenHashFile)
	return os.WriteFile(path, []byte(hash+"\n"), 0o600)
}
