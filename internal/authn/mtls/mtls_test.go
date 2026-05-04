package mtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestAuthenticate_ValidCert(t *testing.T) {
	t.Parallel()

	ctx := contextWithCert(t, "test-operator", []string{"hummingbird"})

	p := &Provider{}
	id, err := p.Authenticate(ctx)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if id.Name != "test-operator" {
		t.Errorf("Name = %q", id.Name)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "hummingbird" {
		t.Errorf("Groups = %v", id.Groups)
	}
	if id.Meta["provider"] != "mtls" {
		t.Errorf("Meta[provider] = %q", id.Meta["provider"])
	}
	if id.Meta["serial"] == "" {
		t.Error("Meta[serial] should not be empty")
	}
}

func TestAuthenticate_NoPeer(t *testing.T) {
	t.Parallel()

	p := &Provider{}
	_, err := p.Authenticate(context.Background())
	if err == nil {
		t.Error("expected error for missing peer")
	}
}

func TestAuthenticate_NoTLSInfo(t *testing.T) {
	t.Parallel()

	ctx := peer.NewContext(context.Background(), &peer.Peer{})
	p := &Provider{}
	_, err := p.Authenticate(ctx)
	if err == nil {
		t.Error("expected error for missing TLS info")
	}
}

func TestAuthenticate_NoVerifiedChains(t *testing.T) {
	t.Parallel()

	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: nil,
			},
		},
	})

	p := &Provider{}
	_, err := p.Authenticate(ctx)
	if err == nil {
		t.Error("expected error for no verified chains")
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	auth, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if auth.Name() != "mtls" {
		t.Errorf("Name = %q", auth.Name())
	}
}

func contextWithCert(t *testing.T, cn string, org []string) context.Context {
	t.Helper()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: org,
		},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, _ := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	clientCert, _ := x509.ParseCertificate(clientDER)

	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{clientCert, caCert}},
			},
		},
	})
}
