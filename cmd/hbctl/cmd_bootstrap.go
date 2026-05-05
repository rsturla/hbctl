package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/rsturla/hbctl/internal/cli"
	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"github.com/rsturla/hbctl/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type bootstrapCmd struct{}

func (c *bootstrapCmd) Name() string { return "bootstrap" }
func (c *bootstrapCmd) Help() string { return "Bootstrap mTLS credentials from a node" }

func (c *bootstrapCmd) Run(g cli.Globals, args []string) error {
	fs := cli.Flags("bootstrap")
	token := fs.String("token", "", "bootstrap token")
	fingerprint := fs.String("ca-fingerprint", "", "expected CA fingerprint sha256:<hex>")
	outputDir := fs.String("output-dir", "", "directory to write certs")
	_ = fs.Parse(args)

	if *token == "" || *fingerprint == "" || *outputDir == "" {
		return fmt.Errorf("usage: hbctl bootstrap --token <token> --ca-fingerprint sha256:<hex> --output-dir <dir>")
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: verifyFingerprint(*fingerprint),
	}
	conn, err := grpc.NewClient(g.Endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close() }()

	hostname, _ := os.Hostname()
	cn := fmt.Sprintf("hbctl-%s", hostname)
	csrPEM, keyPEM, err := pki.GenerateCSR(cn)
	if err != nil {
		return fmt.Errorf("generate CSR: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := pb.NewMachineServiceClient(conn).BootstrapAuth(ctx, &pb.BootstrapAuthRequest{Token: *token, Csr: csrPEM})
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}

	if err := os.MkdirAll(*outputDir, 0o700); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	for name, data := range map[string][]byte{"ca.crt": resp.CaCert, "client.crt": resp.ClientCert, "client.key": keyPEM} {
		perm := os.FileMode(0o600)
		if name == "ca.crt" {
			perm = 0o644
		}
		if err := os.WriteFile(*outputDir+"/"+name, data, perm); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}

	fmt.Printf("Bootstrap successful\n  CA fingerprint: %s\n  Certs written: %s/\n\n", resp.CaFingerprint, *outputDir)
	fmt.Printf("Usage:\n  hbctl --endpoint %s --tls-dir %s version\n", g.Endpoint, *outputDir)
	return nil
}

type genTokenCmd struct{}

func (c *genTokenCmd) Name() string { return "gen-token" }
func (c *genTokenCmd) Help() string { return "Generate a bootstrap token and its hash" }

func (c *genTokenCmd) Run(_ cli.Globals, _ []string) error {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("generate random: %w", err)
	}
	token := hex.EncodeToString(b)
	h := sha256.Sum256([]byte(token))
	hash := "sha256:" + hex.EncodeToString(h[:])

	fmt.Printf("Token: %s\nHash:  %s\n\nOn the node:\n  echo '%s' > /var/lib/hummingbird/pki/bootstrap-token-hash\n", token, hash, hash)
	return nil
}

func verifyFingerprint(expected string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("server presented no certificate")
		}
		for _, raw := range rawCerts {
			h := sha256.Sum256(raw)
			if "sha256:"+hex.EncodeToString(h[:]) == expected {
				return nil
			}
		}
		h := sha256.Sum256(rawCerts[0])
		return fmt.Errorf("fingerprint mismatch:\n  expected: %s\n  got:      sha256:%s", expected, hex.EncodeToString(h[:]))
	}
}
