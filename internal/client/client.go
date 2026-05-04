package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Config struct {
	Endpoint string
	TLSDir   string
}

func Connect(cfg Config) (pb.MachineServiceClient, *grpc.ClientConn, error) {
	tlsCfg, err := loadClientTLS(cfg.TLSDir)
	if err != nil {
		return nil, nil, fmt.Errorf("load TLS: %w", err)
	}

	conn, err := grpc.NewClient(
		cfg.Endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("connect: %w", err)
	}

	return pb.NewMachineServiceClient(conn), conn, nil
}

func loadClientTLS(dir string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read ca.crt: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse ca.crt")
	}

	cert, err := tls.LoadX509KeyPair(
		filepath.Join(dir, "client.crt"),
		filepath.Join(dir, "client.key"),
	)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
