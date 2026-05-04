package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"

	apiv1 "github.com/rsturla/hbctl/internal/api/v1alpha1"
	"github.com/rsturla/hbctl/internal/authn"
	"github.com/rsturla/hbctl/internal/authz"
	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

type Server struct {
	grpcServer *grpc.Server
}

type Options struct {
	TLS             *tls.Config
	Deps            apiv1.Deps
	Auth            authn.Authenticator
	Authz           authz.Authorizer
	BootstrapActive bool
}

func NewServer(opts Options) *Server {
	if opts.BootstrapActive {
		opts.TLS.ClientAuth = tls.VerifyClientCertIfGiven
	}

	skipMethods := map[string]bool{}
	if opts.BootstrapActive {
		skipMethods[pb.MachineService_BootstrapAuth_FullMethodName] = true
		slog.Info("bootstrap endpoint active")
	}

	serverOpts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(opts.TLS)),
	}

	if opts.Auth != nil {
		serverOpts = append(serverOpts,
			grpc.ChainUnaryInterceptor(authn.UnaryInterceptor(opts.Auth, skipMethods)),
			grpc.ChainStreamInterceptor(authn.StreamInterceptor(opts.Auth, skipMethods)),
		)
		slog.Info("authentication enabled", "method", opts.Auth.Name())
	}

	if opts.Authz != nil {
		slog.Info("authorization enabled", "method", opts.Authz.Name())
	}

	gs := grpc.NewServer(serverOpts...)

	machine := apiv1.NewMachineServer(opts.Deps, opts.Authz)
	pb.RegisterMachineServiceServer(gs, machine)

	reflection.Register(gs)

	return &Server{grpcServer: gs}
}

func (s *Server) Serve(lis net.Listener) error {
	return s.grpcServer.Serve(lis)
}

func (s *Server) GracefulStop() {
	s.grpcServer.GracefulStop()
}

func Listen(ctx context.Context, addr string) (net.Listener, error) {
	lc := net.ListenConfig{}
	lis, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	slog.Info("gRPC server listening", "addr", lis.Addr().String())
	return lis, nil
}
