package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	apiv1 "github.com/rsturla/hbctl/internal/api/v1alpha1"
	authnmtls "github.com/rsturla/hbctl/internal/authn/mtls"
	"github.com/rsturla/hbctl/internal/authz"
	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"github.com/rsturla/hbctl/internal/health"
	"github.com/rsturla/hbctl/internal/pki"
	"github.com/rsturla/hbctl/internal/system/bootc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type fakeChecker struct {
	mu     sync.Mutex
	result *health.Result
	err    error
	calls  int
}

func (f *fakeChecker) Check(_ context.Context) (*health.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.result, f.err
}

func (f *fakeChecker) CallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakeBootc struct {
	status *bootc.Status
	err    error
}

func (f *fakeBootc) Status(_ context.Context) (*bootc.Status, error) {
	return f.status, f.err
}

func (f *fakeBootc) Switch(_ context.Context, _ string) error { return nil }
func (f *fakeBootc) Rollback(_ context.Context) error         { return nil }

// testServer bundles a running gRPC server with its PKI dir for test reuse.
type testServer struct {
	srv  *Server
	lis  net.Listener
	dir  string
	stop func()
}

func newTestServer(t *testing.T, checker health.Checker, br bootc.StatusReader) *testServer {
	t.Helper()

	dir := t.TempDir()
	if err := pki.Bootstrap(dir); err != nil {
		t.Fatalf("pki bootstrap: %v", err)
	}

	serverTLS, err := pki.LoadServerTLS(dir)
	if err != nil {
		t.Fatalf("load server TLS: %v", err)
	}

	auth, _ := authnmtls.New(nil)
	srv := NewServer(Options{TLS: serverTLS, Deps: apiv1.Deps{Health: checker, Bootc: br}, Auth: auth, Authz: &authz.AllowAll{}})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go srv.Serve(lis)

	return &testServer{
		srv: srv,
		lis: lis,
		dir: dir,
		stop: func() {
			srv.GracefulStop()
		},
	}
}

func (ts *testServer) clientConn(t *testing.T) *grpc.ClientConn {
	t.Helper()

	certPEM, keyPEM, err := pki.GenerateClientCert(ts.dir, "test-client")
	if err != nil {
		t.Fatalf("generate client cert: %v", err)
	}

	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}

	caPEM, err := os.ReadFile(filepath.Join(ts.dir, "ca.crt"))
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
	}

	conn, err := grpc.NewClient(
		ts.lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestServerRoundTrip(t *testing.T) {
	ts := newTestServer(t, &fakeChecker{
		result: &health.Result{Status: health.Healthy},
	}, &fakeBootc{
		status: &bootc.Status{Image: "test:latest", Version: "1.0.0"},
	})
	defer ts.stop()

	conn := ts.clientConn(t)
	client := pb.NewMachineServiceClient(conn)

	vResp, err := client.Version(context.Background(), &pb.VersionRequest{})
	if err != nil {
		t.Fatalf("Version RPC: %v", err)
	}
	if vResp.OsImage != "test:latest" {
		t.Errorf("OsImage = %q, want test:latest", vResp.OsImage)
	}

	hResp, err := client.Health(context.Background(), &pb.HealthRequest{})
	if err != nil {
		t.Fatalf("Health RPC: %v", err)
	}
	if hResp.Status != pb.HealthStatus_HEALTH_STATUS_HEALTHY {
		t.Errorf("Health = %v, want HEALTHY", hResp.Status)
	}
}

func TestServer_NoClientCert_Rejected(t *testing.T) {
	ts := newTestServer(t, &fakeChecker{
		result: &health.Result{Status: health.Healthy},
	}, &fakeBootc{
		status: &bootc.Status{Image: "test:latest", Version: "1.0.0"},
	})
	defer ts.stop()

	caPEM, err := os.ReadFile(filepath.Join(ts.dir, "ca.crt"))
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	clientTLS := &tls.Config{
		RootCAs:    caPool,
		ServerName: "localhost",
	}

	conn, err := grpc.NewClient(
		ts.lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewMachineServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.Version(ctx, &pb.VersionRequest{})
	if err == nil {
		t.Error("expected error for missing client cert")
	}
}

func TestServer_WrongCA_Rejected(t *testing.T) {
	ts := newTestServer(t, &fakeChecker{
		result: &health.Result{Status: health.Healthy},
	}, &fakeBootc{
		status: &bootc.Status{Image: "test:latest", Version: "1.0.0"},
	})
	defer ts.stop()

	otherDir := t.TempDir()
	if err := pki.Bootstrap(otherDir); err != nil {
		t.Fatalf("bootstrap other CA: %v", err)
	}

	certPEM, keyPEM, err := pki.GenerateClientCert(otherDir, "rogue-client")
	if err != nil {
		t.Fatalf("generate rogue cert: %v", err)
	}

	rogueCert, _ := tls.X509KeyPair(certPEM, keyPEM)

	otherCAPEM, _ := os.ReadFile(filepath.Join(otherDir, "ca.crt"))
	serverCAPEM, _ := os.ReadFile(filepath.Join(ts.dir, "ca.crt"))

	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(serverCAPEM)
	rootPool.AppendCertsFromPEM(otherCAPEM)

	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{rogueCert},
		RootCAs:      rootPool,
		ServerName:   "localhost",
	}

	conn, err := grpc.NewClient(
		ts.lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewMachineServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.Version(ctx, &pb.VersionRequest{})
	if err == nil {
		t.Error("expected error for client cert signed by wrong CA")
	}
}

func TestServer_InsecureConnection_Rejected(t *testing.T) {
	ts := newTestServer(t, &fakeChecker{
		result: &health.Result{Status: health.Healthy},
	}, nil)
	defer ts.stop()

	conn, err := grpc.NewClient(
		ts.lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewMachineServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.Version(ctx, &pb.VersionRequest{})
	if err == nil {
		t.Error("expected error for insecure connection to TLS server")
	}
}

func TestServer_SelfSignedClientCert_Rejected(t *testing.T) {
	ts := newTestServer(t, &fakeChecker{
		result: &health.Result{Status: health.Healthy},
	}, nil)
	defer ts.stop()

	rogueKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	rogueTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "rogue"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	rogueDER, _ := x509.CreateCertificate(rand.Reader, rogueTmpl, rogueTmpl, &rogueKey.PublicKey, rogueKey)

	rogueCert := tls.Certificate{
		Certificate: [][]byte{rogueDER},
		PrivateKey:  rogueKey,
	}

	serverCAPEM, _ := os.ReadFile(filepath.Join(ts.dir, "ca.crt"))
	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(serverCAPEM)

	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{rogueCert},
		RootCAs:      rootPool,
		ServerName:   "localhost",
	}

	conn, err := grpc.NewClient(
		ts.lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewMachineServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.Version(ctx, &pb.VersionRequest{})
	if err == nil {
		t.Error("expected error for self-signed client cert")
	}
}

func TestServer_ConcurrentRPCs(t *testing.T) {
	checker := &fakeChecker{
		result: &health.Result{
			Status: health.Healthy,
			Checks: []health.CheckResult{
				{Name: "services:crio.service", Status: health.Healthy, Message: "running", Critical: true},
			},
		},
	}

	ts := newTestServer(t, checker, &fakeBootc{
		status: &bootc.Status{Image: "test:latest", Version: "1.0.0"},
	})
	defer ts.stop()

	conn := ts.clientConn(t)
	client := pb.NewMachineServiceClient(conn)

	const concurrency = 20
	var wg sync.WaitGroup
	errs := make(chan error, concurrency*2)

	for i := 0; i < concurrency; i++ {
		wg.Add(2)

		go func() {
			defer wg.Done()
			resp, err := client.Version(context.Background(), &pb.VersionRequest{})
			if err != nil {
				errs <- fmt.Errorf("Version: %w", err)
				return
			}
			if resp.OsImage != "test:latest" {
				errs <- fmt.Errorf("OsImage = %q", resp.OsImage)
			}
		}()

		go func() {
			defer wg.Done()
			resp, err := client.Health(context.Background(), &pb.HealthRequest{})
			if err != nil {
				errs <- fmt.Errorf("Health: %w", err)
				return
			}
			if resp.Status != pb.HealthStatus_HEALTH_STATUS_HEALTHY {
				errs <- fmt.Errorf("Health status = %v", resp.Status)
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

func TestServer_MultipleClientsIndependentCerts(t *testing.T) {
	ts := newTestServer(t, &fakeChecker{
		result: &health.Result{Status: health.Healthy},
	}, &fakeBootc{
		status: &bootc.Status{Image: "test:latest", Version: "1.0.0"},
	})
	defer ts.stop()

	for i := 0; i < 5; i++ {
		cn := fmt.Sprintf("client-%d", i)
		certPEM, keyPEM, err := pki.GenerateClientCert(ts.dir, cn)
		if err != nil {
			t.Fatalf("generate cert for %s: %v", cn, err)
		}

		clientCert, _ := tls.X509KeyPair(certPEM, keyPEM)
		caPEM, _ := os.ReadFile(filepath.Join(ts.dir, "ca.crt"))
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(caPEM)

		clientTLS := &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caPool,
			ServerName:   "localhost",
		}

		conn, err := grpc.NewClient(
			ts.lis.Addr().String(),
			grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
		)
		if err != nil {
			t.Fatalf("dial for %s: %v", cn, err)
		}

		client := pb.NewMachineServiceClient(conn)
		resp, err := client.Version(context.Background(), &pb.VersionRequest{})
		conn.Close()

		if err != nil {
			t.Errorf("Version for %s: %v", cn, err)
		}
		if resp.OsImage != "test:latest" {
			t.Errorf("OsImage for %s = %q", cn, resp.OsImage)
		}
	}
}

func TestServer_HealthRPCPassesServiceDetails(t *testing.T) {
	ts := newTestServer(t, &fakeChecker{
		result: &health.Result{
			Status: health.Unhealthy,
			Checks: []health.CheckResult{
				{Name: "services:crio.service", Status: health.Healthy, Message: "running", Critical: true},
				{Name: "services:kubelet.service", Status: health.Unhealthy, Message: "failed", Critical: true},
			},
		},
	}, nil)
	defer ts.stop()

	conn := ts.clientConn(t)
	client := pb.NewMachineServiceClient(conn)

	resp, err := client.Health(context.Background(), &pb.HealthRequest{})
	if err != nil {
		t.Fatalf("Health: %v", err)
	}

	if resp.Status != pb.HealthStatus_HEALTH_STATUS_UNHEALTHY {
		t.Errorf("Status = %v, want UNHEALTHY", resp.Status)
	}

	if len(resp.Services) != 2 {
		t.Fatalf("Services count = %d, want 2", len(resp.Services))
	}

	if resp.Services[0].Name != "services:crio.service" || !resp.Services[0].Healthy {
		t.Errorf("crio service = %+v", resp.Services[0])
	}
	if resp.Services[1].Name != "services:kubelet.service" || resp.Services[1].Healthy {
		t.Errorf("kubelet service = %+v", resp.Services[1])
	}
}

func TestServer_GracefulStopDrainsConnections(t *testing.T) {
	ts := newTestServer(t, &fakeChecker{
		result: &health.Result{Status: health.Healthy},
	}, &fakeBootc{
		status: &bootc.Status{Image: "test:latest", Version: "1.0.0"},
	})

	conn := ts.clientConn(t)
	client := pb.NewMachineServiceClient(conn)

	_, err := client.Version(context.Background(), &pb.VersionRequest{})
	if err != nil {
		t.Fatalf("Version before stop: %v", err)
	}

	ts.stop()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.Version(ctx, &pb.VersionRequest{})
	if err == nil {
		t.Error("expected error after GracefulStop")
	}
}

func TestListen(t *testing.T) {
	ctx := context.Background()

	lis, err := Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()

	addr := lis.Addr().String()
	if addr == "" {
		t.Error("listener address is empty")
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	if host != "127.0.0.1" {
		t.Errorf("host = %q, want 127.0.0.1", host)
	}
	if port == "0" {
		t.Error("port should be assigned, got 0")
	}
}

func TestListen_InvalidAddr(t *testing.T) {
	ctx := context.Background()

	_, err := Listen(ctx, "invalid:addr:too:many:colons")
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

func BenchmarkRPC_Version(b *testing.B) {
	dir := b.TempDir()
	if err := pki.Bootstrap(dir); err != nil {
		b.Fatalf("pki bootstrap: %v", err)
	}

	serverTLS, _ := pki.LoadServerTLS(dir)
	benchAuth, _ := authnmtls.New(nil)
	srv := NewServer(Options{TLS: serverTLS, Auth: benchAuth, Authz: &authz.AllowAll{}, Deps: apiv1.Deps{
		Health: &fakeChecker{result: &health.Result{Status: health.Healthy}},
		Bootc:  &fakeBootc{status: &bootc.Status{Image: "bench:latest", Version: "1.0.0"}},
	}})

	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(lis)
	defer srv.GracefulStop()

	certPEM, keyPEM, _ := pki.GenerateClientCert(dir, "bench-client")
	clientCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
	}

	conn, _ := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
	)
	defer conn.Close()

	client := pb.NewMachineServiceClient(conn)

	// Warm up connection
	client.Version(context.Background(), &pb.VersionRequest{})

	b.ResetTimer()
	for b.Loop() {
		_, err := client.Version(context.Background(), &pb.VersionRequest{})
		if err != nil {
			b.Fatal(err)
		}
	}
}
