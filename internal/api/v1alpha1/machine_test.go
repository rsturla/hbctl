package v1alpha1

import (
	"context"
	"fmt"
	"runtime"
	"testing"

	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"github.com/rsturla/hbctl/internal/authn"
	"github.com/rsturla/hbctl/internal/authz"
	"github.com/rsturla/hbctl/internal/health"
	"github.com/rsturla/hbctl/internal/system/bootc"
)

type fakeHealthChecker struct {
	result *health.Result
	err    error
}

func (f *fakeHealthChecker) Check(_ context.Context) (*health.Result, error) {
	return f.result, f.err
}

type fakeBootcReader struct {
	status *bootc.Status
	err    error
}

func (f *fakeBootcReader) Status(_ context.Context) (*bootc.Status, error) {
	return f.status, f.err
}

func (f *fakeBootcReader) Switch(_ context.Context, _ string) error { return nil }
func (f *fakeBootcReader) Rollback(_ context.Context) error         { return nil }

func newTestMachineServer(h health.Checker, b bootc.Manager) *MachineServer {
	return NewMachineServer(Deps{Health: h, Bootc: b}, &authz.AllowAll{})
}

func TestVersion(t *testing.T) {
	t.Parallel()

	srv := newTestMachineServer(
		&fakeHealthChecker{},
		&fakeBootcReader{
			status: &bootc.Status{
				Image:   "registry.example.com/os:latest",
				Version: "1.0.0",
			},
		},
	)

	resp, err := srv.Version(authn.ContextWithIdentity(context.Background(), authn.Identity{Name: "test"}), &pb.VersionRequest{})
	if err != nil {
		t.Fatalf("Version: %v", err)
	}

	if resp.Version != version {
		t.Errorf("Version = %q, want %q", resp.Version, version)
	}
	if resp.GoVersion != runtime.Version() {
		t.Errorf("GoVersion = %q, want %q", resp.GoVersion, runtime.Version())
	}
	if resp.OsImage != "registry.example.com/os:latest" {
		t.Errorf("OsImage = %q", resp.OsImage)
	}
	if resp.OsVersion != "1.0.0" {
		t.Errorf("OsVersion = %q", resp.OsVersion)
	}
}

func TestVersion_NoBootc(t *testing.T) {
	t.Parallel()

	srv := newTestMachineServer(&fakeHealthChecker{}, nil)

	resp, err := srv.Version(authn.ContextWithIdentity(context.Background(), authn.Identity{Name: "test"}), &pb.VersionRequest{})
	if err != nil {
		t.Fatalf("Version: %v", err)
	}

	if resp.OsImage != "" {
		t.Errorf("OsImage = %q, want empty", resp.OsImage)
	}
	if resp.OsVersion != "" {
		t.Errorf("OsVersion = %q, want empty", resp.OsVersion)
	}
}

func TestVersion_BootcError(t *testing.T) {
	t.Parallel()

	srv := newTestMachineServer(
		&fakeHealthChecker{},
		&fakeBootcReader{err: fmt.Errorf("bootc not found")},
	)

	resp, err := srv.Version(authn.ContextWithIdentity(context.Background(), authn.Identity{Name: "test"}), &pb.VersionRequest{})
	if err != nil {
		t.Fatalf("Version should not fail on bootc error: %v", err)
	}

	if resp.Version != version {
		t.Errorf("Version = %q, want %q", resp.Version, version)
	}
	if resp.OsImage != "" {
		t.Errorf("OsImage should be empty on bootc error, got %q", resp.OsImage)
	}
}

func TestVersion_BootcStagedImage(t *testing.T) {
	t.Parallel()

	srv := newTestMachineServer(
		&fakeHealthChecker{},
		&fakeBootcReader{
			status: &bootc.Status{
				Image:   "registry.example.com/os:v1.0.0",
				Version: "1.0.0",
				Staged:  "registry.example.com/os:v1.1.0",
			},
		},
	)

	resp, err := srv.Version(authn.ContextWithIdentity(context.Background(), authn.Identity{Name: "test"}), &pb.VersionRequest{})
	if err != nil {
		t.Fatalf("Version: %v", err)
	}

	if resp.OsImage != "registry.example.com/os:v1.0.0" {
		t.Errorf("OsImage = %q, want running image", resp.OsImage)
	}
}

func TestVersion_AlwaysReturnsGoVersion(t *testing.T) {
	t.Parallel()

	srv := newTestMachineServer(&fakeHealthChecker{}, nil)
	resp, _ := srv.Version(authn.ContextWithIdentity(context.Background(), authn.Identity{Name: "test"}), &pb.VersionRequest{})

	if resp.GoVersion == "" {
		t.Error("GoVersion should never be empty")
	}
}

func TestHealth_Healthy(t *testing.T) {
	t.Parallel()

	srv := newTestMachineServer(
		&fakeHealthChecker{
			result: &health.Result{
				Status: health.Healthy,
				Checks: []health.CheckResult{
					{Name: "crio.service", Message: "running", Status: health.Healthy, Critical: true},
					{Name: "kubelet.service", Message: "running", Status: health.Healthy, Critical: true},
				},
			},
		},
		nil,
	)

	resp, err := srv.Health(authn.ContextWithIdentity(context.Background(), authn.Identity{Name: "test"}), &pb.HealthRequest{})
	if err != nil {
		t.Fatalf("Health: %v", err)
	}

	if resp.Status != pb.HealthStatus_HEALTH_STATUS_HEALTHY {
		t.Errorf("Status = %v, want HEALTHY", resp.Status)
	}
	if len(resp.Services) != 2 {
		t.Errorf("got %d services, want 2", len(resp.Services))
	}
}

func TestHealth_Unhealthy(t *testing.T) {
	t.Parallel()

	srv := newTestMachineServer(
		&fakeHealthChecker{
			result: &health.Result{
				Status: health.Unhealthy,
				Checks: []health.CheckResult{
					{Name: "services:kubelet.service", Status: health.Unhealthy, Message: "dead", Critical: true},
				},
			},
		},
		nil,
	)

	resp, err := srv.Health(authn.ContextWithIdentity(context.Background(), authn.Identity{Name: "test"}), &pb.HealthRequest{})
	if err != nil {
		t.Fatalf("Health: %v", err)
	}

	if resp.Status != pb.HealthStatus_HEALTH_STATUS_UNHEALTHY {
		t.Errorf("Status = %v, want UNHEALTHY", resp.Status)
	}
}

func TestHealth_CheckerError(t *testing.T) {
	t.Parallel()

	srv := newTestMachineServer(
		&fakeHealthChecker{
			err: fmt.Errorf("dbus connection refused"),
		},
		nil,
	)

	resp, err := srv.Health(authn.ContextWithIdentity(context.Background(), authn.Identity{Name: "test"}), &pb.HealthRequest{})
	if err != nil {
		t.Fatalf("Health RPC should not return error, got: %v", err)
	}

	if resp.Status != pb.HealthStatus_HEALTH_STATUS_UNHEALTHY {
		t.Errorf("Status on checker error = %v, want UNHEALTHY", resp.Status)
	}
	if len(resp.Services) != 0 {
		t.Errorf("Services on error = %d, want 0", len(resp.Services))
	}
}

func TestHealth_ServiceFieldMapping(t *testing.T) {
	t.Parallel()

	srv := newTestMachineServer(
		&fakeHealthChecker{
			result: &health.Result{
				Status: health.Unhealthy,
				Checks: []health.CheckResult{
					{Name: "services:crio.service", Message: "running", Status: health.Healthy, Critical: true},
					{Name: "services:kubelet.service", Status: health.Unhealthy, Message: "failed", Critical: true},
				},
			},
		},
		nil,
	)

	resp, _ := srv.Health(authn.ContextWithIdentity(context.Background(), authn.Identity{Name: "test"}), &pb.HealthRequest{})

	crio := resp.Services[0]
	if crio.Name != "services:crio.service" {
		t.Errorf("crio Name = %q", crio.Name)
	}
	if crio.State != "running" {
		t.Errorf("crio State = %q", crio.State)
	}
	if crio.SubState != "" {
		t.Errorf("crio SubState = %q", crio.SubState)
	}
	if !crio.Healthy {
		t.Error("crio should be healthy")
	}

	kubelet := resp.Services[1]
	if kubelet.Name != "services:kubelet.service" {
		t.Errorf("kubelet Name = %q", kubelet.Name)
	}
	if kubelet.State != "failed" {
		t.Errorf("kubelet State = %q", kubelet.State)
	}
	if kubelet.Healthy {
		t.Error("kubelet should not be healthy")
	}
}

func TestHealth_EmptyServices(t *testing.T) {
	t.Parallel()

	srv := newTestMachineServer(
		&fakeHealthChecker{
			result: &health.Result{
				Status:   health.Healthy,
			},
		},
		nil,
	)

	resp, err := srv.Health(authn.ContextWithIdentity(context.Background(), authn.Identity{Name: "test"}), &pb.HealthRequest{})
	if err != nil {
		t.Fatalf("Health: %v", err)
	}

	if resp.Status != pb.HealthStatus_HEALTH_STATUS_HEALTHY {
		t.Errorf("Status = %v, want HEALTHY", resp.Status)
	}
	if len(resp.Services) != 0 {
		t.Errorf("Services = %d, want 0", len(resp.Services))
	}
}

func TestHealth_StatusEnumAlignment(t *testing.T) {
	t.Parallel()

	if int32(health.Unknown) != int32(pb.HealthStatus_HEALTH_STATUS_UNKNOWN) {
		t.Errorf("Unknown mismatch: health=%d proto=%d", health.Unknown, pb.HealthStatus_HEALTH_STATUS_UNKNOWN)
	}
	if int32(health.Healthy) != int32(pb.HealthStatus_HEALTH_STATUS_HEALTHY) {
		t.Errorf("Healthy mismatch: health=%d proto=%d", health.Healthy, pb.HealthStatus_HEALTH_STATUS_HEALTHY)
	}
	if int32(health.Unhealthy) != int32(pb.HealthStatus_HEALTH_STATUS_UNHEALTHY) {
		t.Errorf("Unhealthy mismatch: health=%d proto=%d", health.Unhealthy, pb.HealthStatus_HEALTH_STATUS_UNHEALTHY)
	}
}
