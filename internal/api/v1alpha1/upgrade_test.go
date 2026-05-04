package v1alpha1

import (
	"context"
	"fmt"
	"testing"

	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"github.com/rsturla/hbctl/internal/system/bootc"
	"github.com/rsturla/hbctl/internal/system/systemd"
	"github.com/rsturla/hbctl/internal/upgrade"
)

type fakeBootcMgr struct {
	status      *bootc.Status
	statusErr   error
	switched    string
	switchErr   error
	rolledBack  bool
	rollbackErr error
}

func (f *fakeBootcMgr) Status(_ context.Context) (*bootc.Status, error) {
	return f.status, f.statusErr
}

func (f *fakeBootcMgr) Switch(_ context.Context, image string) error {
	f.switched = image
	if f.switchErr != nil {
		return f.switchErr
	}
	f.status.Staged = image
	return nil
}

func (f *fakeBootcMgr) Rollback(_ context.Context) error {
	f.rolledBack = true
	return f.rollbackErr
}

type fakeSystemdMgr struct {
	rebooted  bool
	rebootErr error
}

func (f *fakeSystemdMgr) ListUnits(_ context.Context) ([]systemd.UnitStatus, error) {
	return nil, nil
}

func (f *fakeSystemdMgr) UnitStatus(_ context.Context, _ string) (*systemd.UnitStatus, error) {
	return nil, nil
}

func (f *fakeSystemdMgr) Reboot(_ context.Context) error {
	f.rebooted = true
	return f.rebootErr
}

func (f *fakeSystemdMgr) StartUnit(_ context.Context, _ string) error   { return nil }
func (f *fakeSystemdMgr) StopUnit(_ context.Context, _ string) error    { return nil }
func (f *fakeSystemdMgr) RestartUnit(_ context.Context, _ string) error { return nil }

func newTestUpgradeServer(fb *fakeBootcMgr, fs *fakeSystemdMgr) *UpgradeServer {
	mgr := upgrade.NewManager(fb, fs)
	return NewUpgradeServer(mgr)
}

func TestUpgradeRPC(t *testing.T) {
	t.Parallel()

	fb := &fakeBootcMgr{
		status: &bootc.Status{
			Image:       "registry.example.com/os:v1.0.0",
			ImageDigest: "sha256:aaa",
		},
	}
	srv := newTestUpgradeServer(fb, &fakeSystemdMgr{})

	resp, err := srv.Upgrade(context.Background(), &pb.UpgradeRequest{
		Image: "registry.example.com/os:v1.1.0",
	})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}

	if resp.CurrentImage != "registry.example.com/os:v1.0.0" {
		t.Errorf("CurrentImage = %q", resp.CurrentImage)
	}
	if resp.StagedImage != "registry.example.com/os:v1.1.0" {
		t.Errorf("StagedImage = %q", resp.StagedImage)
	}
	if !resp.RebootRequired {
		t.Error("should require reboot after staging")
	}
}

func TestUpgradeRPC_EmptyImage(t *testing.T) {
	t.Parallel()

	srv := newTestUpgradeServer(
		&fakeBootcMgr{status: &bootc.Status{}},
		&fakeSystemdMgr{},
	)

	_, err := srv.Upgrade(context.Background(), &pb.UpgradeRequest{})
	if err == nil {
		t.Error("expected error for empty image")
	}
}

func TestUpgradeRPC_SwitchError(t *testing.T) {
	t.Parallel()

	srv := newTestUpgradeServer(
		&fakeBootcMgr{
			status:    &bootc.Status{Image: "current:v1"},
			switchErr: fmt.Errorf("image not found"),
		},
		&fakeSystemdMgr{},
	)

	_, err := srv.Upgrade(context.Background(), &pb.UpgradeRequest{Image: "bad:v2"})
	if err == nil {
		t.Error("expected error on switch failure")
	}
}

func TestRollbackRPC(t *testing.T) {
	t.Parallel()

	fb := &fakeBootcMgr{
		status: &bootc.Status{Image: "registry.example.com/os:v1.1.0"},
	}
	srv := newTestUpgradeServer(fb, &fakeSystemdMgr{})

	resp, err := srv.Rollback(context.Background(), &pb.RollbackRequest{})
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	if !fb.rolledBack {
		t.Error("rollback not called")
	}
	if resp.CurrentImage != "registry.example.com/os:v1.1.0" {
		t.Errorf("CurrentImage = %q", resp.CurrentImage)
	}
	if !resp.RebootRequired {
		t.Error("rollback should require reboot")
	}
}

func TestRollbackRPC_Error(t *testing.T) {
	t.Parallel()

	srv := newTestUpgradeServer(
		&fakeBootcMgr{
			status:      &bootc.Status{Image: "current:v1"},
			rollbackErr: fmt.Errorf("no previous deployment"),
		},
		&fakeSystemdMgr{},
	)

	_, err := srv.Rollback(context.Background(), &pb.RollbackRequest{})
	if err == nil {
		t.Error("expected error on rollback failure")
	}
}

func TestRebootRPC(t *testing.T) {
	t.Parallel()

	fs := &fakeSystemdMgr{}
	srv := newTestUpgradeServer(
		&fakeBootcMgr{status: &bootc.Status{}},
		fs,
	)

	_, err := srv.Reboot(context.Background(), &pb.RebootRequest{})
	if err != nil {
		t.Fatalf("Reboot: %v", err)
	}

	if !fs.rebooted {
		t.Error("reboot not called")
	}
}

func TestRebootRPC_Error(t *testing.T) {
	t.Parallel()

	srv := newTestUpgradeServer(
		&fakeBootcMgr{status: &bootc.Status{}},
		&fakeSystemdMgr{rebootErr: fmt.Errorf("not privileged")},
	)

	_, err := srv.Reboot(context.Background(), &pb.RebootRequest{})
	if err == nil {
		t.Error("expected error on reboot failure")
	}
}
