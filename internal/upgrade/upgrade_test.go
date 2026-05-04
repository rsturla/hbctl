package upgrade

import (
	"context"
	"fmt"
	"testing"

	"github.com/rsturla/hbctl/internal/system/bootc"
	"github.com/rsturla/hbctl/internal/system/systemd"
)

type fakeBootc struct {
	status    *bootc.Status
	statusErr error
	switched  string
	switchErr error
	rolledBack bool
	rollbackErr error
}

func (f *fakeBootc) Status(_ context.Context) (*bootc.Status, error) {
	return f.status, f.statusErr
}

func (f *fakeBootc) Switch(_ context.Context, image string) error {
	f.switched = image
	if f.switchErr != nil {
		return f.switchErr
	}
	f.status.Staged = image
	return nil
}

func (f *fakeBootc) Rollback(_ context.Context) error {
	f.rolledBack = true
	return f.rollbackErr
}

type fakeSystemd struct {
	rebooted bool
	rebootErr error
	units    []systemd.UnitStatus
	status   *systemd.UnitStatus
	err      error
}

func (f *fakeSystemd) ListUnits(_ context.Context) ([]systemd.UnitStatus, error) {
	return f.units, f.err
}

func (f *fakeSystemd) UnitStatus(_ context.Context, _ string) (*systemd.UnitStatus, error) {
	return f.status, f.err
}

func (f *fakeSystemd) Reboot(_ context.Context) error {
	f.rebooted = true
	return f.rebootErr
}

func (f *fakeSystemd) StartUnit(_ context.Context, _ string) error   { return nil }
func (f *fakeSystemd) StopUnit(_ context.Context, _ string) error    { return nil }
func (f *fakeSystemd) RestartUnit(_ context.Context, _ string) error { return nil }

func TestUpgrade(t *testing.T) {
	t.Parallel()

	fb := &fakeBootc{
		status: &bootc.Status{
			Image:       "registry.example.com/os:v1.0.0",
			ImageDigest: "sha256:aaa",
		},
	}
	mgr := NewManager(fb, &fakeSystemd{})

	result, err := mgr.Upgrade(context.Background(), "registry.example.com/os:v1.1.0")
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}

	if fb.switched != "registry.example.com/os:v1.1.0" {
		t.Errorf("switched = %q", fb.switched)
	}
	if result.StagedImage != "registry.example.com/os:v1.1.0" {
		t.Errorf("StagedImage = %q", result.StagedImage)
	}
	if result.CurrentImage != "registry.example.com/os:v1.0.0" {
		t.Errorf("CurrentImage = %q", result.CurrentImage)
	}
}

func TestUpgrade_EmptyImage(t *testing.T) {
	t.Parallel()

	mgr := NewManager(&fakeBootc{status: &bootc.Status{}}, &fakeSystemd{})

	_, err := mgr.Upgrade(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty image")
	}
}

func TestUpgrade_SwitchError(t *testing.T) {
	t.Parallel()

	fb := &fakeBootc{
		status:    &bootc.Status{Image: "current:v1"},
		switchErr: fmt.Errorf("pull failed"),
	}
	mgr := NewManager(fb, &fakeSystemd{})

	_, err := mgr.Upgrade(context.Background(), "new:v2")
	if err == nil {
		t.Error("expected error on switch failure")
	}
}

func TestUpgrade_StatusError(t *testing.T) {
	t.Parallel()

	fb := &fakeBootc{statusErr: fmt.Errorf("bootc not found")}
	mgr := NewManager(fb, &fakeSystemd{})

	_, err := mgr.Upgrade(context.Background(), "new:v2")
	if err == nil {
		t.Error("expected error on status failure")
	}
}

func TestRollback(t *testing.T) {
	t.Parallel()

	fb := &fakeBootc{
		status: &bootc.Status{
			Image: "registry.example.com/os:v1.1.0",
		},
	}
	mgr := NewManager(fb, &fakeSystemd{})

	result, err := mgr.Rollback(context.Background())
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	if !fb.rolledBack {
		t.Error("rollback not called")
	}
	if result.CurrentImage != "registry.example.com/os:v1.1.0" {
		t.Errorf("CurrentImage = %q", result.CurrentImage)
	}
}

func TestRollback_Error(t *testing.T) {
	t.Parallel()

	fb := &fakeBootc{
		status:      &bootc.Status{Image: "current:v1"},
		rollbackErr: fmt.Errorf("no rollback available"),
	}
	mgr := NewManager(fb, &fakeSystemd{})

	_, err := mgr.Rollback(context.Background())
	if err == nil {
		t.Error("expected error on rollback failure")
	}
}

func TestReboot(t *testing.T) {
	t.Parallel()

	fs := &fakeSystemd{}
	mgr := NewManager(&fakeBootc{status: &bootc.Status{}}, fs)

	err := mgr.Reboot(context.Background())
	if err != nil {
		t.Fatalf("Reboot: %v", err)
	}

	if !fs.rebooted {
		t.Error("reboot not called")
	}
}

func TestReboot_Error(t *testing.T) {
	t.Parallel()

	fs := &fakeSystemd{rebootErr: fmt.Errorf("permission denied")}
	mgr := NewManager(&fakeBootc{status: &bootc.Status{}}, fs)

	err := mgr.Reboot(context.Background())
	if err == nil {
		t.Error("expected error on reboot failure")
	}
}
