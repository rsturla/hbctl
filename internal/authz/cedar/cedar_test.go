package cedar

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/rsturla/hbctl/internal/authn"
	"github.com/rsturla/hbctl/internal/authz"
)

const adminPolicy = `permit(
  principal in Group::"admins",
  action,
  resource
);`

const readOnlyPolicy = `permit(
  principal in Group::"monitoring",
  action in [Action::"Version", Action::"Health", Action::"Stats", Action::"Logs", Action::"Dmesg", Action::"ServiceStatus", Action::"GetConfig"],
  resource
);`

const denyRebootPolicy = `forbid(
  principal,
  action == Action::"Reboot",
  resource
) unless { principal in Group::"admins" };`

func setupPolicies(t *testing.T, policies ...string) string {
	t.Helper()
	dir := t.TempDir()
	for i, p := range policies {
		name := filepath.Join(dir, fmt.Sprintf("policy-%d.cedar", i))
		if err := os.WriteFile(name, []byte(p), 0o644); err != nil {
			t.Fatalf("write policy: %v", err)
		}
	}
	return dir
}

func newProvider(t *testing.T, dir string) authz.Authorizer {
	t.Helper()
	cfg, _ := json.Marshal(Config{PolicyDir: dir})
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestAdminAccess(t *testing.T) {
	t.Parallel()

	dir := setupPolicies(t, adminPolicy)
	p := newProvider(t, dir)

	admin := authn.Identity{Name: "admin-user", Groups: []string{"admins"}}

	actions := []string{
		"/hb.v1alpha1.MachineService/Version",
		"/hb.v1alpha1.MachineService/Health",
		"/hb.v1alpha1.MachineService/Reboot",
		"/hb.v1alpha1.MachineService/Upgrade",
		"/hb.v1alpha1.MachineService/ApplyConfig",
	}

	for _, action := range actions {
		d, err := p.Authorize(context.Background(), admin, action, authz.ThisNode())
		if err != nil {
			t.Fatalf("Authorize(%s): %v", action, err)
		}
		if d != authz.Allow {
			t.Errorf("admin denied for %s", action)
		}
	}
}

func TestReadOnlyAccess(t *testing.T) {
	t.Parallel()

	dir := setupPolicies(t, readOnlyPolicy)
	p := newProvider(t, dir)

	monitor := authn.Identity{Name: "monitor", Groups: []string{"monitoring"}}

	allowed := []string{"Version", "Health", "Stats", "Logs", "Dmesg", "ServiceStatus", "GetConfig"}
	for _, a := range allowed {
		d, _ := p.Authorize(context.Background(), monitor, "/hb.v1alpha1.MachineService/"+a, authz.ThisNode())
		if d != authz.Allow {
			t.Errorf("monitoring should access %s", a)
		}
	}

	denied := []string{"Reboot", "Upgrade", "Rollback", "ApplyConfig"}
	for _, a := range denied {
		d, _ := p.Authorize(context.Background(), monitor, "/hb.v1alpha1.MachineService/"+a, authz.ThisNode())
		if d != authz.Deny {
			t.Errorf("monitoring should NOT access %s", a)
		}
	}
}

func TestDenyReboot(t *testing.T) {
	t.Parallel()

	dir := setupPolicies(t, adminPolicy, readOnlyPolicy, denyRebootPolicy)
	p := newProvider(t, dir)

	monitor := authn.Identity{Name: "monitor", Groups: []string{"monitoring"}}
	d, _ := p.Authorize(context.Background(), monitor, "/hb.v1alpha1.MachineService/Reboot", authz.ThisNode())
	if d != authz.Deny {
		t.Error("monitoring should be denied Reboot by forbid policy")
	}

	admin := authn.Identity{Name: "admin", Groups: []string{"admins"}}
	d, _ = p.Authorize(context.Background(), admin, "/hb.v1alpha1.MachineService/Reboot", authz.ThisNode())
	if d != authz.Allow {
		t.Error("admin should still be allowed Reboot (unless clause)")
	}
}

func TestNoGroupsDenied(t *testing.T) {
	t.Parallel()

	dir := setupPolicies(t, adminPolicy, readOnlyPolicy)
	p := newProvider(t, dir)

	nobody := authn.Identity{Name: "unknown-user"}
	d, _ := p.Authorize(context.Background(), nobody, "/hb.v1alpha1.MachineService/Version", authz.ThisNode())
	if d != authz.Deny {
		t.Error("user with no groups should be denied")
	}
}

func TestEmptyPolicyDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := newProvider(t, dir)

	d, _ := p.Authorize(context.Background(), authn.Identity{Name: "anyone"}, "/any", authz.ThisNode())
	if d != authz.Deny {
		t.Error("empty policy set should deny by default")
	}
}

func TestMissingPolicyDir(t *testing.T) {
	t.Parallel()

	cfg, _ := json.Marshal(Config{PolicyDir: "/nonexistent-12345"})
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New should not error for missing dir: %v", err)
	}

	d, _ := p.Authorize(context.Background(), authn.Identity{Name: "anyone"}, "/any", authz.ThisNode())
	if d != authz.Deny {
		t.Error("missing policy dir should deny by default")
	}
}

func TestInvalidPolicyFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "bad.cedar"), []byte("not valid cedar syntax!!!"), 0o644)

	cfg, _ := json.Marshal(Config{PolicyDir: dir})
	_, err := New(cfg)
	if err == nil {
		t.Error("expected error for invalid policy syntax")
	}
}

func TestNonCedarFilesIgnored(t *testing.T) {
	t.Parallel()

	dir := setupPolicies(t, adminPolicy)
	_ = os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not a policy"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "notes.md"), []byte("# notes"), 0o644)

	p := newProvider(t, dir)

	admin := authn.Identity{Name: "admin", Groups: []string{"admins"}}
	d, _ := p.Authorize(context.Background(), admin, "/hb.v1alpha1.MachineService/Version", authz.ThisNode())
	if d != authz.Allow {
		t.Error("admin should be allowed — non-.cedar files should be ignored")
	}
}

func TestMultiplePolicyFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "01-admins.cedar"), []byte(adminPolicy), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "02-monitoring.cedar"), []byte(readOnlyPolicy), 0o644)

	p := newProvider(t, dir)

	admin := authn.Identity{Name: "admin", Groups: []string{"admins"}}
	d, _ := p.Authorize(context.Background(), admin, "/hb.v1alpha1.MachineService/Reboot", authz.ThisNode())
	if d != authz.Allow {
		t.Error("admin should be allowed from 01-admins.cedar")
	}

	monitor := authn.Identity{Name: "mon", Groups: []string{"monitoring"}}
	d, _ = p.Authorize(context.Background(), monitor, "/hb.v1alpha1.MachineService/Health", authz.ThisNode())
	if d != authz.Allow {
		t.Error("monitor should be allowed from 02-monitoring.cedar")
	}
}

func TestName(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := newProvider(t, dir)
	if p.Name() != "cedar" {
		t.Errorf("Name = %q", p.Name())
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	var c Config
	if c.PolicyDir != "" {
		t.Error("default PolicyDir should be empty (filled by New)")
	}
}

