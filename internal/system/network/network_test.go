package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderNetworkFile_DHCP(t *testing.T) {
	t.Parallel()

	iface := Interface{Name: "eth0", DHCP: true}
	got := renderNetworkFile(iface)

	assertContains(t, got, "[Match]")
	assertContains(t, got, "Name=eth0")
	assertContains(t, got, "DHCP=yes")
	assertNotContains(t, got, "Address=")
}

func TestRenderNetworkFile_Static(t *testing.T) {
	t.Parallel()

	iface := Interface{
		Name:      "eth0",
		Addresses: []string{"192.168.1.10/24", "fd00::10/64"},
		Gateway:   "192.168.1.1",
	}
	got := renderNetworkFile(iface)

	assertContains(t, got, "DHCP=no")
	assertContains(t, got, "Address=192.168.1.10/24")
	assertContains(t, got, "Address=fd00::10/64")
	assertContains(t, got, "Gateway=192.168.1.1")
}

func TestRenderNetworkFile_MTU(t *testing.T) {
	t.Parallel()

	iface := Interface{Name: "eth0", DHCP: true, MTU: 9000}
	got := renderNetworkFile(iface)

	assertContains(t, got, "[Link]")
	assertContains(t, got, "MTUBytes=9000")
}

func TestRenderNetworkFile_NoMTU(t *testing.T) {
	t.Parallel()

	iface := Interface{Name: "eth0", DHCP: true}
	got := renderNetworkFile(iface)

	assertNotContains(t, got, "[Link]")
	assertNotContains(t, got, "MTUBytes")
}

func TestParseNetworkFile_DHCP(t *testing.T) {
	t.Parallel()

	content := "[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n"
	iface := parseNetworkFile(content)

	if iface.Name != "eth0" {
		t.Errorf("Name = %q", iface.Name)
	}
	if !iface.DHCP {
		t.Error("DHCP should be true")
	}
}

func TestParseNetworkFile_Static(t *testing.T) {
	t.Parallel()

	content := "[Match]\nName=ens5\n\n[Network]\nDHCP=no\nAddress=10.0.0.5/24\nAddress=10.0.1.5/24\nGateway=10.0.0.1\n"
	iface := parseNetworkFile(content)

	if iface.Name != "ens5" {
		t.Errorf("Name = %q", iface.Name)
	}
	if iface.DHCP {
		t.Error("DHCP should be false")
	}
	if len(iface.Addresses) != 2 {
		t.Fatalf("Addresses count = %d, want 2", len(iface.Addresses))
	}
	if iface.Gateway != "10.0.0.1" {
		t.Errorf("Gateway = %q", iface.Gateway)
	}
}

func TestParseNetworkFile_MTU(t *testing.T) {
	t.Parallel()

	content := "[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n\n[Link]\nMTUBytes=9000\n"
	iface := parseNetworkFile(content)

	if iface.MTU != 9000 {
		t.Errorf("MTU = %d, want 9000", iface.MTU)
	}
}

func TestRenderParseRoundTrip(t *testing.T) {
	t.Parallel()

	original := Interface{
		Name:      "ens5",
		Addresses: []string{"10.0.0.5/24"},
		Gateway:   "10.0.0.1",
		MTU:       1500,
	}

	content := renderNetworkFile(original)
	parsed := parseNetworkFile(content)

	if parsed.Name != original.Name {
		t.Errorf("Name: %q != %q", parsed.Name, original.Name)
	}
	if parsed.DHCP != original.DHCP {
		t.Errorf("DHCP: %v != %v", parsed.DHCP, original.DHCP)
	}
	if len(parsed.Addresses) != len(original.Addresses) {
		t.Errorf("Addresses count: %d != %d", len(parsed.Addresses), len(original.Addresses))
	}
	if parsed.Gateway != original.Gateway {
		t.Errorf("Gateway: %q != %q", parsed.Gateway, original.Gateway)
	}
	if parsed.MTU != original.MTU {
		t.Errorf("MTU: %d != %d", parsed.MTU, original.MTU)
	}
}

func TestWriteAndRead(t *testing.T) {
	dir := t.TempDir()

	mgr := NewManager()
	ifaces := []Interface{
		{Name: "eth0", DHCP: true},
		{Name: "eth1", Addresses: []string{"10.0.0.5/24"}, Gateway: "10.0.0.1"},
	}

	if err := mgr.Write(dir, ifaces); err != nil {
		t.Fatalf("Write: %v", err)
	}

	files, _ := os.ReadDir(dir)
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}

	read, err := mgr.Read(dir)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if len(read) != 2 {
		t.Fatalf("Read returned %d interfaces, want 2", len(read))
	}
}

func TestWrite_EmptyName(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager()

	err := mgr.Write(dir, []Interface{{DHCP: true}})
	if err == nil {
		t.Error("expected error for empty interface name")
	}
}

func TestWrite_EmptyList(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager()

	err := mgr.Write(dir, nil)
	if err != nil {
		t.Fatalf("Write empty: %v", err)
	}
}

func TestRead_NonexistentDir(t *testing.T) {
	mgr := NewManager()
	ifaces, err := mgr.Read("/nonexistent-dir-12345")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(ifaces) != 0 {
		t.Errorf("expected empty, got %d", len(ifaces))
	}
}

func TestRead_IgnoresNonKubeosFiles(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "89-ethernet.network"), []byte("[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "10-hb-eth1.network"), []byte("[Match]\nName=eth1\n\n[Network]\nDHCP=yes\n"), 0o644)

	mgr := NewManager()
	ifaces, err := mgr.Read(dir)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if len(ifaces) != 1 {
		t.Fatalf("expected 1 hb interface, got %d", len(ifaces))
	}
	if ifaces[0].Name != "eth1" {
		t.Errorf("Name = %q, want eth1", ifaces[0].Name)
	}
}

func TestWrite_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager()

	mgr.Write(dir, []Interface{{Name: "eth0", DHCP: true}})

	info, _ := os.Stat(filepath.Join(dir, "10-hb-eth0.network"))
	if info.Mode().Perm() != 0o644 {
		t.Errorf("permissions = %o, want 0644", info.Mode().Perm())
	}
}

func FuzzParseNetworkFile(f *testing.F) {
	f.Add("[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n")
	f.Add("[Match]\nName=ens5\n\n[Network]\nDHCP=no\nAddress=10.0.0.5/24\nGateway=10.0.0.1\n")
	f.Add("[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n\n[Link]\nMTUBytes=9000\n")
	f.Add("")
	f.Add("garbage")
	f.Add("[Match]\n\n[Network]\n")
	f.Add("Name=eth0\nDHCP=yes\nAddress=\nGateway=\nMTUBytes=abc\n")

	f.Fuzz(func(t *testing.T, content string) {
		iface := parseNetworkFile(content)
		_ = iface.Name
		_ = iface.DHCP
		_ = iface.Gateway
		_ = iface.MTU
		_ = iface.Addresses
	})
}

func FuzzRenderParseRoundTrip(f *testing.F) {
	f.Add("eth0", true, "10.0.0.1/24", "10.0.0.1", uint32(1500))
	f.Add("ens5", false, "192.168.1.100/24", "192.168.1.1", uint32(9000))
	f.Add("bond0", true, "", "", uint32(0))

	f.Fuzz(func(t *testing.T, name string, dhcp bool, addr, gw string, mtu uint32) {
		if name == "" {
			return
		}
		iface := Interface{
			Name: name,
			DHCP: dhcp,
			MTU:  mtu,
		}
		if !dhcp && addr != "" {
			iface.Addresses = []string{addr}
			iface.Gateway = gw
		}

		content := renderNetworkFile(iface)
		parsed := parseNetworkFile(content)

		if parsed.Name != name {
			t.Errorf("Name: %q != %q", parsed.Name, name)
		}
		if parsed.DHCP != dhcp {
			t.Errorf("DHCP: %v != %v", parsed.DHCP, dhcp)
		}
		if parsed.MTU != mtu {
			t.Errorf("MTU: %d != %d", parsed.MTU, mtu)
		}
	})
}

func assertContains(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("expected %q to contain %q", s, substr)
	}
}

func assertNotContains(t *testing.T, s, substr string) {
	t.Helper()
	if strings.Contains(s, substr) {
		t.Errorf("expected %q to NOT contain %q", s, substr)
	}
}
