package validate

import "testing"

func TestUnitName(t *testing.T) {
	t.Parallel()

	valid := []string{"crio.service", "kubelet.service", "sshd.socket", "chronyd.service", "foo@bar.service", "my-unit.timer"}
	for _, name := range valid {
		if err := UnitName(name); err != nil {
			t.Errorf("UnitName(%q) = %v, want nil", name, err)
		}
	}

	invalid := []string{"", "../etc/passwd", "crio", "--help", "foo bar.service", "a\nb.service", string(make([]byte, 300))}
	for _, name := range invalid {
		if err := UnitName(name); err == nil {
			t.Errorf("UnitName(%q) = nil, want error", name)
		}
	}
}

func TestInterfaceName(t *testing.T) {
	t.Parallel()

	valid := []string{"eth0", "ens5", "bond0", "br-lan", "wlan0"}
	for _, name := range valid {
		if err := InterfaceName(name); err != nil {
			t.Errorf("InterfaceName(%q) = %v", name, err)
		}
	}

	invalid := []string{"", "../../etc", "eth 0", "a/b", "a\nb", string(make([]byte, 20)), "a..b"}
	for _, name := range invalid {
		if err := InterfaceName(name); err == nil {
			t.Errorf("InterfaceName(%q) = nil, want error", name)
		}
	}
}

func TestHostname(t *testing.T) {
	t.Parallel()

	valid := []string{"node-1", "worker.example.com", "a", "my-host-123"}
	for _, name := range valid {
		if err := Hostname(name); err != nil {
			t.Errorf("Hostname(%q) = %v", name, err)
		}
	}

	invalid := []string{"", "-bad", "bad-", "a b", "a\nb", string(make([]byte, 260)), "foo..bar"}
	for _, name := range invalid {
		if err := Hostname(name); err == nil {
			t.Errorf("Hostname(%q) = nil, want error", name)
		}
	}
}

func TestIPAddress(t *testing.T) {
	t.Parallel()

	valid := []string{"8.8.8.8", "1.1.1.1", "::1", "fd00::1", "192.168.1.1"}
	for _, addr := range valid {
		if err := IPAddress(addr); err != nil {
			t.Errorf("IPAddress(%q) = %v", addr, err)
		}
	}

	invalid := []string{"", "not-ip", "8.8.8.8\nevil", "8.8.8.8 extra"}
	for _, addr := range invalid {
		if err := IPAddress(addr); err == nil {
			t.Errorf("IPAddress(%q) = nil, want error", addr)
		}
	}
}

func TestImageRef(t *testing.T) {
	t.Parallel()

	valid := []string{
		"registry.example.com/os:v1.0",
		"quay.io/hummingbird/kubeos:latest",
		"ghcr.io/org/image@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
	}
	for _, ref := range valid {
		if err := ImageRef(ref); err != nil {
			t.Errorf("ImageRef(%q) = %v", ref, err)
		}
	}

	invalid := []string{"", "--help", "-flag", string(make([]byte, 2000))}
	for _, ref := range invalid {
		if err := ImageRef(ref); err == nil {
			t.Errorf("ImageRef(%q) = nil, want error", ref)
		}
	}
}

func TestKernelArg(t *testing.T) {
	t.Parallel()

	valid := []string{"fips=1", "systemd.unified_cgroup_hierarchy=1", "console=ttyS0,115200n8"}
	for _, arg := range valid {
		if err := KernelArg(arg); err != nil {
			t.Errorf("KernelArg(%q) = %v", arg, err)
		}
	}

	blocked := []string{"init=/bin/sh", "rd.break", "selinux=0", "enforcing=0", "INIT=/bin/bash"}
	for _, arg := range blocked {
		if err := KernelArg(arg); err == nil {
			t.Errorf("KernelArg(%q) = nil, want blocked", arg)
		}
	}
}

func FuzzUnitName(f *testing.F) {
	f.Add("crio.service")
	f.Add("")
	f.Add("../../../etc/passwd")
	f.Add("--help")
	f.Add(string(make([]byte, 1000)))

	f.Fuzz(func(t *testing.T, name string) {
		_ = UnitName(name)
	})
}

func FuzzImageRef(f *testing.F) {
	f.Add("registry.example.com/os:v1")
	f.Add("")
	f.Add("--help")
	f.Add("-flag")

	f.Fuzz(func(t *testing.T, ref string) {
		_ = ImageRef(ref)
	})
}

func FuzzHostname(f *testing.F) {
	f.Add("node-1")
	f.Add("")
	f.Add("evil\nhost")

	f.Fuzz(func(t *testing.T, name string) {
		_ = Hostname(name)
	})
}
