package machineconfig

import (
	"testing"

	"github.com/rsturla/hbctl/internal/system/network"
)

type fakeNetworkManager struct {
	written []network.Interface
	readVal []network.Interface
	err     error
}

func (f *fakeNetworkManager) Write(_ string, ifaces []network.Interface) error {
	f.written = ifaces
	return f.err
}

func (f *fakeNetworkManager) Read(_ string) ([]network.Interface, error) {
	return f.readVal, f.err
}

type fakeKargsManager struct {
	written []string
	readVal []string
	err     error
}

func (f *fakeKargsManager) Write(_ string, args []string) error {
	f.written = args
	return f.err
}

func (f *fakeKargsManager) Read(_ string) ([]string, error) {
	return f.readVal, f.err
}

func TestApply_Network(t *testing.T) {
	t.Parallel()

	net := &fakeNetworkManager{}
	ka := &fakeKargsManager{}
	applier := NewApplier("/tmp/net", "/tmp/kargs", net, ka)

	cfg := &Config{
		Interfaces: []network.Interface{
			{Name: "eth0", DHCP: true},
			{Name: "eth1", Addresses: []string{"10.0.0.5/24"}, Gateway: "10.0.0.1"},
		},
	}

	result, err := applier.Apply(cfg)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if len(net.written) != 2 {
		t.Errorf("expected 2 interfaces written, got %d", len(net.written))
	}
	if result.RebootRequired {
		t.Error("network changes should not require reboot")
	}
}

func TestApply_KernelArgs_RebootRequired(t *testing.T) {
	t.Parallel()

	ka := &fakeKargsManager{readVal: []string{"fips=1"}}
	applier := NewApplier("", "", &fakeNetworkManager{}, ka)

	cfg := &Config{
		KernelArgs: []string{"fips=1", "selinux=1"},
	}

	result, err := applier.Apply(cfg)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if !result.RebootRequired {
		t.Error("changed kernel args should require reboot")
	}
	if len(ka.written) != 2 {
		t.Errorf("expected 2 kargs written, got %d", len(ka.written))
	}
}

func TestApply_KernelArgs_NoRebootWhenSame(t *testing.T) {
	t.Parallel()

	ka := &fakeKargsManager{readVal: []string{"fips=1"}}
	applier := NewApplier("", "", &fakeNetworkManager{}, ka)

	cfg := &Config{
		KernelArgs: []string{"fips=1"},
	}

	result, err := applier.Apply(cfg)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if result.RebootRequired {
		t.Error("same kernel args should not require reboot")
	}
}

func TestApply_NTP_Warning(t *testing.T) {
	t.Parallel()

	applier := NewApplier("", "", &fakeNetworkManager{}, &fakeKargsManager{})

	cfg := &Config{
		NTPServers: []string{"pool.ntp.org"},
	}

	result, err := applier.Apply(cfg)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if len(result.Warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(result.Warnings))
	}
}

func TestApply_EmptyConfig(t *testing.T) {
	t.Parallel()

	applier := NewApplier("", "", &fakeNetworkManager{}, &fakeKargsManager{})

	result, err := applier.Apply(&Config{})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if result.RebootRequired {
		t.Error("empty config should not require reboot")
	}
	if len(result.Warnings) != 0 {
		t.Errorf("expected no warnings, got %d", len(result.Warnings))
	}
}

func TestRead(t *testing.T) {
	t.Parallel()

	net := &fakeNetworkManager{
		readVal: []network.Interface{
			{Name: "eth0", DHCP: true},
		},
	}
	ka := &fakeKargsManager{
		readVal: []string{"fips=1"},
	}
	applier := NewApplier("", "", net, ka)

	cfg, err := applier.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if len(cfg.Interfaces) != 1 {
		t.Errorf("Interfaces count = %d, want 1", len(cfg.Interfaces))
	}
	if len(cfg.KernelArgs) != 1 {
		t.Errorf("KernelArgs count = %d, want 1", len(cfg.KernelArgs))
	}
	if cfg.Hostname == "" {
		t.Error("Hostname should not be empty")
	}
}

func TestStringSliceEqual(t *testing.T) {
	t.Parallel()

	cases := []struct {
		a, b []string
		want bool
	}{
		{nil, nil, true},
		{[]string{}, []string{}, true},
		{[]string{"a"}, []string{"a"}, true},
		{[]string{"a", "b"}, []string{"a", "b"}, true},
		{[]string{"a"}, []string{"b"}, false},
		{[]string{"a"}, []string{"a", "b"}, false},
		{nil, []string{"a"}, false},
	}

	for _, tc := range cases {
		got := stringSliceEqual(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("stringSliceEqual(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
