package v1alpha1

import (
	"context"
	"testing"

	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"github.com/rsturla/hbctl/internal/machineconfig"
	"github.com/rsturla/hbctl/internal/system/kargs"
	"github.com/rsturla/hbctl/internal/system/network"
)

type fakeNetMgr struct {
	written []network.Interface
	readVal []network.Interface
	err     error
}

func (f *fakeNetMgr) Write(_ string, ifaces []network.Interface) error {
	f.written = ifaces
	return f.err
}

func (f *fakeNetMgr) Read(_ string) ([]network.Interface, error) {
	return f.readVal, f.err
}

type fakeKargsMgr struct {
	written []string
	readVal []string
	err     error
}

func (f *fakeKargsMgr) Write(_ string, args []string) error {
	f.written = args
	return f.err
}

func (f *fakeKargsMgr) Read(_ string) ([]string, error) {
	return f.readVal, f.err
}

func newTestConfigServer(net *fakeNetMgr, ka *fakeKargsMgr) *ConfigServer {
	applier := machineconfig.NewApplier("", "", net, ka)
	return NewConfigServer(applier)
}

func TestGetConfig(t *testing.T) {
	t.Parallel()

	srv := newTestConfigServer(
		&fakeNetMgr{readVal: []network.Interface{
			{Name: "eth0", DHCP: true},
		}},
		&fakeKargsMgr{readVal: []string{"fips=1"}},
	)

	resp, err := srv.GetConfig(context.Background(), &pb.GetConfigRequest{})
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}

	if resp.Config == nil {
		t.Fatal("Config is nil")
	}
	if resp.Config.Hostname == "" {
		t.Error("Hostname should not be empty")
	}
	if len(resp.Config.KernelArgs) != 1 || resp.Config.KernelArgs[0] != "fips=1" {
		t.Errorf("KernelArgs = %v", resp.Config.KernelArgs)
	}
	if resp.Config.Network == nil || len(resp.Config.Network.Interfaces) != 1 {
		t.Fatal("expected 1 network interface")
	}
	if resp.Config.Network.Interfaces[0].Name != "eth0" {
		t.Errorf("iface Name = %q", resp.Config.Network.Interfaces[0].Name)
	}
}

func TestGetConfig_Empty(t *testing.T) {
	t.Parallel()

	srv := newTestConfigServer(&fakeNetMgr{}, &fakeKargsMgr{})

	resp, err := srv.GetConfig(context.Background(), &pb.GetConfigRequest{})
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}

	if resp.Config == nil {
		t.Fatal("Config should not be nil")
	}
}

func TestApplyConfig_Network(t *testing.T) {
	t.Parallel()

	net := &fakeNetMgr{}
	srv := newTestConfigServer(net, &fakeKargsMgr{})

	resp, err := srv.ApplyConfig(context.Background(), &pb.ApplyConfigRequest{
		Config: &pb.MachineConfig{
			Network: &pb.NetworkConfig{
				Interfaces: []*pb.NetworkInterface{
					{Name: "eth0", Dhcp: true, Mtu: 9000},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}

	if resp.RebootRequired {
		t.Error("network changes should not require reboot")
	}
	if len(net.written) != 1 {
		t.Fatalf("expected 1 interface written, got %d", len(net.written))
	}
	if net.written[0].Name != "eth0" {
		t.Errorf("written iface Name = %q", net.written[0].Name)
	}
	if net.written[0].MTU != 9000 {
		t.Errorf("written iface MTU = %d", net.written[0].MTU)
	}
}

func TestApplyConfig_KernelArgs(t *testing.T) {
	t.Parallel()

	ka := &fakeKargsMgr{readVal: []string{"old=1"}}
	srv := newTestConfigServer(&fakeNetMgr{}, ka)

	resp, err := srv.ApplyConfig(context.Background(), &pb.ApplyConfigRequest{
		Config: &pb.MachineConfig{
			KernelArgs: []string{"new=1"},
		},
	})
	if err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}

	if !resp.RebootRequired {
		t.Error("changed kernel args should require reboot")
	}
}

func TestApplyConfig_NilConfig(t *testing.T) {
	t.Parallel()

	srv := newTestConfigServer(&fakeNetMgr{}, &fakeKargsMgr{})

	_, err := srv.ApplyConfig(context.Background(), &pb.ApplyConfigRequest{})
	if err == nil {
		t.Error("expected error for nil config")
	}
}

func TestApplyConfig_NTP_Warning(t *testing.T) {
	t.Parallel()

	srv := newTestConfigServer(&fakeNetMgr{}, &fakeKargsMgr{})

	resp, err := srv.ApplyConfig(context.Background(), &pb.ApplyConfigRequest{
		Config: &pb.MachineConfig{
			NtpServers: []string{"pool.ntp.org"},
		},
	})
	if err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}

	if len(resp.Warnings) == 0 {
		t.Error("expected NTP warning")
	}
}

func TestConfigToProto_FullConfig(t *testing.T) {
	t.Parallel()

	cfg := &machineconfig.Config{
		Hostname:   "node-1",
		KernelArgs: []string{"fips=1"},
		DNSServers: []string{"8.8.8.8"},
		NTPServers: []string{"pool.ntp.org"},
		Interfaces: []network.Interface{
			{Name: "eth0", DHCP: true, MTU: 1500},
			{Name: "eth1", Addresses: []string{"10.0.0.5/24"}, Gateway: "10.0.0.1"},
		},
	}

	mc := configToProto(cfg)

	if mc.Hostname != "node-1" {
		t.Errorf("Hostname = %q", mc.Hostname)
	}
	if len(mc.KernelArgs) != 1 {
		t.Errorf("KernelArgs = %v", mc.KernelArgs)
	}
	if len(mc.DnsServers) != 1 {
		t.Errorf("DnsServers = %v", mc.DnsServers)
	}
	if mc.Network == nil || len(mc.Network.Interfaces) != 2 {
		t.Fatal("expected 2 network interfaces")
	}
	if mc.Network.Interfaces[0].Mtu != 1500 {
		t.Errorf("iface[0] MTU = %d", mc.Network.Interfaces[0].Mtu)
	}
}

func TestProtoToConfig_FullConfig(t *testing.T) {
	t.Parallel()

	mc := &pb.MachineConfig{
		Hostname:   "node-2",
		KernelArgs: []string{"selinux=1"},
		DnsServers: []string{"1.1.1.1", "8.8.8.8"},
		NtpServers: []string{"time.google.com"},
		Network: &pb.NetworkConfig{
			Interfaces: []*pb.NetworkInterface{
				{Name: "ens5", Dhcp: true},
			},
		},
	}

	cfg := protoToConfig(mc)

	if cfg.Hostname != "node-2" {
		t.Errorf("Hostname = %q", cfg.Hostname)
	}
	if len(cfg.DNSServers) != 2 {
		t.Errorf("DNSServers = %v", cfg.DNSServers)
	}
	if len(cfg.Interfaces) != 1 {
		t.Fatalf("Interfaces count = %d", len(cfg.Interfaces))
	}
	if cfg.Interfaces[0].Name != "ens5" {
		t.Errorf("iface Name = %q", cfg.Interfaces[0].Name)
	}
}

func TestProtoToConfig_NilNetwork(t *testing.T) {
	t.Parallel()

	mc := &pb.MachineConfig{Hostname: "test"}
	cfg := protoToConfig(mc)

	if len(cfg.Interfaces) != 0 {
		t.Errorf("Interfaces should be empty, got %d", len(cfg.Interfaces))
	}
}

func TestConfigToProto_NoInterfaces(t *testing.T) {
	t.Parallel()

	cfg := &machineconfig.Config{Hostname: "test"}
	mc := configToProto(cfg)

	if mc.Network != nil {
		t.Error("Network should be nil with no interfaces")
	}
}

func TestProtoConfigRoundTrip(t *testing.T) {
	t.Parallel()

	original := &pb.MachineConfig{
		Hostname:   "worker-3",
		KernelArgs: []string{"fips=1", "selinux=1"},
		DnsServers: []string{"8.8.8.8"},
		Network: &pb.NetworkConfig{
			Interfaces: []*pb.NetworkInterface{
				{Name: "eth0", Dhcp: true, Mtu: 9000},
				{Name: "eth1", Addresses: []string{"10.0.0.5/24"}, Gateway: "10.0.0.1"},
			},
		},
	}

	cfg := protoToConfig(original)
	roundTripped := configToProto(cfg)

	if roundTripped.Hostname != original.Hostname {
		t.Errorf("Hostname: %q != %q", roundTripped.Hostname, original.Hostname)
	}
	if len(roundTripped.KernelArgs) != len(original.KernelArgs) {
		t.Errorf("KernelArgs len: %d != %d", len(roundTripped.KernelArgs), len(original.KernelArgs))
	}
	if len(roundTripped.Network.Interfaces) != len(original.Network.Interfaces) {
		t.Errorf("Interfaces len: %d != %d", len(roundTripped.Network.Interfaces), len(original.Network.Interfaces))
	}
	if roundTripped.Network.Interfaces[0].Mtu != 9000 {
		t.Errorf("MTU lost in round-trip: %d", roundTripped.Network.Interfaces[0].Mtu)
	}
}

// Verify kargs.Manager interface is satisfied by fakeKargsMgr
var _ kargs.Manager = (*fakeKargsMgr)(nil)
var _ network.Manager = (*fakeNetMgr)(nil)
