package machineconfig

import (
	"fmt"
	"os"
	"strings"

	"github.com/rsturla/hbctl/internal/system/kargs"
	"github.com/rsturla/hbctl/internal/system/network"
	"github.com/rsturla/hbctl/internal/validate"
)

type Config struct {
	Hostname   string
	KernelArgs []string
	DNSServers []string
	NTPServers []string
	Interfaces []network.Interface
}

type ApplyResult struct {
	Warnings       []string
	RebootRequired bool
}

type Applier struct {
	networkDir string
	kargsDir   string
	network    network.Manager
	kargs      kargs.Manager
}

func NewApplier(networkDir, kargsDir string, net network.Manager, ka kargs.Manager) *Applier {
	return &Applier{
		networkDir: networkDir,
		kargsDir:   kargsDir,
		network:    net,
		kargs:      ka,
	}
}

func (a *Applier) Apply(cfg *Config) (*ApplyResult, error) {
	result := &ApplyResult{}

	if cfg.Hostname != "" {
		if err := validate.Hostname(cfg.Hostname); err != nil {
			return nil, fmt.Errorf("invalid hostname: %w", err)
		}
		if err := applyHostname(cfg.Hostname); err != nil {
			return nil, fmt.Errorf("apply hostname: %w", err)
		}
	}

	for _, iface := range cfg.Interfaces {
		if err := validate.InterfaceName(iface.Name); err != nil {
			return nil, fmt.Errorf("invalid interface: %w", err)
		}
		for _, addr := range iface.Addresses {
			if err := validate.NetworkAddress(addr); err != nil {
				return nil, fmt.Errorf("invalid address on %s: %w", iface.Name, err)
			}
		}
		if iface.Gateway != "" {
			if err := validate.NoNewlines("gateway", iface.Gateway); err != nil {
				return nil, fmt.Errorf("invalid gateway on %s: %w", iface.Name, err)
			}
		}
	}

	if len(cfg.Interfaces) > 0 {
		if err := a.network.Write(a.networkDir, cfg.Interfaces); err != nil {
			return nil, fmt.Errorf("apply network: %w", err)
		}
	}

	for _, arg := range cfg.KernelArgs {
		if err := validate.KernelArg(arg); err != nil {
			return nil, fmt.Errorf("blocked kernel arg: %w", err)
		}
	}

	if len(cfg.KernelArgs) > 0 {
		existing, _ := a.kargs.Read(a.kargsDir)
		if err := a.kargs.Write(a.kargsDir, cfg.KernelArgs); err != nil {
			return nil, fmt.Errorf("apply kargs: %w", err)
		}
		if !stringSliceEqual(existing, cfg.KernelArgs) {
			result.RebootRequired = true
		}
	}

	for _, server := range cfg.DNSServers {
		if err := validate.IPAddress(server); err != nil {
			return nil, fmt.Errorf("invalid DNS server: %w", err)
		}
	}

	if len(cfg.DNSServers) > 0 {
		if err := applyDNS(cfg.DNSServers); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("dns: %v", err))
		}
	}

	if len(cfg.NTPServers) > 0 {
		result.Warnings = append(result.Warnings, "ntp: chrony config not yet implemented")
	}

	return result, nil
}

func (a *Applier) Read() (*Config, error) {
	cfg := &Config{}

	hostname, err := os.Hostname()
	if err == nil {
		cfg.Hostname = hostname
	}

	ifaces, err := a.network.Read(a.networkDir)
	if err == nil {
		cfg.Interfaces = ifaces
	}

	args, err := a.kargs.Read(a.kargsDir)
	if err == nil {
		cfg.KernelArgs = args
	}

	dns, err := readDNS()
	if err == nil {
		cfg.DNSServers = dns
	}

	return cfg, nil
}

func applyHostname(name string) error {
	return os.WriteFile("/etc/hostname", []byte(name+"\n"), 0o644)
}

func applyDNS(servers []string) error {
	var b strings.Builder
	for _, s := range servers {
		b.WriteString(fmt.Sprintf("nameserver %s\n", s))
	}
	return os.WriteFile("/etc/resolv.conf", []byte(b.String()), 0o644)
}

func readDNS() ([]string, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver ") {
			servers = append(servers, strings.TrimPrefix(line, "nameserver "))
		}
	}
	return servers, nil
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
