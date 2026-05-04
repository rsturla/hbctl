package network

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const defaultDir = "/etc/systemd/network"

type Interface struct {
	Name      string
	DHCP      bool
	Addresses []string
	Gateway   string
	MTU       uint32
}

type Manager interface {
	Write(dir string, ifaces []Interface) error
	Read(dir string) ([]Interface, error)
}

type FileManager struct{}

func NewManager() *FileManager {
	return &FileManager{}
}

func (m *FileManager) Write(dir string, ifaces []Interface) error {
	if dir == "" {
		dir = defaultDir
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create network dir: %w", err)
	}

	for i, iface := range ifaces {
		if iface.Name == "" {
			return fmt.Errorf("interface %d: name required", i)
		}
		content := renderNetworkFile(iface)
		filename := fmt.Sprintf("10-hb-%s.network", iface.Name)
		path := filepath.Join(dir, filename)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}

	return nil
}

func (m *FileManager) Read(dir string) ([]Interface, error) {
	if dir == "" {
		dir = defaultDir
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read network dir: %w", err)
	}

	var ifaces []Interface
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "10-hb-") || !strings.HasSuffix(entry.Name(), ".network") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}

		iface := parseNetworkFile(string(data))
		if iface.Name != "" {
			ifaces = append(ifaces, iface)
		}
	}

	return ifaces, nil
}

func renderNetworkFile(iface Interface) string {
	var b strings.Builder

	b.WriteString("[Match]\n")
	_, _ = fmt.Fprintf(&b, "Name=%s\n", iface.Name)
	b.WriteString("\n[Network]\n")

	if iface.DHCP {
		b.WriteString("DHCP=yes\n")
	} else {
		b.WriteString("DHCP=no\n")
		for _, addr := range iface.Addresses {
			_, _ = fmt.Fprintf(&b, "Address=%s\n", addr)
		}
		if iface.Gateway != "" {
			_, _ = fmt.Fprintf(&b, "Gateway=%s\n", iface.Gateway)
		}
	}

	if iface.MTU > 0 {
		_, _ = fmt.Fprintf(&b, "\n[Link]\nMTUBytes=%d\n", iface.MTU)
	}

	return b.String()
}

func parseNetworkFile(content string) Interface {
	var iface Interface
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Name":
			iface.Name = v
		case "DHCP":
			iface.DHCP = v == "yes"
		case "Address":
			iface.Addresses = append(iface.Addresses, v)
		case "Gateway":
			iface.Gateway = v
		case "MTUBytes":
			_, _ = fmt.Sscanf(v, "%d", &iface.MTU)
		}
	}
	return iface
}
