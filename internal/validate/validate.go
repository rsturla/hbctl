package validate

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	unitNameRe     = regexp.MustCompile(`^[a-zA-Z0-9_@:.-]+\.(?:service|socket|timer|mount|target|path|scope|slice|swap)$`)
	ifaceNameRe    = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	hostnameRe     = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	imageRefRe     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]*(:[a-zA-Z0-9._-]+)?(@sha256:[a-f0-9]{64})?$`)
	dangerousKargs = []string{"init=", "rd.break", "selinux=0", "enforcing=0", "systemd.unit=", "rescue", "emergency", "single"}
)

func UnitName(name string) error {
	if name == "" {
		return fmt.Errorf("unit name required")
	}
	if len(name) > 256 {
		return fmt.Errorf("unit name too long")
	}
	if !unitNameRe.MatchString(name) {
		return fmt.Errorf("invalid unit name: %q", name)
	}
	return nil
}

func InterfaceName(name string) error {
	if name == "" {
		return fmt.Errorf("interface name required")
	}
	if len(name) > 15 {
		return fmt.Errorf("interface name too long")
	}
	if !ifaceNameRe.MatchString(name) {
		return fmt.Errorf("invalid interface name: %q", name)
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("invalid interface name: %q", name)
	}
	return nil
}

func Hostname(name string) error {
	if name == "" {
		return fmt.Errorf("hostname required")
	}
	if len(name) > 253 {
		return fmt.Errorf("hostname too long")
	}
	if !hostnameRe.MatchString(name) {
		return fmt.Errorf("invalid hostname: %q", name)
	}
	return nil
}

func IPAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("IP address required")
	}
	if strings.ContainsAny(addr, "\n\r\t ") {
		return fmt.Errorf("IP address contains invalid characters")
	}
	if net.ParseIP(addr) == nil {
		return fmt.Errorf("invalid IP address: %q", addr)
	}
	return nil
}

func ImageRef(ref string) error {
	if ref == "" {
		return fmt.Errorf("image reference required")
	}
	if len(ref) > 1024 {
		return fmt.Errorf("image reference too long")
	}
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("image reference must not start with '-'")
	}
	if !imageRefRe.MatchString(ref) {
		return fmt.Errorf("invalid image reference: %q", ref)
	}
	return nil
}

func NetworkAddress(addr string) error {
	if strings.ContainsAny(addr, "\n\r\t") {
		return fmt.Errorf("network address contains invalid characters")
	}
	return nil
}

func KernelArg(arg string) error {
	if strings.ContainsAny(arg, "\n\r\t") {
		return fmt.Errorf("kernel argument contains invalid characters")
	}
	lower := strings.ToLower(arg)
	for _, dangerous := range dangerousKargs {
		if strings.HasPrefix(lower, dangerous) || lower == dangerous {
			return fmt.Errorf("dangerous kernel argument blocked: %q", arg)
		}
	}
	return nil
}

func NoNewlines(field, value string) error {
	if strings.ContainsAny(value, "\n\r") {
		return fmt.Errorf("%s contains newline characters", field)
	}
	return nil
}
