package systemd

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/coreos/go-systemd/v22/dbus"
)

type UnitStatus struct {
	Name             string
	Description      string
	LoadState        string
	ActiveState      string
	SubState         string
	UnitFileState    string
	MainPID          uint32
	MemoryBytes      uint64
	ActiveEnterTimestamp string
}

type Manager interface {
	ListUnits(ctx context.Context) ([]UnitStatus, error)
	UnitStatus(ctx context.Context, name string) (*UnitStatus, error)
	StartUnit(ctx context.Context, name string) error
	StopUnit(ctx context.Context, name string) error
	RestartUnit(ctx context.Context, name string) error
	Reboot(ctx context.Context) error
}

type DBusManager struct{}

func NewManager() *DBusManager {
	return &DBusManager{}
}

func (m *DBusManager) ListUnits(ctx context.Context) ([]UnitStatus, error) {
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect to systemd: %w", err)
	}
	defer conn.Close()

	units, err := conn.ListUnitsContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("list units: %w", err)
	}

	result := make([]UnitStatus, 0, len(units))
	for _, u := range units {
		result = append(result, UnitStatus{
			Name:        u.Name,
			Description: u.Description,
			LoadState:   u.LoadState,
			ActiveState: u.ActiveState,
			SubState:    u.SubState,
		})
	}

	return result, nil
}

func (m *DBusManager) UnitStatus(ctx context.Context, name string) (*UnitStatus, error) {
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect to systemd: %w", err)
	}
	defer conn.Close()

	props, err := conn.GetUnitPropertiesContext(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("get unit properties %s: %w", name, err)
	}

	status := &UnitStatus{
		Name:        name,
		Description: propString(props, "Description"),
		LoadState:   propString(props, "LoadState"),
		ActiveState: propString(props, "ActiveState"),
		SubState:    propString(props, "SubState"),
	}

	status.UnitFileState = propString(props, "UnitFileState")

	if ts, ok := props["ActiveEnterTimestamp"].(uint64); ok && ts > 0 {
		status.ActiveEnterTimestamp = fmt.Sprintf("%d", ts)
	}

	svcProps, err := conn.GetUnitTypePropertiesContext(ctx, name, "Service")
	if err == nil {
		status.MainPID = propUint32(svcProps, "MainPID")
		status.MemoryBytes = propUint64(svcProps, "MemoryCurrent")
	}

	return status, nil
}

func (m *DBusManager) StartUnit(ctx context.Context, name string) error {
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return fmt.Errorf("connect to systemd: %w", err)
	}
	defer conn.Close()

	ch := make(chan string, 1)
	if _, err := conn.StartUnitContext(ctx, name, "replace", ch); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}
	result := <-ch
	if result != "done" {
		return fmt.Errorf("start %s: %s", name, result)
	}
	return nil
}

func (m *DBusManager) StopUnit(ctx context.Context, name string) error {
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return fmt.Errorf("connect to systemd: %w", err)
	}
	defer conn.Close()

	ch := make(chan string, 1)
	if _, err := conn.StopUnitContext(ctx, name, "replace", ch); err != nil {
		return fmt.Errorf("stop %s: %w", name, err)
	}
	result := <-ch
	if result != "done" {
		return fmt.Errorf("stop %s: %s", name, result)
	}
	return nil
}

func (m *DBusManager) RestartUnit(ctx context.Context, name string) error {
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return fmt.Errorf("connect to systemd: %w", err)
	}
	defer conn.Close()

	ch := make(chan string, 1)
	if _, err := conn.RestartUnitContext(ctx, name, "replace", ch); err != nil {
		return fmt.Errorf("restart %s: %w", name, err)
	}
	result := <-ch
	if result != "done" {
		return fmt.Errorf("restart %s: %s", name, result)
	}
	return nil
}

func (m *DBusManager) Reboot(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "systemctl", "reboot")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl reboot: %w: %s", err, out)
	}
	return nil
}

func propString(props map[string]interface{}, key string) string {
	v, ok := props[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func propUint32(props map[string]interface{}, key string) uint32 {
	v, ok := props[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case uint32:
		return n
	case uint64:
		return uint32(n)
	case int:
		return uint32(n)
	default:
		return 0
	}
}

func propUint64(props map[string]interface{}, key string) uint64 {
	v, ok := props[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case uint64:
		return n
	case uint32:
		return uint64(n)
	case int:
		return uint64(n)
	default:
		return 0
	}
}
