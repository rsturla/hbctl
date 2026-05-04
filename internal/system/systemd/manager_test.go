package systemd

import (
	"context"
	"testing"
)

type fakeManager struct {
	units  []UnitStatus
	status *UnitStatus
	err    error
}

func (f *fakeManager) ListUnits(_ context.Context) ([]UnitStatus, error) {
	return f.units, f.err
}

func (f *fakeManager) UnitStatus(_ context.Context, _ string) (*UnitStatus, error) {
	return f.status, f.err
}

func (f *fakeManager) Reboot(_ context.Context) error { return nil }
func (f *fakeManager) StartUnit(_ context.Context, _ string) error   { return nil }
func (f *fakeManager) StopUnit(_ context.Context, _ string) error    { return nil }
func (f *fakeManager) RestartUnit(_ context.Context, _ string) error { return nil }

func TestManagerInterface(t *testing.T) {
	t.Parallel()

	fm := &fakeManager{
		units: []UnitStatus{
			{Name: "crio.service", ActiveState: "active", SubState: "running"},
			{Name: "kubelet.service", ActiveState: "active", SubState: "running"},
		},
	}

	var m Manager = fm
	units, err := m.ListUnits(context.Background())
	if err != nil {
		t.Fatalf("ListUnits: %v", err)
	}
	if len(units) != 2 {
		t.Errorf("units count = %d, want 2", len(units))
	}
}

func TestManagerInterface_UnitStatus(t *testing.T) {
	t.Parallel()

	fm := &fakeManager{
		status: &UnitStatus{
			Name:        "crio.service",
			Description: "CRI-O Container Runtime",
			LoadState:   "loaded",
			ActiveState: "active",
			SubState:    "running",
			MainPID:     1234,
			MemoryBytes: 52428800,
		},
	}

	var m Manager = fm
	s, err := m.UnitStatus(context.Background(), "crio.service")
	if err != nil {
		t.Fatalf("UnitStatus: %v", err)
	}
	if s.Name != "crio.service" {
		t.Errorf("Name = %q", s.Name)
	}
	if s.MainPID != 1234 {
		t.Errorf("MainPID = %d", s.MainPID)
	}
	if s.MemoryBytes != 52428800 {
		t.Errorf("MemoryBytes = %d", s.MemoryBytes)
	}
}

func TestPropString(t *testing.T) {
	t.Parallel()

	props := map[string]interface{}{
		"Description": "test service",
		"Number":      42,
	}

	if got := propString(props, "Description"); got != "test service" {
		t.Errorf("propString(Description) = %q", got)
	}
	if got := propString(props, "Number"); got != "" {
		t.Errorf("propString(Number) = %q, want empty", got)
	}
	if got := propString(props, "Missing"); got != "" {
		t.Errorf("propString(Missing) = %q, want empty", got)
	}
}

func TestPropUint32(t *testing.T) {
	t.Parallel()

	props := map[string]interface{}{
		"PID32":   uint32(1234),
		"PID64":   uint64(5678),
		"PIDInt":  int(9012),
		"String":  "not a number",
		"Float":   3.14,
	}

	if got := propUint32(props, "PID32"); got != 1234 {
		t.Errorf("propUint32(PID32) = %d", got)
	}
	if got := propUint32(props, "PID64"); got != 5678 {
		t.Errorf("propUint32(PID64) = %d", got)
	}
	if got := propUint32(props, "PIDInt"); got != 9012 {
		t.Errorf("propUint32(PIDInt) = %d", got)
	}
	if got := propUint32(props, "String"); got != 0 {
		t.Errorf("propUint32(String) = %d, want 0", got)
	}
	if got := propUint32(props, "Float"); got != 0 {
		t.Errorf("propUint32(Float) = %d, want 0", got)
	}
	if got := propUint32(props, "Missing"); got != 0 {
		t.Errorf("propUint32(Missing) = %d, want 0", got)
	}
}

func TestPropUint64(t *testing.T) {
	t.Parallel()

	props := map[string]interface{}{
		"Mem64":  uint64(52428800),
		"Mem32":  uint32(1048576),
		"MemInt": int(2097152),
		"String": "nope",
	}

	if got := propUint64(props, "Mem64"); got != 52428800 {
		t.Errorf("propUint64(Mem64) = %d", got)
	}
	if got := propUint64(props, "Mem32"); got != 1048576 {
		t.Errorf("propUint64(Mem32) = %d", got)
	}
	if got := propUint64(props, "MemInt"); got != 2097152 {
		t.Errorf("propUint64(MemInt) = %d", got)
	}
	if got := propUint64(props, "String"); got != 0 {
		t.Errorf("propUint64(String) = %d, want 0", got)
	}
}

func TestUnitStatusFields(t *testing.T) {
	t.Parallel()

	s := UnitStatus{
		Name:                "test.service",
		Description:         "Test",
		LoadState:           "loaded",
		ActiveState:         "active",
		SubState:            "running",
		UnitFileState:       "enabled",
		MainPID:             42,
		MemoryBytes:         1024,
		ActiveEnterTimestamp: "1714838400000000",
	}

	if s.Name != "test.service" {
		t.Errorf("Name = %q", s.Name)
	}
	if s.UnitFileState != "enabled" {
		t.Errorf("UnitFileState = %q", s.UnitFileState)
	}
	if s.ActiveEnterTimestamp != "1714838400000000" {
		t.Errorf("ActiveEnterTimestamp = %q", s.ActiveEnterTimestamp)
	}
}
