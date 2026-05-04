package health

import (
	"context"
	"fmt"
	"testing"
)

type fakeChecker struct {
	result *Result
	err    error
}

func (f *fakeChecker) Check(_ context.Context) (*Result, error) {
	return f.result, f.err
}

func TestCheckerInterface_Healthy(t *testing.T) {
	t.Parallel()

	fc := &fakeChecker{
		result: &Result{
			Status: Healthy,
			Services: []ServiceHealth{
				{Name: "crio.service", State: "active", SubState: "running", Healthy: true},
				{Name: "kubelet.service", State: "active", SubState: "running", Healthy: true},
			},
		},
	}

	var c Checker = fc
	result, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result.Status != Healthy {
		t.Errorf("Status = %d, want Healthy", result.Status)
	}
	if len(result.Services) != 2 {
		t.Errorf("got %d services, want 2", len(result.Services))
	}
}

func TestCheckerInterface_Unhealthy(t *testing.T) {
	t.Parallel()

	fc := &fakeChecker{
		result: &Result{
			Status: Unhealthy,
			Services: []ServiceHealth{
				{Name: "crio.service", State: "active", SubState: "running", Healthy: true},
				{Name: "kubelet.service", State: "inactive", SubState: "dead", Healthy: false},
			},
		},
	}

	var c Checker = fc
	result, _ := c.Check(context.Background())
	if result.Status != Unhealthy {
		t.Errorf("Status = %d, want Unhealthy", result.Status)
	}
}

func TestCheckerInterface_Error(t *testing.T) {
	t.Parallel()

	fc := &fakeChecker{
		err: fmt.Errorf("dbus connection refused"),
	}

	var c Checker = fc
	_, err := c.Check(context.Background())
	if err == nil {
		t.Error("expected error from checker")
	}
}

func TestStatusConstants(t *testing.T) {
	t.Parallel()

	if Unknown != 0 {
		t.Errorf("Unknown = %d, want 0", Unknown)
	}
	if Healthy != 1 {
		t.Errorf("Healthy = %d, want 1", Healthy)
	}
	if Unhealthy != 2 {
		t.Errorf("Unhealthy = %d, want 2", Unhealthy)
	}
}

func TestServiceHealth_StateVariations(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		state    string
		subState string
		healthy  bool
	}{
		{"active+running", "active", "running", true},
		{"active+exited", "active", "exited", true},
		{"inactive+dead", "inactive", "dead", false},
		{"failed+failed", "failed", "failed", false},
		{"activating+start", "activating", "start", false},
		{"deactivating+stop", "deactivating", "stop-sigterm", false},
		{"reloading+reload", "reloading", "reload", false},
		{"active+waiting", "active", "waiting", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sh := ServiceHealth{
				Name:     "test.service",
				State:    tc.state,
				SubState: tc.subState,
				Healthy:  tc.healthy,
			}
			if sh.Healthy != tc.healthy {
				t.Errorf("Healthy = %v, want %v for state=%s sub=%s", sh.Healthy, tc.healthy, tc.state, tc.subState)
			}
		})
	}
}

func TestNewSystemdChecker(t *testing.T) {
	t.Parallel()

	units := []string{"crio.service", "kubelet.service"}
	c := NewSystemdChecker(units)

	if len(c.units) != 2 {
		t.Errorf("units length = %d, want 2", len(c.units))
	}
	if c.units[0] != "crio.service" {
		t.Errorf("units[0] = %q, want crio.service", c.units[0])
	}
}

func TestNewSystemdChecker_EmptyUnits(t *testing.T) {
	t.Parallel()

	c := NewSystemdChecker(nil)
	if len(c.units) != 0 {
		t.Errorf("units length = %d, want 0", len(c.units))
	}
}

func TestResult_NoServices(t *testing.T) {
	t.Parallel()

	r := &Result{
		Status:   Healthy,
		Services: nil,
	}
	if r.Status != Healthy {
		t.Errorf("Status = %d, want Healthy", r.Status)
	}
	if r.Services != nil {
		t.Errorf("Services = %v, want nil", r.Services)
	}
}

func TestResult_MixedServices(t *testing.T) {
	t.Parallel()

	r := &Result{
		Status: Unhealthy,
		Services: []ServiceHealth{
			{Name: "a.service", State: "active", SubState: "running", Healthy: true},
			{Name: "b.service", State: "failed", SubState: "failed", Healthy: false},
			{Name: "c.service", State: "active", SubState: "running", Healthy: true},
		},
	}

	healthyCount := 0
	for _, svc := range r.Services {
		if svc.Healthy {
			healthyCount++
		}
	}
	if healthyCount != 2 {
		t.Errorf("healthy services = %d, want 2", healthyCount)
	}
}
