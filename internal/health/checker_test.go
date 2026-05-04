package health

import (
	"context"
	"testing"
)

func TestAggregator_AllHealthy(t *testing.T) {
	t.Parallel()
	agg := NewAggregator()
	agg.Register(
		Probe{Name: "a", Critical: true, Check: func(_ context.Context) (Status, string) { return Healthy, "ok" }},
		Probe{Name: "b", Critical: true, Check: func(_ context.Context) (Status, string) { return Healthy, "ok" }},
	)
	result, err := agg.Check(context.Background())
	if err != nil { t.Fatalf("Check: %v", err) }
	if result.Status != Healthy { t.Errorf("Status = %d, want Healthy", result.Status) }
	if len(result.Checks) != 2 { t.Errorf("Checks = %d, want 2", len(result.Checks)) }
}

func TestAggregator_CriticalUnhealthy(t *testing.T) {
	t.Parallel()
	agg := NewAggregator()
	agg.Register(
		Probe{Name: "ok", Critical: true, Check: func(_ context.Context) (Status, string) { return Healthy, "running" }},
		Probe{Name: "bad", Critical: true, Check: func(_ context.Context) (Status, string) { return Unhealthy, "dead" }},
	)
	result, _ := agg.Check(context.Background())
	if result.Status != Unhealthy { t.Errorf("Status = %d, want Unhealthy", result.Status) }
}

func TestAggregator_NonCriticalUnhealthy_Degraded(t *testing.T) {
	t.Parallel()
	agg := NewAggregator()
	agg.Register(
		Probe{Name: "core", Critical: true, Check: func(_ context.Context) (Status, string) { return Healthy, "ok" }},
		Probe{Name: "dns", Critical: false, Check: func(_ context.Context) (Status, string) { return Unhealthy, "timeout" }},
	)
	result, _ := agg.Check(context.Background())
	if result.Status != Degraded { t.Errorf("Status = %d, want Degraded", result.Status) }
}

func TestAggregator_Empty(t *testing.T) {
	t.Parallel()
	agg := NewAggregator()
	result, _ := agg.Check(context.Background())
	if result.Status != Healthy { t.Errorf("empty should be Healthy, got %d", result.Status) }
}

func TestAggregator_CheckResultFields(t *testing.T) {
	t.Parallel()
	agg := NewAggregator()
	agg.Register(Probe{Name: "test:unit", Critical: true, Check: func(_ context.Context) (Status, string) { return Healthy, "running" }})
	result, _ := agg.Check(context.Background())
	if len(result.Checks) != 1 { t.Fatal("expected 1 check") }
	c := result.Checks[0]
	if c.Name != "test:unit" { t.Errorf("Name = %q", c.Name) }
	if c.Status != Healthy { t.Errorf("Status = %d", c.Status) }
	if c.Message != "running" { t.Errorf("Message = %q", c.Message) }
	if !c.Critical { t.Error("Critical should be true") }
}

func TestStatusConstants(t *testing.T) {
	t.Parallel()
	if Unknown != 0 { t.Errorf("Unknown = %d", Unknown) }
	if Healthy != 1 { t.Errorf("Healthy = %d", Healthy) }
	if Unhealthy != 2 { t.Errorf("Unhealthy = %d", Unhealthy) }
	if Degraded != 3 { t.Errorf("Degraded = %d", Degraded) }
}

func TestSystemdUnitProbes(t *testing.T) {
	t.Parallel()
	probes := SystemdUnitProbes([]string{"a.service", "b.service"})
	if len(probes) != 2 { t.Fatalf("probes = %d, want 2", len(probes)) }
	if probes[0].Name != "services:a.service" { t.Errorf("Name = %q", probes[0].Name) }
	if !probes[0].Critical { t.Error("systemd probes should be critical") }
}

func TestCheckerInterface(t *testing.T) {
	t.Parallel()
	var c Checker = NewAggregator()
	result, err := c.Check(context.Background())
	if err != nil { t.Fatalf("Check: %v", err) }
	if result.Status != Healthy { t.Errorf("Status = %d", result.Status) }
}
