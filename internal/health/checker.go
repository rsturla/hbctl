package health

import (
	"context"
	"fmt"
	"sync"

	"github.com/coreos/go-systemd/v22/dbus"
)

type Status int

const (
	Unknown   Status = 0
	Healthy   Status = 1
	Unhealthy Status = 2
	Degraded  Status = 3
)

type Probe struct {
	Name     string
	Critical bool
	Check    func(ctx context.Context) (Status, string)
}

type CheckResult struct {
	Name     string
	Status   Status
	Message  string
	Critical bool
}

type Result struct {
	Status Status
	Checks []CheckResult
}

type Checker interface {
	Check(ctx context.Context) (*Result, error)
}

type Aggregator struct {
	mu     sync.RWMutex
	probes []Probe
}

func NewAggregator() *Aggregator {
	return &Aggregator{}
}

func (a *Aggregator) Register(probes ...Probe) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.probes = append(a.probes, probes...)
}

func (a *Aggregator) Check(ctx context.Context) (*Result, error) {
	a.mu.RLock()
	probes := make([]Probe, len(a.probes))
	copy(probes, a.probes)
	a.mu.RUnlock()

	result := &Result{Status: Healthy}

	for _, probe := range probes {
		status, msg := probe.Check(ctx)
		result.Checks = append(result.Checks, CheckResult{
			Name:     probe.Name,
			Status:   status,
			Message:  msg,
			Critical: probe.Critical,
		})

		if status == Unhealthy && probe.Critical {
			result.Status = Unhealthy
		} else if status != Healthy && result.Status == Healthy {
			result.Status = Degraded
		}
	}

	return result, nil
}

func SystemdUnitProbes(units []string) []Probe {
	var probes []Probe
	for _, unit := range units {
		unit := unit
		probes = append(probes, Probe{
			Name:     "services:" + unit,
			Critical: true,
			Check: func(ctx context.Context) (Status, string) {
				conn, err := dbus.NewSystemConnectionContext(ctx)
				if err != nil {
					return Unhealthy, fmt.Sprintf("dbus: %v", err)
				}
				defer conn.Close()

				props, err := conn.GetUnitPropertiesContext(ctx, unit)
				if err != nil {
					return Unhealthy, fmt.Sprintf("query: %v", err)
				}

				activeState, _ := props["ActiveState"].(string)
				subState, _ := props["SubState"].(string)

				if activeState == "active" && (subState == "running" || subState == "exited") {
					return Healthy, subState
				}
				return Unhealthy, activeState + "/" + subState
			},
		})
	}
	return probes
}
