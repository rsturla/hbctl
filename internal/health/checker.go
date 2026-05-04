package health

import (
	"context"
	"fmt"

	"github.com/coreos/go-systemd/v22/dbus"
)

type Status int

const (
	Unknown   Status = 0
	Healthy   Status = 1
	Unhealthy Status = 2
)

type ServiceHealth struct {
	Name     string
	State    string
	SubState string
	Healthy  bool
}

type Result struct {
	Status   Status
	Services []ServiceHealth
}

type Checker interface {
	Check(ctx context.Context) (*Result, error)
}

type SystemdChecker struct {
	units []string
}

func NewSystemdChecker(units []string) *SystemdChecker {
	return &SystemdChecker{units: units}
}

func (c *SystemdChecker) Check(ctx context.Context) (*Result, error) {
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return &Result{Status: Unhealthy}, fmt.Errorf("connect to systemd: %w", err)
	}
	defer conn.Close()

	result := &Result{Status: Healthy}

	for _, unit := range c.units {
		props, err := conn.GetUnitPropertiesContext(ctx, unit)
		if err != nil {
			result.Services = append(result.Services, ServiceHealth{
				Name:    unit,
				State:   "error",
				Healthy: false,
			})
			result.Status = Unhealthy
			continue
		}

		activeState, _ := props["ActiveState"].(string)
		subState, _ := props["SubState"].(string)
		healthy := activeState == "active" && (subState == "running" || subState == "exited")

		result.Services = append(result.Services, ServiceHealth{
			Name:     unit,
			State:    activeState,
			SubState: subState,
			Healthy:  healthy,
		})

		if !healthy {
			result.Status = Unhealthy
		}
	}

	return result, nil
}
