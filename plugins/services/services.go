package services

import (
	"encoding/json"
	"fmt"

	"github.com/rsturla/hbctl/internal/health"
	"github.com/rsturla/hbctl/internal/system/systemd"
)

type Config struct {
	HealthUnits []string `json:"health_units"`
}

type Plugin struct {
	systemd systemd.Manager
	cfg     Config
}


func New(raw json.RawMessage) (*Plugin, error) {
	var cfg Config
	if raw != nil {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("parse services config: %w", err)
		}
	}
	if len(cfg.HealthUnits) == 0 {
		cfg.HealthUnits = []string{"crio.service", "kubelet.service"}
	}
	return &Plugin{
		systemd: systemd.NewManager(),
		cfg:     cfg,
	}, nil
}

func (p *Plugin) Name() string { return "services" }

func (p *Plugin) Init() error { return nil }

func (p *Plugin) Systemd() systemd.Manager { return p.systemd }

func (p *Plugin) HealthChecks() []health.Probe {
	return health.SystemdUnitProbes(p.cfg.HealthUnits)
}
