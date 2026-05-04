package config

import (
	"encoding/json"

	"github.com/rsturla/hbctl/internal/health"
	"github.com/rsturla/hbctl/internal/plugin"
	"github.com/rsturla/hbctl/internal/system/kargs"
	"github.com/rsturla/hbctl/internal/system/network"
)

type Plugin struct {
	network network.Manager
	kargs   kargs.Manager
}

func init() {
	plugin.Register("config", New)
}

func New(_ json.RawMessage) (plugin.Plugin, error) {
	return &Plugin{
		network: network.NewManager(),
		kargs:   kargs.NewManager(),
	}, nil
}

func (p *Plugin) Name() string { return "config" }

func (p *Plugin) Init() error { return nil }

func (p *Plugin) Network() network.Manager { return p.network }
func (p *Plugin) Kargs() kargs.Manager     { return p.kargs }

func (p *Plugin) HealthChecks() []health.Probe {
	return nil
}
