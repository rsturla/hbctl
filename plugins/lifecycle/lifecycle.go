package lifecycle

import (
	"context"
	"encoding/json"

	"github.com/rsturla/hbctl/internal/health"
	"github.com/rsturla/hbctl/internal/plugin"
	"github.com/rsturla/hbctl/internal/system/bootc"
)

type Plugin struct {
	bootc bootc.Manager
}

func init() {
	plugin.Register("lifecycle", New)
}

func New(_ json.RawMessage) (plugin.Plugin, error) {
	return &Plugin{
		bootc: bootc.NewCLI(),
	}, nil
}

func (p *Plugin) Name() string { return "lifecycle" }

func (p *Plugin) Init() error { return nil }

func (p *Plugin) Bootc() bootc.Manager { return p.bootc }

func (p *Plugin) HealthChecks() []health.Probe {
	return []health.Probe{
		{
			Name:     "lifecycle:bootc",
			Critical: false,
			Check: func(ctx context.Context) (health.Status, string) {
				st, err := p.bootc.Status(ctx)
				if err != nil {
					return health.Unknown, err.Error()
				}
				msg := st.Image
				if st.Staged != "" {
					msg += " (staged: " + st.Staged + ")"
				}
				return health.Healthy, msg
			},
		},
	}
}
