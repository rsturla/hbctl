package diagnostics

import (
	"encoding/json"

	"github.com/rsturla/hbctl/internal/health"
	"github.com/rsturla/hbctl/internal/plugin"
	"github.com/rsturla/hbctl/internal/system/journal"
	"github.com/rsturla/hbctl/internal/system/proc"
)

type Plugin struct {
	journal journal.Reader
	proc    proc.Reader
}

func init() {
	plugin.Register("diagnostics", New)
}

func New(_ json.RawMessage) (plugin.Plugin, error) {
	return &Plugin{
		journal: journal.NewReader(),
		proc:    proc.NewReader([]string{"/", "/var"}),
	}, nil
}

func (p *Plugin) Name() string { return "diagnostics" }

func (p *Plugin) Init() error { return nil }

func (p *Plugin) Journal() journal.Reader { return p.journal }
func (p *Plugin) Proc() proc.Reader       { return p.proc }

func (p *Plugin) HealthChecks() []health.Probe {
	return nil
}
