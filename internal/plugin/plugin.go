package plugin

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/rsturla/hbctl/internal/health"
)

type Plugin interface {
	Name() string
	Init() error
	HealthChecks() []health.Probe
}

type Factory func(cfg json.RawMessage) (Plugin, error)


var (
	mu        sync.Mutex
	factories = make(map[string]Factory)
)

func Register(name string, factory Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := factories[name]; ok {
		panic(fmt.Sprintf("plugin already registered: %q", name))
	}
	factories[name] = factory
	slog.Debug("plugin factory registered", "name", name)
}

func Available() []string {
	mu.Lock()
	defer mu.Unlock()
	names := make([]string, 0, len(factories))
	for name := range factories {
		names = append(names, name)
	}
	return names
}

func Create(name string, cfg json.RawMessage) (Plugin, error) {
	mu.Lock()
	factory, ok := factories[name]
	mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown plugin: %q (available: %v)", name, Available())
	}
	return factory(cfg)
}
