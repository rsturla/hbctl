package plugin

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/rsturla/hbctl/internal/health"
)

type Plugin interface {
	Name() string
	Init() error
	HealthChecks() []health.Probe
}

type Factory func(cfg json.RawMessage) (Plugin, error)

type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]Factory)}
}

func (r *Registry) Register(name string, factory Factory) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.factories[name]; ok {
		return fmt.Errorf("plugin already registered: %q", name)
	}
	r.factories[name] = factory
	return nil
}

func (r *Registry) Create(name string, cfg json.RawMessage) (Plugin, error) {
	r.mu.RLock()
	factory, ok := r.factories[name]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown plugin: %q (registered: %v)", name, r.Names())
	}
	return factory(cfg)
}

func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	return names
}
