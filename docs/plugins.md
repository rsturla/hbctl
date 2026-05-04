# Plugins

## Overview

Plugins are compiled into the `hb-agent` binary and activated via the `HB_PLUGINS` environment variable. This model supports RPM packaging — one binary ships all plugins, configuration controls what runs.

## Built-in Plugins

### services (default)

Systemd unit management.

**RPCs:** ServiceStatus, ServiceControl (start/stop/restart)
**Health probes:** One probe per configured unit (critical)
**Resources:** `Service::"<unit-name>"`

### diagnostics (default)

System observability.

**RPCs:** Logs, Dmesg, Stats
**Health probes:** None (it IS the observability)
**Resources:** `Node::"*"` (read-only)

### lifecycle (default)

OS image lifecycle.

**RPCs:** Upgrade, Rollback, Reboot
**Health probes:** `lifecycle:bootc` (non-critical, reports current image)
**Resources:** `Image::"<ref>"`, `Node::"*"`

### config (default)

Machine configuration.

**RPCs:** GetConfig, ApplyConfig
**Health probes:** None
**Resources:** `Config::"machine"`

## Configuration

Enable plugins via environment variable:

```bash
# Default set
HB_PLUGINS=services,diagnostics,lifecycle,config

# Minimal (diagnostics only)
HB_PLUGINS=diagnostics

# With future plugins
HB_PLUGINS=services,diagnostics,lifecycle,config,firewall,security
```

Plugins not listed in `HB_PLUGINS` are never instantiated — no goroutines, no health probes, no D-Bus connections.

## Plugin Interface

```go
type Plugin interface {
    Name() string
    Init() error
    HealthChecks() []health.Probe
}
```

Plugins are registered in main.go via the `plugin.Registry`:

```go
registry := plugin.NewRegistry()
registry.Register("services", func(cfg json.RawMessage) (plugin.Plugin, error) {
    return services.New(cfg)
})
```

## Writing a New Plugin

1. Create `plugins/<name>/<name>.go`
2. Implement the `plugin.Plugin` interface
3. Add a `New(json.RawMessage) (*Plugin, error)` factory
4. Register in `cmd/hb-agent/main.go`'s `newPluginRegistry()`
5. Add health probes for anything the plugin manages
6. Expose typed accessors for system managers (e.g., `Systemd()`)

The handler framework enforces auth — your handlers use `handler.NewUnary` with a resource extractor, same as every other handler.
