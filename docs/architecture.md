# Architecture

## Overview

```
hbctl ──mTLS──> hb-agent ──> plugins ──> system
```

hb-agent is a single-process gRPC server. All interactions with the host OS go through plugins. The handler framework enforces authentication and authorization on every request.

## Handler Framework

Every RPC is wrapped in `handler.Unary` or `handler.ServerStream`. These types require a typed `authz.Resource` extractor at construction time — the server panics at startup if any handler is missing one.

```go
upgradeH: handler.NewUnary("Upgrade",
    func(req *pb.UpgradeRequest) authz.Resource {
        return authz.ImageResource(req.Image)    // REQUIRED
    },
    func(ctx context.Context, req *pb.UpgradeRequest) (*pb.UpgradeResponse, error) {
        // business logic — auth already happened
    },
)
```

The `Execute` method enforces the auth chain:

1. Extract identity from context (injected by authn interceptor)
2. Extract resource from request (via the extractor function)
3. Validate resource (typed, non-empty)
4. Authorize via the authz provider (Cedar, allow-all)
5. Call the handler function

If any step fails, the handler function is never called.

## Request Flow

```
Client
  │
  ▼
TLS handshake (mTLS, TLS 1.3, ECDSA P-256)
  │
  ▼
authn interceptor → Identity in context
  │
  ▼
handler.Execute
  ├── extract Resource from request
  ├── validate Resource
  ├── authorize (Identity, Action, Resource) via Cedar
  └── call handler function
  │
  ▼
Plugin system interaction (systemd, bootc, journalctl, /proc)
  │
  ▼
Response
```

## Plugin System

Plugins are compiled into the binary and activated via `HB_PLUGINS`. Each plugin:

- Has a `Factory` function registered in a `plugin.Registry`
- Provides `HealthChecks()` (probes for the health aggregator)
- Exposes typed accessors for its system managers (e.g., `Systemd()`, `Bootc()`)

The registry pattern is consistent across all extension points:

```go
// Authentication
authn.Registry → Register("mtls", mtls.New)

// Authorization
authz.Registry → Register("cedar", cedar.New)

// Plugins
plugin.Registry → Register("services", services.New)
```

## Health Aggregation

Each plugin contributes probes. The core aggregates them:

- **Healthy** — all probes pass
- **Degraded** — non-critical probes failing
- **Unhealthy** — critical probes failing

The systemd watchdog only pings when status is not Unhealthy. Degraded is acceptable for watchdog (the node is functional but impaired).

## Binary Layout

```
cmd/
  hb-agent/       Agent entrypoint — wires plugins, auth, server
  hbctl/           CLI client — subcommand dispatch, gRPC calls

internal/
  agent/           gRPC server wiring
  api/v1alpha1/    RPC handler implementations
  authn/           Authentication framework + providers (mtls, token)
  authz/           Authorization framework + Cedar provider
  bootstrap/       CSR-based credential bootstrap
  client/          gRPC client wrapper for hbctl
  config/          Env-based configuration
  gen/             Generated protobuf code
  handler/         Auth-by-default handler framework
  health/          Health probe aggregator
  machineconfig/   Machine config apply/read logic
  pki/             CA/cert generation, TLS config
  plugin/          Plugin registry and interface
  system/          System interaction wrappers
    bootc/         bootc CLI wrapper
    journal/       journalctl subprocess wrapper
    kargs/         bootc kargs.d TOML manager
    network/       systemd-networkd file manager
    proc/          /proc stats reader
    systemd/       systemd D-Bus wrapper
  upgrade/         Upgrade orchestration
  validate/        Input validation

plugins/
  services/        Systemd unit management
  diagnostics/     Logs, dmesg, stats
  lifecycle/       Upgrade, rollback, reboot
  config/          Network, kargs, DNS, hostname

api/proto/
  hb/v1alpha1/     Protobuf service definition
```
