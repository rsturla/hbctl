# hbctl

Node management agent and CLI for [bootc](https://containers.github.io/bootc/)-based immutable OS images.

`hb-agent` runs as a systemd service and exposes a gRPC API over mTLS. `hbctl` is the CLI client. Designed for immutable, shell-less systems where the agent is the sole management interface.

## Features

- **13 gRPC RPCs** for node lifecycle, diagnostics, configuration, and service control
- **Auth-by-default** — every handler requires a typed resource and authorized identity
- **Pluggable authentication** — mTLS (default), bearer token, extensible for OIDC/LDAP
- **Pluggable authorization** — [Cedar](https://www.cedarpolicy.com/) policy engine with per-resource granularity
- **Plugin architecture** — compiled-in plugins enabled via config, RPM-friendly
- **Generalized health** — Healthy/Degraded/Unhealthy with per-plugin probes
- **Bootstrap** — CSR-based credential issuance with fingerprint verification
- **Input validation** — all user inputs validated before reaching system commands
- **FIPS-ready** — all crypto via Go stdlib, compatible with `GOEXPERIMENT=systemcrypto`

## Quick Start

```bash
# Build
make build

# Start agent (generates TLS certs on first run)
HB_LOG_FORMAT=text ./bin/hb-agent

# Generate bootstrap token
./bin/hbctl gen-token

# Bootstrap client credentials
./bin/hbctl bootstrap \
  --endpoint 10.0.0.5:50000 \
  --token <token> \
  --ca-fingerprint sha256:<hex> \
  --output-dir ~/.hbctl/

# Use
HBCTL_TLS_DIR=~/.hbctl HBCTL_ENDPOINT=10.0.0.5:50000 ./bin/hbctl health
```

## RPCs

| RPC | Plugin | Description |
|-----|--------|-------------|
| Version | core | Agent version, OS image, digest, staged image |
| Health | core | Aggregated health from all plugin probes |
| BootstrapAuth | core | CSR-based credential issuance (unauthenticated) |
| Logs | diagnostics | Stream journal logs (follow, filter by unit) |
| Dmesg | diagnostics | Stream kernel logs |
| Stats | diagnostics | Memory, CPU, load, disk usage |
| ServiceStatus | services | Systemd unit properties |
| ServiceControl | services | Start/stop/restart systemd units |
| GetConfig | config | Current hostname, network, DNS, kernel args |
| ApplyConfig | config | Apply machine configuration |
| Upgrade | lifecycle | Stage new OS image via `bootc switch` |
| Rollback | lifecycle | Revert to previous deployment |
| Reboot | lifecycle | Trigger system reboot |

## Documentation

- [Architecture](docs/architecture.md) — handler framework, auth model, plugin system
- [Authentication](docs/authentication.md) — mTLS, token auth, bootstrap flow
- [Authorization](docs/authorization.md) — Cedar policies, resource types, examples
- [Plugins](docs/plugins.md) — plugin interface, built-in plugins, configuration
- [Security](docs/security.md) — threat model, input validation, crypto choices
- [Plugin Architecture](docs/plugin-architecture.md) — future plugin design and roadmap

## Configuration

### Agent (`hb-agent`)

| Variable | Default | Description |
|----------|---------|-------------|
| `HB_LISTEN_ADDR` | `:50000` | gRPC listen address |
| `HB_TLS_DIR` | `/var/lib/hummingbird/pki` | PKI directory |
| `HB_LOG_FORMAT` | `json` | `json` or `text` |
| `HB_HEALTH_INTERVAL` | `10s` | Health check / watchdog interval |
| `HB_AUTH_METHOD` | `mtls` | Authentication method |
| `HB_AUTH_CONFIG` | | JSON config for auth provider |
| `HB_AUTHZ_METHOD` | `allow-all` | Authorization method |
| `HB_AUTHZ_CONFIG` | | JSON config for authz provider |
| `HB_PLUGINS` | `services,diagnostics,lifecycle,config` | Enabled plugins |

### CLI (`hbctl`)

```bash
hbctl --endpoint 10.0.0.5:50000 --tls-dir ~/.hbctl/certs health
```

| Flag / Variable | Default | Description |
|----------------|---------|-------------|
| `--endpoint` / `HBCTL_ENDPOINT` | `127.0.0.1:50000` | Agent address |
| `--tls-dir` / `HBCTL_TLS_DIR` | `/var/lib/hummingbird/pki` | Directory with `ca.crt`, `client.crt`, `client.key` |
| `-o`, `--output` / `HBCTL_OUTPUT` | `text` | Output format: `text` or `json` |

Flags override environment variables.

JSON output example:
```bash
hbctl -o json health
hbctl --output json stats
```

## Build

```bash
make build       # build hb-agent + hbctl
make test        # run tests
make test-race   # tests with race detector
make fuzz        # fuzz all targets (10s each)
make lint        # golangci-lint
make check       # lint + test-race + build (CI entrypoint)
make proto       # regenerate protobuf code
make tools       # install protoc-gen-go, protoc-gen-go-grpc
```

## License

Apache-2.0
