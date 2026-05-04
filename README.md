# hbctl

Node management agent and CLI for [bootc](https://containers.github.io/bootc/)-based immutable OS images.

`hb-agent` runs as a systemd service and exposes a gRPC API over mTLS. `hbctl` is the CLI client.

## RPCs

| RPC | Description |
|-----|-------------|
| `Version` | Agent version, OS image, digest, staged image |
| `Health` | Systemd unit health (configurable units) |
| `Logs` | Stream journal logs (follow, filter by unit) |
| `Dmesg` | Stream kernel logs |
| `Stats` | Memory, CPU, load, disk usage |
| `ServiceStatus` | Detailed systemd unit properties |
| `GetConfig` | Current hostname, network, DNS, kernel args |
| `ApplyConfig` | Apply machine configuration |
| `Upgrade` | Stage new OS image via `bootc switch` |
| `Rollback` | Revert to previous deployment via `bootc rollback` |
| `Reboot` | Trigger system reboot |

## Build

```bash
make build     # builds bin/hb-agent and bin/hbctl
make test      # run tests
make proto     # regenerate protobuf code
```

`hb-agent` requires `CGO_ENABLED=1` and `systemd-devel` (links libsystemd for sdjournal). `hbctl` is a static binary (`CGO_ENABLED=0`).

## Usage

### Agent

```bash
# Start with defaults
hb-agent

# Configure via environment
HB_LISTEN_ADDR=:50000       # gRPC listen address
HB_TLS_DIR=/var/lib/hummingbird/pki  # PKI directory (auto-generated on first boot)
HB_LOG_FORMAT=json           # json or text
HB_HEALTH_INTERVAL=10s       # health check / watchdog interval
HB_HEALTH_UNITS=crio.service,kubelet.service  # units to monitor
```

On first start, the agent generates a self-signed CA and server certificate in the TLS directory. Client certificates are signed by this CA.

### CLI

```bash
hbctl version
hbctl health
hbctl stats
hbctl logs -u sshd.service -n 50
hbctl logs -f                        # follow mode
hbctl dmesg -n 20
hbctl service-status chronyd.service
hbctl config get
hbctl upgrade --image registry.example.com/os:v2.0.0
hbctl rollback
hbctl reboot
```

Configure via environment:

```bash
HBCTL_ENDPOINT=10.0.0.5:50000        # agent address
HBCTL_TLS_DIR=/path/to/certs         # directory with ca.crt, client.crt, client.key
```

## Architecture

```
hbctl ──mTLS──> hb-agent ──> systemd D-Bus (health, unit status)
                         ──> journalctl (log streaming)
                         ──> /proc (memory, CPU, load)
                         ──> bootc CLI (upgrade, rollback, status)
                         ──> filesystem (network config, kargs, DNS)
```

The agent is the sole management interface for immutable nodes. No SSH required.

## Security

- mTLS with TLS 1.3 minimum, ECDSA P-256 keys
- CA + server cert auto-generated on first boot
- Client certs required for all connections
- Systemd hardening: `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`

## License

Apache-2.0
