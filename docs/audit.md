# Audit Logging

## Overview

Every security-relevant event is logged to an append-only file with HMAC-SHA256 integrity chain. Tampering and deletion are detectable via `audit.VerifyLog()`.

Audit is built into the handler framework — RPCs are logged automatically. Bootstrap and agent lifecycle events are logged explicitly.

## Event Types

### RPC Events (automatic via handler framework)

Every RPC emits an audit event with the outcome. The event `type` field is `rpc.<action>` where `<action>` is the standardized action name.

See [actions.md](actions.md) for the complete list of actions, verbs, and resource types.

### Bootstrap Events (manual)

| Action | Type | Description |
|--------|------|-------------|
| `BootstrapAuth` | `bootstrap` | Credential issuance attempt |

### Lifecycle Events (manual)

| Action | Type | Description |
|--------|------|-------------|
| `startup` | `lifecycle.startup` | Agent started |
| `shutdown` | `lifecycle.shutdown` | Agent shutting down |
| `health_change` | `lifecycle.health_change` | Health state transition (detail: from/to) |

## Outcomes

| Outcome | When |
|---------|------|
| `success` | RPC completed, bootstrap succeeded, agent started/stopped |
| `denied` | Authorization denied, bootstrap token invalid |
| `error` | Authorization error, handler error |
| `unauthenticated` | No identity in context (missing or invalid credentials) |
| `healthy` | Health state changed to healthy |
| `degraded` | Health state changed to degraded |
| `unhealthy` | Health state changed to unhealthy |

## Event Format

JSON lines, one event per line:

```json
{
  "ts": "2026-05-05T01:23:45.678Z",
  "id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "type": "rpc.services:StartService",
  "identity": "admin@corp.com",
  "action": "services:StartService",
  "resource_type": "Service",
  "resource_id": "crio.service",
  "outcome": "success",
  "peer": "10.0.0.1:54321",
  "prev_hash": "abc123...",
  "hash": "def456..."
}
```

## Integrity Chain

Each event's `hash` is an HMAC-SHA256 over all fields including `prev_hash`. This creates a chain:

```
genesis → event1.hash → event2.hash → event3.hash → ...
```

Tampering with any event breaks the chain from that point forward. Deleting an event creates a gap (`prev_hash` won't match).

Verify with:
```go
result, err := audit.VerifyLog("/var/log/hummingbird/audit/audit.log", "/var/log/hummingbird/audit/hmac.key")
// result.BrokenChain > 0 means tampering or deletion detected
```

## Exclude Rules

Suppress audit for specific identity+action+resource combinations. Failures are NEVER excluded.

```json
{
  "excludes": [
    {"identity": "prometheus", "action": "Health"},
    {"identity": "prometheus", "action": "Stats"},
    {"identity": "prometheus", "action": "ServiceStatus", "resource": "crio.service"},
    {"identity": "healthcheck-bot"}
  ]
}
```

| Rule | Effect |
|------|--------|
| `{"identity":"prometheus","action":"Health"}` | Suppress prometheus Health success only |
| `{"identity":"prometheus","action":"ServiceStatus","resource":"crio.service"}` | Suppress prometheus checking crio status only |
| `{"identity":"healthcheck-bot"}` | Suppress all healthcheck-bot successes |

If prometheus calls `Reboot` — **logged** (not in exclude rules).
If prometheus gets `denied` on Health — **logged** (failures never excluded).

## Configuration

```
Audit directory: /var/log/hummingbird/audit (default)
Max size: 100 MB (default)
Max age: 90 days (default)
```

Files:
- `audit.log` — event log (0600)
- `hmac.key` — 32-byte HMAC key (0600)

## SIEM Integration

The JSON lines format is compatible with all major log shippers:

- **Filebeat** → Elasticsearch → Kibana / Azure Sentinel
- **Fluentd** → CrowdStrike Falcon LogScale / Splunk
- **Vector** → any destination
- **Promtail** → Loki → Grafana

No agent code changes needed — configure the shipper to tail `audit.log`.
