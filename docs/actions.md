# Action Naming Convention

## Format

```
<plugin>:<Verb><Noun>
```

- **plugin** — lowercase, matches the plugin name (e.g., `core`, `services`, `diagnostics`, `config`, `lifecycle`)
- **Verb** — from the closed set below, PascalCase
- **Noun** — PascalCase, what the action operates on

Examples: `services:StartService`, `lifecycle:StageUpgrade`, `diagnostics:StreamLogs`

## Allowed Verbs

| Verb | Meaning | Mutating? | Example |
|------|---------|-----------|---------|
| `Get` | Read a single resource | No | `core:GetVersion` |
| `Describe` | Read detailed resource info | No | `services:DescribeService` |
| `List` | Read multiple resources | No | `services:ListServices` (future) |
| `Stream` | Server-streaming read | No | `diagnostics:StreamLogs` |
| `Put` | Create or replace configuration | Yes | `config:PutConfig` |
| `Start` | Start a resource or operation | Yes | `services:StartService`, `lifecycle:StartReboot` |
| `Stop` | Stop a resource | Yes | `services:StopService` |
| `Restart` | Restart a resource | Yes | `services:RestartService` |
| `Stage` | Prepare but don't activate | Yes | `lifecycle:StageUpgrade` |
| `Rollback` | Revert to previous state | Yes | `lifecycle:RollbackUpgrade` |
| `Bootstrap` | Initial credential setup | Yes | `core:BootstrapAuth` |

No other verbs are allowed. The handler framework panics at startup if an action uses an unrecognized verb.

## Enforcement

Actions are validated at handler construction time:

```go
// This works — verb is in the allowed set
handler.NewUnary(handler.Action("services", handler.VerbStart, "Service"), ...)

// This panics — "Delete" is not an allowed verb
handler.NewUnary(handler.Action("services", "Delete", "Service"), ...)

// This panics — format doesn't match <plugin>:<Verb><Noun>
handler.NewUnary("bad-format", ...)
```

The `handler.Action()` constructor validates format and verb, returning the string only if valid.

## Current Actions

| Action | Plugin | Verb | Resource Type |
|--------|--------|------|---------------|
| `core:GetVersion` | core | Get | Node |
| `core:GetHealth` | core | Get | Node |
| `core:BootstrapAuth` | core | Bootstrap | Node |
| `diagnostics:GetStats` | diagnostics | Get | Node |
| `diagnostics:StreamLogs` | diagnostics | Stream | Node |
| `diagnostics:StreamDmesg` | diagnostics | Stream | Node |
| `services:DescribeService` | services | Describe | Service |
| `services:StartService` | services | Start | Service |
| `services:StopService` | services | Stop | Service |
| `services:RestartService` | services | Restart | Service |
| `config:GetConfig` | config | Get | Node |
| `config:PutConfig` | config | Put | Config |
| `lifecycle:StageUpgrade` | lifecycle | Stage | Image |
| `lifecycle:RollbackUpgrade` | lifecycle | Rollback | Node |
| `lifecycle:StartReboot` | lifecycle | Start | Node |

## Cedar Policy Examples

```cedar
// Allow monitoring to read everything
permit(
  principal in Group::"monitoring",
  action in [
    Action::"core:GetVersion",
    Action::"core:GetHealth",
    Action::"diagnostics:GetStats",
    Action::"diagnostics:StreamLogs",
    Action::"diagnostics:StreamDmesg",
    Action::"services:DescribeService",
    Action::"config:GetConfig"
  ],
  resource
);

// SRE can restart services but not stop them
permit(
  principal in Group::"sre",
  action in [
    Action::"services:RestartService",
    Action::"services:DescribeService"
  ],
  resource is Service
);

// Only admins can reboot or upgrade
permit(
  principal in Group::"admins",
  action in [
    Action::"lifecycle:StartReboot",
    Action::"lifecycle:StageUpgrade",
    Action::"lifecycle:RollbackUpgrade"
  ],
  resource
);

// Deny stop for everyone except admins
forbid(
  principal,
  action == Action::"services:StopService",
  resource
) unless { principal in Group::"admins" };
```

## Adding New Actions

1. Choose the plugin and verb from the allowed set
2. Use `handler.Action("plugin", handler.VerbXxx, "Noun")` to construct the action
3. The framework validates the format — invalid actions panic at startup
4. Document the new action in this file
5. Add Cedar policy examples showing how to authorize it
