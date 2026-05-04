# Authorization

## Overview

Authorization is pluggable via the `authz.Registry`. Set `HB_AUTHZ_METHOD` to select.

The handler framework enforces authorization on every RPC. If no authorizer is configured (`nil`), all requests are denied.

## Providers

### allow-all (default)

Permits all authenticated requests. **Development only.** The agent emits a security warning at startup when this is active.

```
HB_AUTHZ_METHOD=allow-all
```

### Cedar

[Cedar](https://www.cedarpolicy.com/) policy engine with per-resource granularity.

```
HB_AUTHZ_METHOD=cedar
HB_AUTHZ_CONFIG={"policy_dir":"/var/lib/hummingbird/policies"}
```

Policies are loaded from `*.cedar` files in the policy directory. Default deny — if no policy permits the request, it is denied.

## Resource Types

Every RPC targets a typed resource:

| Type | Example | Used by |
|------|---------|---------|
| `Node` | `Node::"*"` | Version, Health, Rollback, Reboot |
| `Service` | `Service::"crio.service"` | ServiceControl, ServiceStatus |
| `Image` | `Image::"registry.example.com/os:v2"` | Upgrade |
| `Config` | `Config::"machine"` | ApplyConfig |
| `Path` | `Path::"/etc/hostname"` | Future file operations |

Read-only RPCs (Version, Health, Stats, Logs, Dmesg, GetConfig) default to `Node::"*"`.

## Cedar Policy Examples

### Admin — full access

```cedar
// policies/01-admins.cedar
permit(
  principal in Group::"admins",
  action,
  resource
);
```

### Read-only monitoring

```cedar
// policies/02-monitoring.cedar
permit(
  principal in Group::"monitoring",
  action in [
    Action::"Version",
    Action::"Health",
    Action::"Stats",
    Action::"Logs",
    Action::"Dmesg",
    Action::"ServiceStatus",
    Action::"GetConfig"
  ],
  resource
);
```

### SRE — service control for specific units

```cedar
// policies/03-sre-services.cedar
permit(
  principal in Group::"sre",
  action in [Action::"ServiceControl", Action::"ServiceStatus"],
  resource in [Service::"crio.service", Service::"kubelet.service"]
);
```

### Deny reboot for non-admins

```cedar
// policies/04-deny-reboot.cedar
forbid(
  principal,
  action == Action::"Reboot",
  resource
) unless { principal in Group::"admins" };
```

### Upgrade restricted to specific images

```cedar
// policies/05-upgrade-policy.cedar
permit(
  principal in Group::"release-managers",
  action == Action::"Upgrade",
  resource is Image
);
```

## Identity Mapping

Identity comes from the authentication provider:

| Auth Method | Name | Groups |
|-------------|------|--------|
| mTLS | Certificate CN | Certificate Organization |
| Token | `"bearer-token"` | (none) |
| OIDC (future) | `sub` claim | `groups` claim |

Cedar policies reference these as `User::"<name>"` and `Group::"<group>"`.
