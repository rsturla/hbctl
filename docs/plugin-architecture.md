# Plugin Architecture

## Vision

hb-agent becomes a thin kernel: gRPC server, authn, authz, health aggregation, and plugin lifecycle. Everything else — services, network, storage, containers, security — is a plugin.

Plugins are compiled in (not dynamically loaded). Each plugin is a Go package that registers its RPCs, health checks, and Cedar resource types at startup.

## Plugin Interface

```go
// internal/plugin/plugin.go

type Plugin interface {
    // Name returns a unique identifier (e.g., "services", "network", "storage")
    Name() string

    // Register adds gRPC services and handlers to the server.
    // Each plugin defines its own proto service.
    Register(srv *Server)

    // HealthChecks returns probes that the health aggregator runs.
    HealthChecks() []health.Probe

    // ResourceTypes returns Cedar entity types this plugin introduces.
    // Used to validate Cedar policies at load time.
    ResourceTypes() []authz.ResourceType
}

type Server struct {
    Registrar grpc.ServiceRegistrar
    Authz     authz.Authorizer
    Config    map[string]json.RawMessage  // per-plugin config from HB_PLUGIN_<NAME>_CONFIG
}
```

## Health Generalization

Current health is hardcoded: "are crio.service and kubelet.service running?" That's one check type (systemd units) for one use case (Kubernetes).

Generalized health: each plugin contributes probes. The core aggregates them.

```go
// internal/health/health.go

type Status int
const (
    Unknown   Status = 0
    Healthy   Status = 1
    Unhealthy Status = 2
    Degraded  Status = 3  // new: partially healthy
)

type Probe struct {
    Name     string                                        // "systemd:crio.service", "network:dns", "storage:root-fs"
    Check    func(ctx context.Context) (Status, string)    // status + human-readable message
    Critical bool                                          // if true, unhealthy → overall unhealthy
}

type Aggregator struct {
    probes []Probe
}

func (a *Aggregator) Register(probes ...Probe) {
    a.probes = append(a.probes, probes...)
}

func (a *Aggregator) Check(ctx context.Context) *Result {
    result := &Result{Status: Healthy}
    for _, probe := range a.probes {
        status, msg := probe.Check(ctx)
        result.Checks = append(result.Checks, CheckResult{
            Name: probe.Name, Status: status, Message: msg,
        })
        if status == Unhealthy && probe.Critical {
            result.Status = Unhealthy
        } else if status != Healthy && result.Status == Healthy {
            result.Status = Degraded
        }
    }
    return result
}
```

Health proto response becomes richer:

```protobuf
message HealthResponse {
  HealthStatus status = 1;           // overall: HEALTHY, UNHEALTHY, DEGRADED
  repeated HealthCheck checks = 2;   // individual probe results
}

message HealthCheck {
  string name = 1;       // "services:crio.service"
  HealthStatus status = 2;
  string message = 3;    // "active (running) since ..."
  bool critical = 4;
}
```

## Plugin Examples

### services (current systemd functionality)

```go
type ServicesPlugin struct {
    systemd systemd.Manager
    units   []string  // from config
}

func (p *ServicesPlugin) Name() string { return "services" }

func (p *ServicesPlugin) Register(srv *plugin.Server) {
    pb.RegisterServiceManagerServer(srv.Registrar, &serviceHandler{
        systemd: p.systemd,
        az:      srv.Authz,
    })
}

func (p *ServicesPlugin) HealthChecks() []health.Probe {
    var probes []health.Probe
    for _, unit := range p.units {
        unit := unit
        probes = append(probes, health.Probe{
            Name:     "services:" + unit,
            Critical: true,
            Check: func(ctx context.Context) (health.Status, string) {
                st, err := p.systemd.UnitStatus(ctx, unit)
                if err != nil { return health.Unhealthy, err.Error() }
                if st.ActiveState == "active" { return health.Healthy, st.SubState }
                return health.Unhealthy, st.ActiveState + "/" + st.SubState
            },
        })
    }
    return probes
}

func (p *ServicesPlugin) ResourceTypes() []authz.ResourceType {
    return []authz.ResourceType{authz.ResourceService}
}
```

### network

```go
type NetworkPlugin struct {
    manager network.Manager
}

func (p *NetworkPlugin) HealthChecks() []health.Probe {
    return []health.Probe{
        {Name: "network:dns", Critical: false, Check: p.checkDNS},
        {Name: "network:default-route", Critical: true, Check: p.checkDefaultRoute},
        {Name: "network:connectivity", Critical: false, Check: p.checkConnectivity},
    }
}

// Proto: NetworkManagerService
// RPCs: ListInterfaces, ConfigureInterface, ListRoutes, AddRoute, ...
// Cedar resources: Network::"eth0", Route::"default"
```

### storage

```go
type StoragePlugin struct{}

func (p *StoragePlugin) HealthChecks() []health.Probe {
    return []health.Probe{
        {Name: "storage:root-fs", Critical: true, Check: p.checkRootFS},
        {Name: "storage:disk-pressure", Critical: true, Check: p.checkDiskPressure},
        {Name: "storage:inode-pressure", Critical: false, Check: p.checkInodePressure},
    }
}

// Proto: StorageManagerService
// RPCs: ListVolumes, Mount, Unmount, LVMStatus, EncryptVolume, ...
// Cedar resources: Volume::"/dev/sda1", Mount::"/var"
```

### security

```go
type SecurityPlugin struct{}

func (p *SecurityPlugin) HealthChecks() []health.Probe {
    return []health.Probe{
        {Name: "security:selinux", Critical: true, Check: p.checkSELinux},
        {Name: "security:fips", Critical: false, Check: p.checkFIPS},
        {Name: "security:composefs", Critical: true, Check: p.checkComposefs},
        {Name: "security:tpm", Critical: false, Check: p.checkTPM},
    }
}

// Proto: SecurityManagerService
// RPCs: SELinuxStatus, AuditRules, SeccompProfiles, CertificateStatus, ...
// Cedar resources: Policy::"selinux", Audit::"rule-1"
```

### containers

```go
type ContainersPlugin struct{}

func (p *ContainersPlugin) HealthChecks() []health.Probe {
    return []health.Probe{
        {Name: "containers:runtime", Critical: true, Check: p.checkCRIO},
        {Name: "containers:image-storage", Critical: false, Check: p.checkImageStorage},
    }
}

// Proto: ContainerManagerService
// RPCs: ListContainers, InspectContainer, ListImages, PullImage, ...
// Cedar resources: Container::"abc123", Image::"registry.example.com/app:v1"
```

### observability (eBPF)

```go
type ObservabilityPlugin struct{}

func (p *ObservabilityPlugin) HealthChecks() []health.Probe {
    return []health.Probe{
        {Name: "observability:ebpf", Critical: false, Check: p.checkBPFSupport},
        {Name: "observability:metrics-export", Critical: false, Check: p.checkMetricsEndpoint},
    }
}

// Proto: ObservabilityService
// RPCs: StreamSyscalls, StreamNetworkFlows, ListBPFPrograms, ...
// Cedar resources: BPFProgram::"file-monitor", Metric::"node_cpu_seconds_total"
```

## Agent Startup

```go
func main() {
    cfg := config.Load()

    // Core
    az := createAuthorizer(cfg)
    healthAgg := health.NewAggregator()

    // Register plugins
    plugins := []plugin.Plugin{
        services.New(cfg),      // always present
        diagnostics.New(cfg),   // always present (logs, dmesg, stats)
        lifecycle.New(cfg),     // upgrade, rollback, reboot
        machineconfig.New(cfg), // network, kargs, dns, hostname
    }

    // Optional plugins based on config
    if cfg.PluginEnabled("containers") {
        plugins = append(plugins, containers.New(cfg))
    }
    if cfg.PluginEnabled("security") {
        plugins = append(plugins, security.New(cfg))
    }
    if cfg.PluginEnabled("observability") {
        plugins = append(plugins, observability.New(cfg))
    }

    // Register all plugins
    srv := plugin.NewServer(grpcServer, az, cfg)
    for _, p := range plugins {
        p.Register(srv)
        healthAgg.Register(p.HealthChecks()...)
        slog.Info("plugin registered", "name", p.Name())
    }

    // Core RPCs (Version, Health, Bootstrap)
    registerCoreRPCs(grpcServer, az, healthAgg)
}
```

## Cedar Policy Evolution

With plugins, Cedar policies become per-subsystem:

```cedar
// 01-sre-services.cedar
permit(
  principal in Group::"sre",
  action in [Action::"ServiceStatus", Action::"ServiceControl"],
  resource is Service
);

// 02-sre-network-readonly.cedar
permit(
  principal in Group::"sre",
  action in [Action::"ListInterfaces", Action::"ListRoutes"],
  resource is Network
);

// 03-admin-storage.cedar
permit(
  principal in Group::"admins",
  action,
  resource is Volume
);

// 04-deny-security-changes.cedar
forbid(
  principal,
  action in [Action::"DisableSELinux", Action::"ModifyAuditRules"],
  resource is Policy
) unless { principal in Group::"security-admins" };

// 05-observability-readonly.cedar
permit(
  principal in Group::"monitoring",
  action in [Action::"StreamSyscalls", Action::"StreamNetworkFlows", Action::"ListBPFPrograms"],
  resource is BPFProgram
);
```

## Health Output Example

```
$ hbctl health
Status: DEGRADED

NAME                         STATUS     CRITICAL  MESSAGE
services:crio.service        HEALTHY    yes       running
services:kubelet.service     HEALTHY    yes       running
network:default-route        HEALTHY    yes       via 10.0.0.1 dev eth0
network:dns                  UNHEALTHY  no        cannot resolve api.example.com
network:connectivity         HEALTHY    no        reachable
storage:root-fs              HEALTHY    yes       composefs verified
storage:disk-pressure        HEALTHY    yes       82% used
security:selinux             HEALTHY    yes       enforcing
security:fips                HEALTHY    no        enabled
containers:runtime           HEALTHY    yes       cri-o v1.35.0
observability:ebpf           HEALTHY    no        BTF available, 3 programs loaded
```

Overall = DEGRADED because DNS check failed (non-critical).
Would be UNHEALTHY if any critical check failed.
Watchdog only pings when all critical checks pass.

## Proto Structure

Each plugin defines its own `.proto` file and gRPC service:

```
api/proto/hb/v1alpha1/
  core.proto            # Version, Health, Bootstrap (always present)
  services.proto        # ServiceControl, ServiceStatus
  diagnostics.proto     # Logs, Dmesg, Stats
  lifecycle.proto       # Upgrade, Rollback, Reboot
  config.proto          # GetConfig, ApplyConfig
  network.proto         # ListInterfaces, ConfigureInterface, ...
  storage.proto         # ListVolumes, Mount, ...
  security.proto        # SELinuxStatus, AuditRules, ...
  containers.proto      # ListContainers, InspectContainer, ...
  observability.proto   # StreamSyscalls, StreamNetworkFlows, ...
```

All served on the same gRPC port. Client discovers available services via reflection.

## Migration Path

1. Refactor current code into plugins (services, diagnostics, lifecycle, config) — no new features, just restructure
2. Generalize health with aggregator
3. Add network plugin (firewall rules, routes)
4. Add security plugin (SELinux, FIPS, composefs verification)
5. Add containers plugin (cri-o inspection)
6. Add observability plugin (eBPF, metrics export)

Each step is independently shippable. The plugin interface is the contract — stable from step 1.
