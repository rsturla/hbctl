package v1alpha1

import (
	"context"
	"fmt"
	"runtime"

	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"github.com/rsturla/hbctl/internal/audit"
	"github.com/rsturla/hbctl/internal/authz"
	"github.com/rsturla/hbctl/internal/bootstrap"
	"github.com/rsturla/hbctl/internal/validate"
	"github.com/rsturla/hbctl/internal/handler"
	"github.com/rsturla/hbctl/internal/health"
	"github.com/rsturla/hbctl/internal/machineconfig"
	"github.com/rsturla/hbctl/internal/system/bootc"
	"github.com/rsturla/hbctl/internal/system/journal"
	"github.com/rsturla/hbctl/internal/system/kargs"
	"github.com/rsturla/hbctl/internal/system/network"
	"github.com/rsturla/hbctl/internal/system/proc"
	"github.com/rsturla/hbctl/internal/system/systemd"
	"github.com/rsturla/hbctl/internal/upgrade"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

var version = "0.1.0-dev"

type MachineServer struct {
	pb.UnimplementedMachineServiceServer
	deps handler.Deps

	version        handler.Unary[*pb.VersionRequest, *pb.VersionResponse]
	health         handler.Unary[*pb.HealthRequest, *pb.HealthResponse]
	stats          handler.Unary[*pb.StatsRequest, *pb.StatsResponse]
	serviceStatus  handler.Unary[*pb.ServiceStatusRequest, *pb.ServiceStatusResponse]
	getConfig      handler.Unary[*pb.GetConfigRequest, *pb.GetConfigResponse]
	applyConfig    handler.Unary[*pb.ApplyConfigRequest, *pb.ApplyConfigResponse]
	upgradeH       handler.Unary[*pb.UpgradeRequest, *pb.UpgradeResponse]
	rollback       handler.Unary[*pb.RollbackRequest, *pb.RollbackResponse]
	reboot         handler.Unary[*pb.RebootRequest, *pb.RebootResponse]
	startService   handler.Unary[*pb.ServiceControlRequest, *pb.ServiceControlResponse]
	stopService    handler.Unary[*pb.ServiceControlRequest, *pb.ServiceControlResponse]
	restartService handler.Unary[*pb.ServiceControlRequest, *pb.ServiceControlResponse]
	logs           handler.ServerStream[*pb.LogsRequest, *pb.LogsResponse]
	dmesg          handler.ServerStream[*pb.DmesgRequest, *pb.DmesgResponse]

	bootstrapMgr *bootstrap.Manager
}

type Deps struct {
	Health    health.Checker
	Bootc     bootc.Manager
	Journal   journal.Reader
	Systemd   systemd.Manager
	Proc      proc.Reader
	Network   network.Manager
	Kargs     kargs.Manager
	Bootstrap *bootstrap.Manager
}

func NewMachineServer(srvDeps Deps, az authz.Authorizer, auditLog audit.Logger) *MachineServer {
	diag := NewDiagnosticsServer(srvDeps.Journal, srvDeps.Systemd, srvDeps.Proc)
	cfgSrv := newConfigServerFromDeps(srvDeps)
	upgradeMgr := newUpgradeManagerFromDeps(srvDeps)

	s := &MachineServer{
		deps: handler.Deps{Authz: az, Audit: auditLog},
		bootstrapMgr: srvDeps.Bootstrap,

		// Read-only RPCs — resource is always ThisNode
		version: handler.NewReadOnly(handler.Action("core", handler.VerbGet, "Version"), func(ctx context.Context, _ *pb.VersionRequest) (*pb.VersionResponse, error) {
			resp := &pb.VersionResponse{
				Version:   version,
				GoVersion: runtime.Version(),
			}
			if srvDeps.Bootc != nil {
				st, err := srvDeps.Bootc.Status(ctx)
				if err == nil {
					resp.OsImage = st.Image
					resp.OsVersion = st.Version
					resp.OsImageDigest = st.ImageDigest
					resp.OsStagedImage = st.Staged
				}
			}
			return resp, nil
		}),

		health: handler.NewReadOnly(handler.Action("core", handler.VerbGet, "Health"), func(ctx context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
			result, err := srvDeps.Health.Check(ctx)
			if err != nil {
				return &pb.HealthResponse{Status: pb.HealthStatus_HEALTH_STATUS_UNHEALTHY}, nil
			}
			resp := &pb.HealthResponse{Status: pb.HealthStatus(result.Status)}
			for _, check := range result.Checks {
				resp.Services = append(resp.Services, &pb.ServiceHealth{
					Name:    check.Name,
					State:   check.Message,
					Healthy: check.Status == health.Healthy,
				})
			}
			return resp, nil
		}),

		stats: handler.NewReadOnly(handler.Action("diagnostics", handler.VerbGet, "Stats"), func(ctx context.Context, req *pb.StatsRequest) (*pb.StatsResponse, error) {
			if diag == nil {
				return nil, fmt.Errorf("diagnostics not configured")
			}
			return diag.Stats(ctx, req)
		}),

		serviceStatus: handler.NewUnary(handler.Action("services", handler.VerbDescribe, "Service"),
			func(req *pb.ServiceStatusRequest) authz.Resource {
				if req.Name == "" {
					return authz.ThisNode()
				}
				return authz.ServiceResource(req.Name)
			},
			func(ctx context.Context, req *pb.ServiceStatusRequest) (*pb.ServiceStatusResponse, error) {
				if diag == nil {
					return nil, fmt.Errorf("diagnostics not configured")
				}
				return diag.ServiceStatus(ctx, req)
			},
		),

		getConfig: handler.NewReadOnly(handler.Action("config", handler.VerbGet, "Config"), func(ctx context.Context, req *pb.GetConfigRequest) (*pb.GetConfigResponse, error) {
			if cfgSrv == nil {
				return nil, fmt.Errorf("configuration not configured")
			}
			return cfgSrv.GetConfig(ctx, req)
		}),

		// Mutating RPCs — resource is extracted from request
		applyConfig: handler.NewUnary(handler.Action("config", handler.VerbPut, "Config"),
			func(_ *pb.ApplyConfigRequest) authz.Resource { return authz.ConfigResource("machine") },
			func(ctx context.Context, req *pb.ApplyConfigRequest) (*pb.ApplyConfigResponse, error) {
				if cfgSrv == nil {
					return nil, fmt.Errorf("configuration not configured")
				}
				return cfgSrv.ApplyConfig(ctx, req)
			},
		),

		upgradeH: handler.NewUnary(handler.Action("lifecycle", handler.VerbStage, "Upgrade"),
			func(req *pb.UpgradeRequest) authz.Resource {
				if req.Image == "" {
					return authz.ThisNode()
				}
				return authz.ImageResource(req.Image)
			},
			func(ctx context.Context, req *pb.UpgradeRequest) (*pb.UpgradeResponse, error) {
				if err := validate.ImageRef(req.Image); err != nil {
					return nil, fmt.Errorf("invalid image: %w", err)
				}
				if upgradeMgr == nil {
					return nil, fmt.Errorf("upgrade not configured")
				}
				result, err := upgradeMgr.Upgrade(ctx, req.Image)
				if err != nil {
					return nil, err
				}
				return &pb.UpgradeResponse{
					CurrentImage: result.CurrentImage, CurrentDigest: result.CurrentDigest,
					StagedImage: result.StagedImage, RebootRequired: result.StagedImage != "",
				}, nil
			},
		),

		rollback: handler.NewUnary(handler.Action("lifecycle", handler.VerbRollback, "Upgrade"),
			func(_ *pb.RollbackRequest) authz.Resource { return authz.NodeResource("*") },
			func(ctx context.Context, _ *pb.RollbackRequest) (*pb.RollbackResponse, error) {
				if upgradeMgr == nil {
					return nil, fmt.Errorf("upgrade not configured")
				}
				result, err := upgradeMgr.Rollback(ctx)
				if err != nil {
					return nil, err
				}
				return &pb.RollbackResponse{
					CurrentImage: result.CurrentImage, RollbackImage: result.RollbackImage, RebootRequired: true,
				}, nil
			},
		),

		reboot: handler.NewUnary(handler.Action("lifecycle", handler.VerbStart, "Reboot"),
			func(_ *pb.RebootRequest) authz.Resource { return authz.NodeResource("*") },
			func(ctx context.Context, _ *pb.RebootRequest) (*pb.RebootResponse, error) {
				if upgradeMgr == nil {
					return nil, fmt.Errorf("upgrade not configured")
				}
				return &pb.RebootResponse{}, upgradeMgr.Reboot(ctx)
			},
		),

		startService: handler.NewUnary(handler.Action("services", handler.VerbStart, "Service"),
			serviceResource,
			serviceControlFn(srvDeps.Systemd, func(ctx context.Context, s systemd.Manager, name string) error { return s.StartUnit(ctx, name) }),
		),

		stopService: handler.NewUnary(handler.Action("services", handler.VerbStop, "Service"),
			serviceResource,
			serviceControlFn(srvDeps.Systemd, func(ctx context.Context, s systemd.Manager, name string) error { return s.StopUnit(ctx, name) }),
		),

		restartService: handler.NewUnary(handler.Action("services", handler.VerbRestart, "Service"),
			serviceResource,
			serviceControlFn(srvDeps.Systemd, func(ctx context.Context, s systemd.Manager, name string) error { return s.RestartUnit(ctx, name) }),
		),

		// Streaming RPCs
		logs: handler.NewReadOnlyStream(handler.Action("diagnostics", handler.VerbStream, "Logs"), func(ctx context.Context, req *pb.LogsRequest, send func(*pb.LogsResponse) error) error {
			if diag == nil {
				return fmt.Errorf("diagnostics not configured")
			}
			return diag.LogsStream(ctx, req, send)
		}),

		dmesg: handler.NewReadOnlyStream(handler.Action("diagnostics", handler.VerbStream, "Dmesg"), func(ctx context.Context, req *pb.DmesgRequest, send func(*pb.DmesgResponse) error) error {
			if diag == nil {
				return fmt.Errorf("diagnostics not configured")
			}
			return diag.DmesgStream(ctx, req, send)
		}),
	}

	return s
}

// gRPC interface adapters — one line each, auth built into Execute
func (s *MachineServer) Version(ctx context.Context, req *pb.VersionRequest) (*pb.VersionResponse, error) {
	return s.version.Execute(ctx, s.deps, req)
}
func (s *MachineServer) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	return s.health.Execute(ctx, s.deps, req)
}
func (s *MachineServer) Stats(ctx context.Context, req *pb.StatsRequest) (*pb.StatsResponse, error) {
	return s.stats.Execute(ctx, s.deps, req)
}
func (s *MachineServer) ServiceStatus(ctx context.Context, req *pb.ServiceStatusRequest) (*pb.ServiceStatusResponse, error) {
	return s.serviceStatus.Execute(ctx, s.deps, req)
}
func (s *MachineServer) GetConfig(ctx context.Context, req *pb.GetConfigRequest) (*pb.GetConfigResponse, error) {
	return s.getConfig.Execute(ctx, s.deps, req)
}
func (s *MachineServer) ApplyConfig(ctx context.Context, req *pb.ApplyConfigRequest) (*pb.ApplyConfigResponse, error) {
	return s.applyConfig.Execute(ctx, s.deps, req)
}
func (s *MachineServer) Upgrade(ctx context.Context, req *pb.UpgradeRequest) (*pb.UpgradeResponse, error) {
	return s.upgradeH.Execute(ctx, s.deps, req)
}
func (s *MachineServer) Rollback(ctx context.Context, req *pb.RollbackRequest) (*pb.RollbackResponse, error) {
	return s.rollback.Execute(ctx, s.deps, req)
}
func (s *MachineServer) Reboot(ctx context.Context, req *pb.RebootRequest) (*pb.RebootResponse, error) {
	return s.reboot.Execute(ctx, s.deps, req)
}
func (s *MachineServer) ServiceControl(ctx context.Context, req *pb.ServiceControlRequest) (*pb.ServiceControlResponse, error) {
	switch req.Action {
	case pb.ServiceAction_SERVICE_ACTION_START:
		return s.startService.Execute(ctx, s.deps, req)
	case pb.ServiceAction_SERVICE_ACTION_STOP:
		return s.stopService.Execute(ctx, s.deps, req)
	case pb.ServiceAction_SERVICE_ACTION_RESTART:
		return s.restartService.Execute(ctx, s.deps, req)
	default:
		return nil, fmt.Errorf("unknown service action: %v", req.Action)
	}
}
func (s *MachineServer) Logs(req *pb.LogsRequest, stream grpc.ServerStreamingServer[pb.LogsResponse]) error {
	return s.logs.Execute(stream.Context(), s.deps, req, stream.Send)
}
func (s *MachineServer) Dmesg(req *pb.DmesgRequest, stream grpc.ServerStreamingServer[pb.DmesgResponse]) error {
	return s.dmesg.Execute(stream.Context(), s.deps, req, stream.Send)
}

// BootstrapAuth is unauthenticated — no handler wrapper, direct implementation.
// Audit events emitted manually since this bypasses the handler framework.
func (s *MachineServer) BootstrapAuth(ctx context.Context, req *pb.BootstrapAuthRequest) (*pb.BootstrapAuthResponse, error) {
	if s.bootstrapMgr == nil || !s.bootstrapMgr.Enabled() {
		return nil, fmt.Errorf("bootstrap not available")
	}
	peerAddr := "unknown"
	if p, ok := peer.FromContext(ctx); ok {
		peerAddr = p.Addr.String()
	}
	result, err := s.bootstrapMgr.Bootstrap(req.Token, req.Csr, peerAddr)
	if err != nil {
		s.emitBootstrapAudit(peerAddr, "denied")
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	s.emitBootstrapAudit(peerAddr, "success")
	fp, _ := bootstrap.CAFingerprint(s.bootstrapMgr.TLSDir())
	return &pb.BootstrapAuthResponse{CaCert: result.CACert, ClientCert: result.ClientCert, CaFingerprint: fp}, nil
}

func (s *MachineServer) emitBootstrapAudit(peerAddr, outcome string) {
	if s.deps.Audit == nil {
		return
	}
	s.deps.Audit.Log(audit.Event{
		Type:     "bootstrap",
		Action:   "BootstrapAuth",
		Outcome:  outcome,
		PeerAddr: peerAddr,
	})
}

func serviceResource(req *pb.ServiceControlRequest) authz.Resource {
	if req.Name == "" {
		return authz.ThisNode()
	}
	return authz.ServiceResource(req.Name)
}

func serviceControlFn(sys systemd.Manager, op func(context.Context, systemd.Manager, string) error) func(context.Context, *pb.ServiceControlRequest) (*pb.ServiceControlResponse, error) {
	return func(ctx context.Context, req *pb.ServiceControlRequest) (*pb.ServiceControlResponse, error) {
		if err := validate.UnitName(req.Name); err != nil {
			return nil, fmt.Errorf("invalid unit: %w", err)
		}
		if sys == nil {
			return nil, fmt.Errorf("systemd not configured")
		}
		if err := op(ctx, sys, req.Name); err != nil {
			return nil, fmt.Errorf("service control: %w", err)
		}
		st, err := sys.UnitStatus(ctx, req.Name)
		if err != nil {
			return nil, fmt.Errorf("get unit status: %w", err)
		}
		return &pb.ServiceControlResponse{Name: st.Name, ActiveState: st.ActiveState, SubState: st.SubState}, nil
	}
}

func newConfigServerFromDeps(deps Deps) *ConfigServer {
	if deps.Network == nil || deps.Kargs == nil {
		return nil
	}
	applier := machineconfig.NewApplier("/etc/systemd/network", "/etc/bootc/kargs.d", deps.Network, deps.Kargs)
	return NewConfigServer(applier)
}

func newUpgradeManagerFromDeps(deps Deps) *upgrade.Manager {
	if deps.Bootc == nil || deps.Systemd == nil {
		return nil
	}
	return upgrade.NewManager(deps.Bootc, deps.Systemd)
}
