package v1alpha1

import (
	"context"
	"fmt"
	"runtime"

	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"github.com/rsturla/hbctl/internal/authz"
	"github.com/rsturla/hbctl/internal/bootstrap"
	healthpkg "github.com/rsturla/hbctl/internal/health"
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
	az authz.Authorizer

	version        handler.Unary[*pb.VersionRequest, *pb.VersionResponse]
	health         handler.Unary[*pb.HealthRequest, *pb.HealthResponse]
	stats          handler.Unary[*pb.StatsRequest, *pb.StatsResponse]
	serviceStatus  handler.Unary[*pb.ServiceStatusRequest, *pb.ServiceStatusResponse]
	getConfig      handler.Unary[*pb.GetConfigRequest, *pb.GetConfigResponse]
	applyConfig    handler.Unary[*pb.ApplyConfigRequest, *pb.ApplyConfigResponse]
	upgradeH       handler.Unary[*pb.UpgradeRequest, *pb.UpgradeResponse]
	rollback       handler.Unary[*pb.RollbackRequest, *pb.RollbackResponse]
	reboot         handler.Unary[*pb.RebootRequest, *pb.RebootResponse]
	serviceControl handler.Unary[*pb.ServiceControlRequest, *pb.ServiceControlResponse]
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

func NewMachineServer(deps Deps, az authz.Authorizer) *MachineServer {
	diag := NewDiagnosticsServer(deps.Journal, deps.Systemd, deps.Proc)
	cfgSrv := newConfigServerFromDeps(deps)
	upgradeMgr := newUpgradeManagerFromDeps(deps)

	s := &MachineServer{
		az:           az,
		bootstrapMgr: deps.Bootstrap,

		// Read-only RPCs — resource is always ThisNode
		version: handler.NewReadOnly("Version", func(ctx context.Context, _ *pb.VersionRequest) (*pb.VersionResponse, error) {
			resp := &pb.VersionResponse{
				Version:   version,
				GoVersion: runtime.Version(),
			}
			if deps.Bootc != nil {
				st, err := deps.Bootc.Status(ctx)
				if err == nil {
					resp.OsImage = st.Image
					resp.OsVersion = st.Version
					resp.OsImageDigest = st.ImageDigest
					resp.OsStagedImage = st.Staged
				}
			}
			return resp, nil
		}),

		health: handler.NewReadOnly("Health", func(ctx context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
			result, err := deps.Health.Check(ctx)
			if err != nil {
				return &pb.HealthResponse{Status: pb.HealthStatus_HEALTH_STATUS_UNHEALTHY}, nil
			}
			resp := &pb.HealthResponse{Status: pb.HealthStatus(result.Status)}
			for _, check := range result.Checks {
				resp.Services = append(resp.Services, &pb.ServiceHealth{
					Name:    check.Name,
					State:   check.Message,
					Healthy: check.Status == healthpkg.Healthy,
				})
			}
			return resp, nil
		}),

		stats: handler.NewReadOnly("Stats", func(ctx context.Context, req *pb.StatsRequest) (*pb.StatsResponse, error) {
			if diag == nil {
				return nil, fmt.Errorf("diagnostics not configured")
			}
			return diag.Stats(ctx, req)
		}),

		serviceStatus: handler.NewUnary("ServiceStatus",
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

		getConfig: handler.NewReadOnly("GetConfig", func(ctx context.Context, req *pb.GetConfigRequest) (*pb.GetConfigResponse, error) {
			if cfgSrv == nil {
				return nil, fmt.Errorf("configuration not configured")
			}
			return cfgSrv.GetConfig(ctx, req)
		}),

		// Mutating RPCs — resource is extracted from request
		applyConfig: handler.NewUnary("ApplyConfig",
			func(_ *pb.ApplyConfigRequest) authz.Resource { return authz.ConfigResource("machine") },
			func(ctx context.Context, req *pb.ApplyConfigRequest) (*pb.ApplyConfigResponse, error) {
				if cfgSrv == nil {
					return nil, fmt.Errorf("configuration not configured")
				}
				return cfgSrv.ApplyConfig(ctx, req)
			},
		),

		upgradeH: handler.NewUnary("Upgrade",
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

		rollback: handler.NewUnary("Rollback",
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

		reboot: handler.NewUnary("Reboot",
			func(_ *pb.RebootRequest) authz.Resource { return authz.NodeResource("*") },
			func(ctx context.Context, _ *pb.RebootRequest) (*pb.RebootResponse, error) {
				if upgradeMgr == nil {
					return nil, fmt.Errorf("upgrade not configured")
				}
				return &pb.RebootResponse{}, upgradeMgr.Reboot(ctx)
			},
		),

		serviceControl: handler.NewUnary("ServiceControl",
			func(req *pb.ServiceControlRequest) authz.Resource {
				if req.Name == "" {
					return authz.ThisNode()
				}
				return authz.ServiceResource(req.Name)
			},
			func(ctx context.Context, req *pb.ServiceControlRequest) (*pb.ServiceControlResponse, error) {
				if err := validate.UnitName(req.Name); err != nil {
					return nil, fmt.Errorf("invalid unit: %w", err)
				}
				if deps.Systemd == nil {
					return nil, fmt.Errorf("systemd not configured")
				}
				var err error
				switch req.Action {
				case pb.ServiceAction_SERVICE_ACTION_START:
					err = deps.Systemd.StartUnit(ctx, req.Name)
				case pb.ServiceAction_SERVICE_ACTION_STOP:
					err = deps.Systemd.StopUnit(ctx, req.Name)
				case pb.ServiceAction_SERVICE_ACTION_RESTART:
					err = deps.Systemd.RestartUnit(ctx, req.Name)
				default:
					return nil, fmt.Errorf("unknown action: %v", req.Action)
				}
				if err != nil {
					return nil, fmt.Errorf("service control: %w", err)
				}
				st, err := deps.Systemd.UnitStatus(ctx, req.Name)
				if err != nil {
					return nil, fmt.Errorf("get unit status: %w", err)
				}
				return &pb.ServiceControlResponse{Name: st.Name, ActiveState: st.ActiveState, SubState: st.SubState}, nil
			},
		),

		// Streaming RPCs
		logs: handler.NewReadOnlyStream("Logs", func(ctx context.Context, req *pb.LogsRequest, send func(*pb.LogsResponse) error) error {
			if diag == nil {
				return fmt.Errorf("diagnostics not configured")
			}
			return diag.LogsStream(ctx, req, send)
		}),

		dmesg: handler.NewReadOnlyStream("Dmesg", func(ctx context.Context, req *pb.DmesgRequest, send func(*pb.DmesgResponse) error) error {
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
	return s.version.Execute(ctx, s.az, req)
}
func (s *MachineServer) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	return s.health.Execute(ctx, s.az, req)
}
func (s *MachineServer) Stats(ctx context.Context, req *pb.StatsRequest) (*pb.StatsResponse, error) {
	return s.stats.Execute(ctx, s.az, req)
}
func (s *MachineServer) ServiceStatus(ctx context.Context, req *pb.ServiceStatusRequest) (*pb.ServiceStatusResponse, error) {
	return s.serviceStatus.Execute(ctx, s.az, req)
}
func (s *MachineServer) GetConfig(ctx context.Context, req *pb.GetConfigRequest) (*pb.GetConfigResponse, error) {
	return s.getConfig.Execute(ctx, s.az, req)
}
func (s *MachineServer) ApplyConfig(ctx context.Context, req *pb.ApplyConfigRequest) (*pb.ApplyConfigResponse, error) {
	return s.applyConfig.Execute(ctx, s.az, req)
}
func (s *MachineServer) Upgrade(ctx context.Context, req *pb.UpgradeRequest) (*pb.UpgradeResponse, error) {
	return s.upgradeH.Execute(ctx, s.az, req)
}
func (s *MachineServer) Rollback(ctx context.Context, req *pb.RollbackRequest) (*pb.RollbackResponse, error) {
	return s.rollback.Execute(ctx, s.az, req)
}
func (s *MachineServer) Reboot(ctx context.Context, req *pb.RebootRequest) (*pb.RebootResponse, error) {
	return s.reboot.Execute(ctx, s.az, req)
}
func (s *MachineServer) ServiceControl(ctx context.Context, req *pb.ServiceControlRequest) (*pb.ServiceControlResponse, error) {
	return s.serviceControl.Execute(ctx, s.az, req)
}
func (s *MachineServer) Logs(req *pb.LogsRequest, stream grpc.ServerStreamingServer[pb.LogsResponse]) error {
	return s.logs.Execute(stream.Context(), s.az, req, stream.Send)
}
func (s *MachineServer) Dmesg(req *pb.DmesgRequest, stream grpc.ServerStreamingServer[pb.DmesgResponse]) error {
	return s.dmesg.Execute(stream.Context(), s.az, req, stream.Send)
}

// BootstrapAuth is unauthenticated — no handler wrapper, direct implementation
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
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	fp, _ := bootstrap.CAFingerprint(s.bootstrapMgr.TLSDir())
	return &pb.BootstrapAuthResponse{CaCert: result.CACert, ClientCert: result.ClientCert, CaFingerprint: fp}, nil
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
