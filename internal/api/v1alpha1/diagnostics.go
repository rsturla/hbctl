package v1alpha1

import (
	"context"
	"fmt"

	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"github.com/rsturla/hbctl/internal/system/journal"
	"github.com/rsturla/hbctl/internal/validate"
	"github.com/rsturla/hbctl/internal/system/proc"
	"github.com/rsturla/hbctl/internal/system/systemd"
)

type DiagnosticsServer struct {
	journal journal.Reader
	systemd systemd.Manager
	proc    proc.Reader
}

func NewDiagnosticsServer(j journal.Reader, s systemd.Manager, p proc.Reader) *DiagnosticsServer {
	return &DiagnosticsServer{journal: j, systemd: s, proc: p}
}

func (d *DiagnosticsServer) Logs(req *pb.LogsRequest, stream pb.MachineService_LogsServer) error {
	opts := journal.StreamOpts{
		Follow: req.Follow,
		Unit:   req.Unit,
		Lines:  int(req.Lines),
	}

	entries, errc := d.journal.Stream(stream.Context(), opts)

	for entry := range entries {
		if err := stream.Send(&pb.LogsResponse{
			Timestamp: entry.Timestamp,
			Unit:      entry.Unit,
			Message:   entry.Message,
			Priority:  entry.Priority,
		}); err != nil {
			return err
		}
	}

	if err := <-errc; err != nil {
		return fmt.Errorf("journal stream: %w", err)
	}
	return nil
}

func (d *DiagnosticsServer) Dmesg(req *pb.DmesgRequest, stream pb.MachineService_DmesgServer) error {
	opts := journal.StreamOpts{
		Follow: req.Follow,
		Dmesg:  true,
		Lines:  int(req.Lines),
	}

	entries, errc := d.journal.Stream(stream.Context(), opts)

	for entry := range entries {
		if err := stream.Send(&pb.DmesgResponse{
			Timestamp: entry.Timestamp,
			Facility:  "kern",
			Priority:  entry.Priority,
			Message:   entry.Message,
		}); err != nil {
			return err
		}
	}

	if err := <-errc; err != nil {
		return fmt.Errorf("dmesg stream: %w", err)
	}
	return nil
}

func (d *DiagnosticsServer) LogsStream(ctx context.Context, req *pb.LogsRequest, send func(*pb.LogsResponse) error) error {
	opts := journal.StreamOpts{Follow: req.Follow, Unit: req.Unit, Lines: int(req.Lines)}
	entries, errc := d.journal.Stream(ctx, opts)
	for entry := range entries {
		if err := send(&pb.LogsResponse{
			Timestamp: entry.Timestamp, Unit: entry.Unit, Message: entry.Message, Priority: entry.Priority,
		}); err != nil {
			return err
		}
	}
	if err := <-errc; err != nil {
		return fmt.Errorf("journal stream: %w", err)
	}
	return nil
}

func (d *DiagnosticsServer) DmesgStream(ctx context.Context, req *pb.DmesgRequest, send func(*pb.DmesgResponse) error) error {
	opts := journal.StreamOpts{Follow: req.Follow, Dmesg: true, Lines: int(req.Lines)}
	entries, errc := d.journal.Stream(ctx, opts)
	for entry := range entries {
		if err := send(&pb.DmesgResponse{
			Timestamp: entry.Timestamp, Facility: "kern", Priority: entry.Priority, Message: entry.Message,
		}); err != nil {
			return err
		}
	}
	if err := <-errc; err != nil {
		return fmt.Errorf("dmesg stream: %w", err)
	}
	return nil
}

func (d *DiagnosticsServer) Stats(ctx context.Context, _ *pb.StatsRequest) (*pb.StatsResponse, error) {
	stats, err := d.proc.Read()
	if err != nil {
		return nil, fmt.Errorf("read stats: %w", err)
	}

	resp := &pb.StatsResponse{
		Memory: &pb.MemoryStats{
			TotalBytes:     stats.Memory.TotalBytes,
			AvailableBytes: stats.Memory.AvailableBytes,
			UsedBytes:      stats.Memory.UsedBytes,
		},
		Cpu: &pb.CPUStats{
			Count:        stats.CPU.Count,
			UsagePercent: stats.CPU.UsagePercent,
		},
		Load: &pb.LoadStats{
			Load1:  stats.Load.Load1,
			Load5:  stats.Load.Load5,
			Load15: stats.Load.Load15,
		},
	}

	for _, disk := range stats.Disks {
		resp.Disks = append(resp.Disks, &pb.DiskStats{
			MountPoint:     disk.MountPoint,
			Filesystem:     disk.Filesystem,
			TotalBytes:     disk.TotalBytes,
			AvailableBytes: disk.AvailableBytes,
			UsedBytes:      disk.UsedBytes,
		})
	}

	return resp, nil
}

func (d *DiagnosticsServer) ServiceStatus(ctx context.Context, req *pb.ServiceStatusRequest) (*pb.ServiceStatusResponse, error) {
	if err := validate.UnitName(req.Name); err != nil {
		return nil, fmt.Errorf("invalid unit: %w", err)
	}

	status, err := d.systemd.UnitStatus(ctx, req.Name)
	if err != nil {
		return nil, fmt.Errorf("get unit status: %w", err)
	}

	return &pb.ServiceStatusResponse{
		Name:                 status.Name,
		Description:          status.Description,
		LoadState:            status.LoadState,
		ActiveState:          status.ActiveState,
		SubState:             status.SubState,
		UnitFileState:        status.UnitFileState,
		MainPid:              status.MainPID,
		MemoryBytes:          status.MemoryBytes,
		ActiveEnterTimestamp: status.ActiveEnterTimestamp,
	}, nil
}
