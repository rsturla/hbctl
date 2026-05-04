package v1alpha1

import (
	"context"
	"fmt"
	"testing"

	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"github.com/rsturla/hbctl/internal/system/journal"
	"github.com/rsturla/hbctl/internal/system/proc"
	"github.com/rsturla/hbctl/internal/system/systemd"
	"google.golang.org/grpc/metadata"
)

type fakeJournalReader struct {
	entries []journal.Entry
	err     error
}

func (f *fakeJournalReader) Stream(_ context.Context, _ journal.StreamOpts) (<-chan journal.Entry, <-chan error) {
	ch := make(chan journal.Entry, len(f.entries))
	errc := make(chan error, 1)
	for _, e := range f.entries {
		ch <- e
	}
	close(ch)
	if f.err != nil {
		errc <- f.err
	}
	close(errc)
	return ch, errc
}

type fakeSystemdManager struct {
	units  []systemd.UnitStatus
	status *systemd.UnitStatus
	err    error
}

func (f *fakeSystemdManager) ListUnits(_ context.Context) ([]systemd.UnitStatus, error) {
	return f.units, f.err
}

func (f *fakeSystemdManager) UnitStatus(_ context.Context, _ string) (*systemd.UnitStatus, error) {
	return f.status, f.err
}

func (f *fakeSystemdManager) Reboot(_ context.Context) error { return nil }
func (f *fakeSystemdManager) StartUnit(_ context.Context, _ string) error   { return nil }
func (f *fakeSystemdManager) StopUnit(_ context.Context, _ string) error    { return nil }
func (f *fakeSystemdManager) RestartUnit(_ context.Context, _ string) error { return nil }

type fakeProcReader struct {
	stats *proc.Stats
	err   error
}

func (f *fakeProcReader) Read() (*proc.Stats, error) {
	return f.stats, f.err
}

type fakeLogsStream struct {
	responses []*pb.LogsResponse
	ctx       context.Context
}

func (f *fakeLogsStream) Send(resp *pb.LogsResponse) error {
	f.responses = append(f.responses, resp)
	return nil
}
func (f *fakeLogsStream) Context() context.Context           { return f.ctx }
func (f *fakeLogsStream) SetHeader(metadata.MD) error        { return nil }
func (f *fakeLogsStream) SendHeader(metadata.MD) error       { return nil }
func (f *fakeLogsStream) SetTrailer(metadata.MD)             {}
func (f *fakeLogsStream) SendMsg(any) error                  { return nil }
func (f *fakeLogsStream) RecvMsg(any) error                  { return nil }

type fakeDmesgStream struct {
	responses []*pb.DmesgResponse
	ctx       context.Context
}

func (f *fakeDmesgStream) Send(resp *pb.DmesgResponse) error {
	f.responses = append(f.responses, resp)
	return nil
}
func (f *fakeDmesgStream) Context() context.Context           { return f.ctx }
func (f *fakeDmesgStream) SetHeader(metadata.MD) error        { return nil }
func (f *fakeDmesgStream) SendHeader(metadata.MD) error       { return nil }
func (f *fakeDmesgStream) SetTrailer(metadata.MD)             {}
func (f *fakeDmesgStream) SendMsg(any) error                  { return nil }
func (f *fakeDmesgStream) RecvMsg(any) error                  { return nil }

func TestLogs(t *testing.T) {
	t.Parallel()

	d := NewDiagnosticsServer(
		&fakeJournalReader{
			entries: []journal.Entry{
				{Timestamp: "1000", Unit: "kubelet.service", Message: "started", Priority: "6"},
				{Timestamp: "2000", Unit: "kubelet.service", Message: "ready", Priority: "6"},
			},
		},
		nil, nil,
	)

	stream := &fakeLogsStream{ctx: context.Background()}
	err := d.Logs(&pb.LogsRequest{Unit: "kubelet.service", Lines: 10}, stream)
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}

	if len(stream.responses) != 2 {
		t.Fatalf("got %d responses, want 2", len(stream.responses))
	}
	if stream.responses[0].Message != "started" {
		t.Errorf("responses[0].Message = %q", stream.responses[0].Message)
	}
	if stream.responses[1].Unit != "kubelet.service" {
		t.Errorf("responses[1].Unit = %q", stream.responses[1].Unit)
	}
}

func TestLogs_Empty(t *testing.T) {
	t.Parallel()

	d := NewDiagnosticsServer(&fakeJournalReader{}, nil, nil)

	stream := &fakeLogsStream{ctx: context.Background()}
	err := d.Logs(&pb.LogsRequest{}, stream)
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}

	if len(stream.responses) != 0 {
		t.Errorf("got %d responses, want 0", len(stream.responses))
	}
}

func TestLogs_JournalError(t *testing.T) {
	t.Parallel()

	d := NewDiagnosticsServer(
		&fakeJournalReader{err: fmt.Errorf("journalctl failed")},
		nil, nil,
	)

	stream := &fakeLogsStream{ctx: context.Background()}
	err := d.Logs(&pb.LogsRequest{}, stream)
	if err == nil {
		t.Error("expected error from journal")
	}
}

func TestDmesg(t *testing.T) {
	t.Parallel()

	d := NewDiagnosticsServer(
		&fakeJournalReader{
			entries: []journal.Entry{
				{Timestamp: "1000", Message: "kernel: boot", Priority: "4"},
			},
		},
		nil, nil,
	)

	stream := &fakeDmesgStream{ctx: context.Background()}
	err := d.Dmesg(&pb.DmesgRequest{Lines: 100}, stream)
	if err != nil {
		t.Fatalf("Dmesg: %v", err)
	}

	if len(stream.responses) != 1 {
		t.Fatalf("got %d responses, want 1", len(stream.responses))
	}
	if stream.responses[0].Message != "kernel: boot" {
		t.Errorf("Message = %q", stream.responses[0].Message)
	}
	if stream.responses[0].Facility != "kern" {
		t.Errorf("Facility = %q, want kern", stream.responses[0].Facility)
	}
}

func TestStats(t *testing.T) {
	t.Parallel()

	d := NewDiagnosticsServer(nil, nil, &fakeProcReader{
		stats: &proc.Stats{
			Memory: proc.MemoryStats{
				TotalBytes:     16*1024*1024*1024,
				AvailableBytes: 8*1024*1024*1024,
				UsedBytes:      8*1024*1024*1024,
			},
			CPU: proc.CPUStats{
				Count:        4,
				UsagePercent: 25.5,
			},
			Load: proc.LoadStats{
				Load1: 1.5, Load5: 2.0, Load15: 1.8,
			},
			Disks: []proc.DiskStats{
				{MountPoint: "/", TotalBytes: 100*1024*1024*1024, AvailableBytes: 50*1024*1024*1024, UsedBytes: 50*1024*1024*1024},
			},
		},
	})

	resp, err := d.Stats(context.Background(), &pb.StatsRequest{})
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}

	if resp.Memory.TotalBytes != 16*1024*1024*1024 {
		t.Errorf("Memory.TotalBytes = %d", resp.Memory.TotalBytes)
	}
	if resp.Cpu.Count != 4 {
		t.Errorf("CPU.Count = %d", resp.Cpu.Count)
	}
	if resp.Cpu.UsagePercent != 25.5 {
		t.Errorf("CPU.UsagePercent = %f", resp.Cpu.UsagePercent)
	}
	if resp.Load.Load1 != 1.5 {
		t.Errorf("Load.Load1 = %f", resp.Load.Load1)
	}
	if len(resp.Disks) != 1 {
		t.Fatalf("Disks count = %d", len(resp.Disks))
	}
	if resp.Disks[0].MountPoint != "/" {
		t.Errorf("Disks[0].MountPoint = %q", resp.Disks[0].MountPoint)
	}
}

func TestStats_Error(t *testing.T) {
	t.Parallel()

	d := NewDiagnosticsServer(nil, nil, &fakeProcReader{
		err: fmt.Errorf("read failed"),
	})

	_, err := d.Stats(context.Background(), &pb.StatsRequest{})
	if err == nil {
		t.Error("expected error from proc reader")
	}
}

func TestStats_NoDisks(t *testing.T) {
	t.Parallel()

	d := NewDiagnosticsServer(nil, nil, &fakeProcReader{
		stats: &proc.Stats{
			Memory: proc.MemoryStats{TotalBytes: 1024},
			CPU:    proc.CPUStats{Count: 1},
		},
	})

	resp, err := d.Stats(context.Background(), &pb.StatsRequest{})
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if len(resp.Disks) != 0 {
		t.Errorf("Disks = %d, want 0", len(resp.Disks))
	}
}

func TestServiceStatus(t *testing.T) {
	t.Parallel()

	d := NewDiagnosticsServer(nil, &fakeSystemdManager{
		status: &systemd.UnitStatus{
			Name:                "crio.service",
			Description:         "CRI-O Container Runtime",
			LoadState:           "loaded",
			ActiveState:         "active",
			SubState:            "running",
			UnitFileState:       "enabled",
			MainPID:             1234,
			MemoryBytes:         52428800,
			ActiveEnterTimestamp: "1714838400",
		},
	}, nil)

	resp, err := d.ServiceStatus(context.Background(), &pb.ServiceStatusRequest{Name: "crio.service"})
	if err != nil {
		t.Fatalf("ServiceStatus: %v", err)
	}

	if resp.Name != "crio.service" {
		t.Errorf("Name = %q", resp.Name)
	}
	if resp.Description != "CRI-O Container Runtime" {
		t.Errorf("Description = %q", resp.Description)
	}
	if resp.ActiveState != "active" {
		t.Errorf("ActiveState = %q", resp.ActiveState)
	}
	if resp.MainPid != 1234 {
		t.Errorf("MainPid = %d", resp.MainPid)
	}
	if resp.MemoryBytes != 52428800 {
		t.Errorf("MemoryBytes = %d", resp.MemoryBytes)
	}
}

func TestServiceStatus_EmptyName(t *testing.T) {
	t.Parallel()

	d := NewDiagnosticsServer(nil, &fakeSystemdManager{}, nil)

	_, err := d.ServiceStatus(context.Background(), &pb.ServiceStatusRequest{})
	if err == nil {
		t.Error("expected error for empty service name")
	}
}

func TestServiceStatus_SystemdError(t *testing.T) {
	t.Parallel()

	d := NewDiagnosticsServer(nil, &fakeSystemdManager{
		err: fmt.Errorf("unit not found"),
	}, nil)

	_, err := d.ServiceStatus(context.Background(), &pb.ServiceStatusRequest{Name: "missing.service"})
	if err == nil {
		t.Error("expected error from systemd")
	}
}
