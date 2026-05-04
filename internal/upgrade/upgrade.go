package upgrade

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/rsturla/hbctl/internal/system/bootc"
	"github.com/rsturla/hbctl/internal/system/systemd"
)

type Manager struct {
	bootc   bootc.Manager
	systemd systemd.Manager
}

func NewManager(b bootc.Manager, s systemd.Manager) *Manager {
	return &Manager{bootc: b, systemd: s}
}

type UpgradeResult struct {
	CurrentImage  string
	CurrentDigest string
	StagedImage   string
}

func (m *Manager) Upgrade(ctx context.Context, image string) (*UpgradeResult, error) {
	if image == "" {
		return nil, fmt.Errorf("image required")
	}

	status, err := m.bootc.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("get current status: %w", err)
	}

	slog.Info("staging upgrade", "from", status.Image, "to", image)

	if err := m.bootc.Switch(ctx, image); err != nil {
		return nil, fmt.Errorf("stage upgrade: %w", err)
	}

	newStatus, err := m.bootc.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("get post-switch status: %w", err)
	}

	return &UpgradeResult{
		CurrentImage:  newStatus.Image,
		CurrentDigest: newStatus.ImageDigest,
		StagedImage:   newStatus.Staged,
	}, nil
}

type RollbackResult struct {
	CurrentImage  string
	RollbackImage string
}

func (m *Manager) Rollback(ctx context.Context) (*RollbackResult, error) {
	status, err := m.bootc.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("get current status: %w", err)
	}

	slog.Info("initiating rollback", "current", status.Image)

	if err := m.bootc.Rollback(ctx); err != nil {
		return nil, fmt.Errorf("rollback: %w", err)
	}

	newStatus, err := m.bootc.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("get post-rollback status: %w", err)
	}

	return &RollbackResult{
		CurrentImage:  status.Image,
		RollbackImage: newStatus.Staged,
	}, nil
}

func (m *Manager) Reboot(ctx context.Context) error {
	slog.Info("initiating reboot")
	return m.systemd.Reboot(ctx)
}
