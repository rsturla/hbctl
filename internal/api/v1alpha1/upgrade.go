package v1alpha1

import (
	"context"
	"fmt"

	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"github.com/rsturla/hbctl/internal/upgrade"
)

type UpgradeServer struct {
	mgr *upgrade.Manager
}

func NewUpgradeServer(mgr *upgrade.Manager) *UpgradeServer {
	return &UpgradeServer{mgr: mgr}
}

func (s *UpgradeServer) Upgrade(ctx context.Context, req *pb.UpgradeRequest) (*pb.UpgradeResponse, error) {
	if req.Image == "" {
		return nil, fmt.Errorf("image required")
	}

	result, err := s.mgr.Upgrade(ctx, req.Image)
	if err != nil {
		return nil, fmt.Errorf("upgrade: %w", err)
	}

	return &pb.UpgradeResponse{
		CurrentImage:   result.CurrentImage,
		CurrentDigest:  result.CurrentDigest,
		StagedImage:    result.StagedImage,
		RebootRequired: result.StagedImage != "",
	}, nil
}

func (s *UpgradeServer) Rollback(ctx context.Context, _ *pb.RollbackRequest) (*pb.RollbackResponse, error) {
	result, err := s.mgr.Rollback(ctx)
	if err != nil {
		return nil, fmt.Errorf("rollback: %w", err)
	}

	return &pb.RollbackResponse{
		CurrentImage:   result.CurrentImage,
		RollbackImage:  result.RollbackImage,
		RebootRequired: true,
	}, nil
}

func (s *UpgradeServer) Reboot(ctx context.Context, _ *pb.RebootRequest) (*pb.RebootResponse, error) {
	if err := s.mgr.Reboot(ctx); err != nil {
		return nil, fmt.Errorf("reboot: %w", err)
	}
	return &pb.RebootResponse{}, nil
}
