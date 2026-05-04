package v1alpha1

import (
	"context"
	"fmt"

	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"github.com/rsturla/hbctl/internal/machineconfig"
	"github.com/rsturla/hbctl/internal/system/network"
)

type ConfigServer struct {
	applier *machineconfig.Applier
}

func NewConfigServer(applier *machineconfig.Applier) *ConfigServer {
	return &ConfigServer{applier: applier}
}

func (s *ConfigServer) GetConfig(ctx context.Context, _ *pb.GetConfigRequest) (*pb.GetConfigResponse, error) {
	cfg, err := s.applier.Read()
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	return &pb.GetConfigResponse{
		Config: configToProto(cfg),
	}, nil
}

func (s *ConfigServer) ApplyConfig(ctx context.Context, req *pb.ApplyConfigRequest) (*pb.ApplyConfigResponse, error) {
	if req.Config == nil {
		return nil, fmt.Errorf("config required")
	}

	cfg := protoToConfig(req.Config)

	result, err := s.applier.Apply(cfg)
	if err != nil {
		return nil, fmt.Errorf("apply config: %w", err)
	}

	return &pb.ApplyConfigResponse{
		Warnings:       result.Warnings,
		RebootRequired: result.RebootRequired,
	}, nil
}

func configToProto(cfg *machineconfig.Config) *pb.MachineConfig {
	mc := &pb.MachineConfig{
		Hostname:   cfg.Hostname,
		KernelArgs: cfg.KernelArgs,
		DnsServers: cfg.DNSServers,
		NtpServers: cfg.NTPServers,
	}

	if len(cfg.Interfaces) > 0 {
		mc.Network = &pb.NetworkConfig{}
		for _, iface := range cfg.Interfaces {
			mc.Network.Interfaces = append(mc.Network.Interfaces, &pb.NetworkInterface{
				Name:      iface.Name,
				Dhcp:      iface.DHCP,
				Addresses: iface.Addresses,
				Gateway:   iface.Gateway,
				Mtu:       iface.MTU,
			})
		}
	}

	return mc
}

func protoToConfig(mc *pb.MachineConfig) *machineconfig.Config {
	cfg := &machineconfig.Config{
		Hostname:   mc.Hostname,
		KernelArgs: mc.KernelArgs,
		DNSServers: mc.DnsServers,
		NTPServers: mc.NtpServers,
	}

	if mc.Network != nil {
		for _, iface := range mc.Network.Interfaces {
			cfg.Interfaces = append(cfg.Interfaces, network.Interface{
				Name:      iface.Name,
				DHCP:      iface.Dhcp,
				Addresses: iface.Addresses,
				Gateway:   iface.Gateway,
				MTU:       iface.Mtu,
			})
		}
	}

	return cfg
}
