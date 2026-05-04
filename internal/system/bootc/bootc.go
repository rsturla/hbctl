package bootc

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

type Status struct {
	Image       string
	Version     string
	ImageDigest string
	Staged      string
}

type Manager interface {
	Status(ctx context.Context) (*Status, error)
	Switch(ctx context.Context, image string) error
	Rollback(ctx context.Context) error
}

// StatusReader is the Phase 1 read-only interface, kept for backward compat.
type StatusReader = Manager

type CLI struct{}

func NewCLI() *CLI {
	return &CLI{}
}

func (c *CLI) Status(ctx context.Context) (*Status, error) {
	out, err := exec.CommandContext(ctx, "bootc", "status", "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("bootc status: %w", err)
	}
	return parseStatus(out)
}

func (c *CLI) Switch(ctx context.Context, image string) error {
	if image == "" {
		return fmt.Errorf("image required")
	}
	cmd := exec.CommandContext(ctx, "bootc", "switch", "--transport=registry", "--", image)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("bootc switch: %w: %s", err, out)
	}
	return nil
}

func (c *CLI) Rollback(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "bootc", "rollback")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("bootc rollback: %w: %s", err, out)
	}
	return nil
}

func parseStatus(data []byte) (*Status, error) {
	var raw struct {
		Status struct {
			Booted struct {
				Image struct {
					Image struct {
						Image string `json:"image"`
					} `json:"image"`
					ImageDigest string  `json:"imageDigest"`
					Version     *string `json:"version"`
				} `json:"image"`
			} `json:"booted"`
			Staged *struct {
				Image struct {
					Image struct {
						Image string `json:"image"`
					} `json:"image"`
				} `json:"image"`
			} `json:"staged"`
		} `json:"status"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse bootc status JSON: %w", err)
	}

	s := &Status{
		Image:       raw.Status.Booted.Image.Image.Image,
		ImageDigest: raw.Status.Booted.Image.ImageDigest,
	}
	if raw.Status.Booted.Image.Version != nil {
		s.Version = *raw.Status.Booted.Image.Version
	}
	if raw.Status.Staged != nil {
		s.Staged = raw.Status.Staged.Image.Image.Image
	}
	return s, nil
}
