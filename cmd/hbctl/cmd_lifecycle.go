package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/rsturla/hbctl/internal/cli"
	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"github.com/rsturla/hbctl/internal/output"
)

type upgradeCmd struct{}

func (c *upgradeCmd) Name() string { return "upgrade" }
func (c *upgradeCmd) Help() string { return "Stage OS image upgrade" }

func (c *upgradeCmd) Run(g cli.Globals, args []string) error {
	fs := cli.Flags("upgrade")
	image := fs.String("image", "", "target OS image (required)")
	_ = fs.Parse(args)
	if *image == "" {
		return fmt.Errorf("usage: hbctl upgrade --image <image-ref>")
	}
	return withClient(g, func(ctx context.Context, cl pb.MachineServiceClient) error {
		resp, err := cl.Upgrade(ctx, &pb.UpgradeRequest{Image: *image})
		if err != nil {
			return err
		}
		if g.JSON() {
			return output.JSON(resp)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintf(w, "Current Image:\t%s\n", resp.CurrentImage)
		_, _ = fmt.Fprintf(w, "Staged Image:\t%s\n", resp.StagedImage)
		_, _ = fmt.Fprintf(w, "Reboot Required:\t%v\n", resp.RebootRequired)
		return w.Flush()
	})
}

type rollbackCmd struct{}

func (c *rollbackCmd) Name() string { return "rollback" }
func (c *rollbackCmd) Help() string { return "Rollback to previous OS image" }

func (c *rollbackCmd) Run(g cli.Globals, _ []string) error {
	return withClient(g, func(ctx context.Context, cl pb.MachineServiceClient) error {
		resp, err := cl.Rollback(ctx, &pb.RollbackRequest{})
		if err != nil {
			return err
		}
		if g.JSON() {
			return output.JSON(resp)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintf(w, "Current Image:\t%s\n", resp.CurrentImage)
		_, _ = fmt.Fprintf(w, "Rollback Image:\t%s\n", resp.RollbackImage)
		_, _ = fmt.Fprintf(w, "Reboot Required:\t%v\n", resp.RebootRequired)
		return w.Flush()
	})
}

type rebootCmd struct{}

func (c *rebootCmd) Name() string { return "reboot" }
func (c *rebootCmd) Help() string { return "Reboot the node" }

func (c *rebootCmd) Run(g cli.Globals, _ []string) error {
	return withClient(g, func(ctx context.Context, cl pb.MachineServiceClient) error {
		if _, err := cl.Reboot(ctx, &pb.RebootRequest{}); err != nil {
			return err
		}
		fmt.Println("reboot initiated")
		return nil
	})
}
