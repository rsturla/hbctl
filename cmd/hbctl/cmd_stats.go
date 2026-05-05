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

type statsCmd struct{}

func (c *statsCmd) Name() string { return "stats" }
func (c *statsCmd) Help() string { return "Show system resource stats" }

func (c *statsCmd) Run(g cli.Globals, _ []string) error {
	return withClient(g, func(ctx context.Context, cl pb.MachineServiceClient) error {
		resp, err := cl.Stats(ctx, &pb.StatsRequest{})
		if err != nil {
			return err
		}
		if g.JSON() {
			return output.JSON(resp)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if resp.Memory != nil {
			_, _ = fmt.Fprintf(w, "Memory Total:\t%s\n", output.HumanBytes(resp.Memory.TotalBytes))
			_, _ = fmt.Fprintf(w, "Memory Available:\t%s\n", output.HumanBytes(resp.Memory.AvailableBytes))
			_, _ = fmt.Fprintf(w, "Memory Used:\t%s\n", output.HumanBytes(resp.Memory.UsedBytes))
		}
		if resp.Cpu != nil {
			_, _ = fmt.Fprintf(w, "CPU Count:\t%d\n", resp.Cpu.Count)
			_, _ = fmt.Fprintf(w, "CPU Usage:\t%.1f%%\n", resp.Cpu.UsagePercent)
		}
		if resp.Load != nil {
			_, _ = fmt.Fprintf(w, "Load:\t%.2f %.2f %.2f\n", resp.Load.Load1, resp.Load.Load5, resp.Load.Load15)
		}
		_ = w.Flush()
		if len(resp.Disks) > 0 {
			fmt.Println()
			dw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(dw, "MOUNT\tTOTAL\tAVAILABLE\tUSED\n")
			for _, d := range resp.Disks {
				_, _ = fmt.Fprintf(dw, "%s\t%s\t%s\t%s\n", d.MountPoint, output.HumanBytes(d.TotalBytes), output.HumanBytes(d.AvailableBytes), output.HumanBytes(d.UsedBytes))
			}
			_ = dw.Flush()
		}
		return nil
	})
}
