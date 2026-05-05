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

type serviceStatusCmd struct{}

func (c *serviceStatusCmd) Name() string { return "service-status" }
func (c *serviceStatusCmd) Help() string { return "Show systemd unit status" }

func (c *serviceStatusCmd) Run(g cli.Globals, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: hbctl service-status <unit-name>")
	}
	return withClient(g, func(ctx context.Context, cl pb.MachineServiceClient) error {
		resp, err := cl.ServiceStatus(ctx, &pb.ServiceStatusRequest{Name: args[0]})
		if err != nil {
			return err
		}
		if g.JSON() {
			return output.JSON(resp)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintf(w, "Name:\t%s\n", resp.Name)
		_, _ = fmt.Fprintf(w, "Description:\t%s\n", resp.Description)
		_, _ = fmt.Fprintf(w, "Active State:\t%s\n", resp.ActiveState)
		_, _ = fmt.Fprintf(w, "Sub State:\t%s\n", resp.SubState)
		if resp.MainPid > 0 {
			_, _ = fmt.Fprintf(w, "Main PID:\t%d\n", resp.MainPid)
		}
		if resp.MemoryBytes > 0 {
			_, _ = fmt.Fprintf(w, "Memory:\t%s\n", output.HumanBytes(resp.MemoryBytes))
		}
		return w.Flush()
	})
}
