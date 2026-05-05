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

type healthCmd struct{}

func (c *healthCmd) Name() string { return "health" }
func (c *healthCmd) Help() string { return "Show node health status" }

func (c *healthCmd) Run(g cli.Globals, _ []string) error {
	return withClient(g, func(ctx context.Context, cl pb.MachineServiceClient) error {
		resp, err := cl.Health(ctx, &pb.HealthRequest{})
		if err != nil {
			return err
		}
		if g.JSON() {
			return output.JSON(resp)
		}
		status := "UNKNOWN"
		switch resp.Status {
		case pb.HealthStatus_HEALTH_STATUS_HEALTHY:
			status = "HEALTHY"
		case pb.HealthStatus_HEALTH_STATUS_UNHEALTHY:
			status = "UNHEALTHY"
		}
		fmt.Printf("Status: %s\n", status)
		if len(resp.Services) > 0 {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "SERVICE\tSTATE\tHEALTHY\n")
			for _, svc := range resp.Services {
				healthy := "no"
				if svc.Healthy {
					healthy = "yes"
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", svc.Name, svc.State, healthy)
			}
			_ = w.Flush()
		}
		return nil
	})
}
