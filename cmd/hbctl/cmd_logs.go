package main

import (
	"context"
	"fmt"
	"io"

	"github.com/rsturla/hbctl/internal/cli"
	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"github.com/rsturla/hbctl/internal/output"
)

type logsCmd struct{}

func (c *logsCmd) Name() string { return "logs" }
func (c *logsCmd) Help() string { return "Stream journal logs" }

func (c *logsCmd) Run(g cli.Globals, args []string) error {
	fs := cli.Flags("logs")
	follow := fs.Bool("f", false, "follow log output")
	unit := fs.String("u", "", "filter by systemd unit")
	lines := fs.Int("n", 100, "number of lines")
	_ = fs.Parse(args)

	return withClient(g, func(ctx context.Context, cl pb.MachineServiceClient) error {
		if *follow {
			ctx = context.WithoutCancel(ctx)
		}
		stream, err := cl.Logs(ctx, &pb.LogsRequest{Follow: *follow, Unit: *unit, Lines: int32(*lines)})
		if err != nil {
			return err
		}
		for {
			entry, err := stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if g.JSON() {
				_ = output.JSON(entry)
			} else if entry.Unit != "" {
				fmt.Printf("%s %s: %s\n", entry.Timestamp, entry.Unit, entry.Message)
			} else {
				fmt.Printf("%s %s\n", entry.Timestamp, entry.Message)
			}
		}
	})
}
