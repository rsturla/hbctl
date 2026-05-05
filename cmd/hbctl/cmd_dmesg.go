package main

import (
	"context"
	"fmt"
	"io"

	"github.com/rsturla/hbctl/internal/cli"
	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"github.com/rsturla/hbctl/internal/output"
)

type dmesgCmd struct{}

func (c *dmesgCmd) Name() string { return "dmesg" }
func (c *dmesgCmd) Help() string { return "Stream kernel logs" }

func (c *dmesgCmd) Run(g cli.Globals, args []string) error {
	fs := cli.Flags("dmesg")
	follow := fs.Bool("f", false, "follow output")
	lines := fs.Int("n", 100, "number of lines")
	_ = fs.Parse(args)

	return withClient(g, func(ctx context.Context, cl pb.MachineServiceClient) error {
		if *follow {
			ctx = context.WithoutCancel(ctx)
		}
		stream, err := cl.Dmesg(ctx, &pb.DmesgRequest{Follow: *follow, Lines: int32(*lines)})
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
			} else {
				fmt.Printf("[%s] %s\n", entry.Priority, entry.Message)
			}
		}
	})
}
