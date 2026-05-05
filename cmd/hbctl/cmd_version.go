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

type versionCmd struct{}

func (c *versionCmd) Name() string { return "version" }
func (c *versionCmd) Help() string { return "Show agent and OS version" }

func (c *versionCmd) Run(g cli.Globals, _ []string) error {
	return withClient(g, func(ctx context.Context, cl pb.MachineServiceClient) error {
		resp, err := cl.Version(ctx, &pb.VersionRequest{})
		if err != nil {
			return err
		}
		if g.JSON() {
			return output.JSON(resp)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintf(w, "Agent Version:\t%s\n", resp.Version)
		_, _ = fmt.Fprintf(w, "Go Version:\t%s\n", resp.GoVersion)
		if resp.OsImage != "" {
			_, _ = fmt.Fprintf(w, "OS Image:\t%s\n", resp.OsImage)
		}
		if resp.OsImageDigest != "" {
			_, _ = fmt.Fprintf(w, "Image Digest:\t%s\n", resp.OsImageDigest)
		}
		if resp.OsStagedImage != "" {
			_, _ = fmt.Fprintf(w, "Staged Image:\t%s\n", resp.OsStagedImage)
		}
		return w.Flush()
	})
}
