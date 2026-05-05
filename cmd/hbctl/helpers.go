package main

import (
	"context"
	"time"

	"github.com/rsturla/hbctl/internal/cli"
	"github.com/rsturla/hbctl/internal/client"
	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
)

func withClient(g cli.Globals, fn func(context.Context, pb.MachineServiceClient) error) error {
	c, conn, err := client.Connect(client.Config{Endpoint: g.Endpoint, TLSDir: g.TLSDir})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return fn(ctx, c)
}
