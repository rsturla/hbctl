package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/rsturla/hbctl/internal/cli"
	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"github.com/rsturla/hbctl/internal/output"
)

type configGetCmd struct{}

func (c *configGetCmd) Name() string { return "config-get" }
func (c *configGetCmd) Help() string { return "Show current machine config" }

func (c *configGetCmd) Run(g cli.Globals, _ []string) error {
	return withClient(g, func(ctx context.Context, cl pb.MachineServiceClient) error {
		resp, err := cl.GetConfig(ctx, &pb.GetConfigRequest{})
		if err != nil {
			return err
		}
		if g.JSON() {
			return output.JSON(resp)
		}
		cfg := resp.Config
		if cfg == nil {
			fmt.Println("no config")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if cfg.Hostname != "" {
			_, _ = fmt.Fprintf(w, "Hostname:\t%s\n", cfg.Hostname)
		}
		if len(cfg.DnsServers) > 0 {
			_, _ = fmt.Fprintf(w, "DNS Servers:\t%s\n", strings.Join(cfg.DnsServers, ", "))
		}
		if len(cfg.KernelArgs) > 0 {
			_, _ = fmt.Fprintf(w, "Kernel Args:\t%s\n", strings.Join(cfg.KernelArgs, " "))
		}
		_ = w.Flush()
		if cfg.Network != nil && len(cfg.Network.Interfaces) > 0 {
			fmt.Println()
			nw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(nw, "INTERFACE\tDHCP\tADDRESSES\tGATEWAY\tMTU\n")
			for _, iface := range cfg.Network.Interfaces {
				dhcp := "no"
				if iface.Dhcp {
					dhcp = "yes"
				}
				mtu := ""
				if iface.Mtu > 0 {
					mtu = fmt.Sprintf("%d", iface.Mtu)
				}
				_, _ = fmt.Fprintf(nw, "%s\t%s\t%s\t%s\t%s\n", iface.Name, dhcp, strings.Join(iface.Addresses, ", "), iface.Gateway, mtu)
			}
			_ = nw.Flush()
		}
		return nil
	})
}

type configApplyCmd struct{}

func (c *configApplyCmd) Name() string { return "config-apply" }
func (c *configApplyCmd) Help() string { return "Apply machine configuration from JSON" }

func (c *configApplyCmd) Run(g cli.Globals, args []string) error {
	fs := cli.Flags("config-apply")
	file := fs.String("f", "", "JSON config file (use - for stdin)")
	_ = fs.Parse(args)

	if *file == "" {
		return fmt.Errorf("usage: hbctl config-apply -f <file.json>")
	}

	var data []byte
	var err error
	if *file == "-" {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	} else {
		data, err = os.ReadFile(*file)
	}
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	var cfg pb.MachineConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	return withClient(g, func(ctx context.Context, cl pb.MachineServiceClient) error {
		resp, err := cl.ApplyConfig(ctx, &pb.ApplyConfigRequest{Config: &cfg})
		if err != nil {
			return err
		}
		if g.JSON() {
			return output.JSON(resp)
		}
		if resp.RebootRequired {
			fmt.Println("Config applied. Reboot required for kernel arg changes.")
		} else {
			fmt.Println("Config applied.")
		}
		for _, w := range resp.Warnings {
			fmt.Printf("  warning: %s\n", w)
		}
		return nil
	})
}
