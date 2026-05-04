package main

import (
	"context"
	"flag"
	"fmt"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
	"github.com/rsturla/hbctl/internal/client"
	"github.com/rsturla/hbctl/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var cliVersion = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	endpoint := envOr("HBCTL_ENDPOINT", "127.0.0.1:50000")
	tlsDir := envOr("HBCTL_TLS_DIR", "/var/lib/hummingbird/pki")

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "version":
		run(endpoint, tlsDir, cmdVersion)
	case "health":
		run(endpoint, tlsDir, cmdHealth)
	case "stats":
		run(endpoint, tlsDir, cmdStats)
	case "logs":
		runWithArgs(endpoint, tlsDir, args, cmdLogs)
	case "dmesg":
		runWithArgs(endpoint, tlsDir, args, cmdDmesg)
	case "service-status":
		runWithArgs(endpoint, tlsDir, args, cmdServiceStatus)
	case "config":
		if len(args) == 0 {
			fmt.Fprintf(os.Stderr, "usage: hbctl config [get|apply]\n")
			os.Exit(1)
		}
		switch args[0] {
		case "get":
			run(endpoint, tlsDir, cmdConfigGet)
		default:
			fmt.Fprintf(os.Stderr, "unknown config subcommand: %s\n", args[0])
			os.Exit(1)
		}
	case "upgrade":
		runWithArgs(endpoint, tlsDir, args, cmdUpgrade)
	case "rollback":
		run(endpoint, tlsDir, cmdRollback)
	case "reboot":
		run(endpoint, tlsDir, cmdReboot)
	case "bootstrap":
		cmdBootstrap(endpoint, args)
	case "gen-token":
		cmdGenToken()
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `hbctl — Hummingbird node management CLI

Usage: hbctl <command> [flags]

Commands:
  version          Show agent and OS version
  health           Show node health status
  stats            Show system resource stats
  logs             Stream journal logs
  dmesg            Stream kernel logs
  service-status   Show systemd unit status
  config get       Show current machine config
  upgrade          Stage OS image upgrade
  rollback         Rollback to previous OS image
  reboot           Reboot the node
  bootstrap        Bootstrap mTLS credentials from a node
  gen-token        Generate a bootstrap token and its hash

Environment:
  HBCTL_ENDPOINT   Agent address (default: 127.0.0.1:50000)
  HBCTL_TLS_DIR    TLS cert directory (default: /var/lib/hummingbird/pki)
`)
}

type cmdFunc func(context.Context, pb.MachineServiceClient) error
type cmdFuncArgs func(context.Context, pb.MachineServiceClient, []string) error

func run(endpoint, tlsDir string, fn cmdFunc) {
	c, conn, err := client.Connect(client.Config{Endpoint: endpoint, TLSDir: tlsDir})
	if err != nil {
		fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := fn(ctx, c); err != nil {
		fatal(err)
	}
}

func runWithArgs(endpoint, tlsDir string, args []string, fn cmdFuncArgs) {
	c, conn, err := client.Connect(client.Config{Endpoint: endpoint, TLSDir: tlsDir})
	if err != nil {
		fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := fn(ctx, c, args); err != nil {
		fatal(err)
	}
}

func cmdVersion(ctx context.Context, c pb.MachineServiceClient) error {
	resp, err := c.Version(ctx, &pb.VersionRequest{})
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Agent Version:\t%s\n", resp.Version)
	fmt.Fprintf(w, "Go Version:\t%s\n", resp.GoVersion)
	if resp.OsImage != "" {
		fmt.Fprintf(w, "OS Image:\t%s\n", resp.OsImage)
	}
	if resp.OsVersion != "" {
		fmt.Fprintf(w, "OS Version:\t%s\n", resp.OsVersion)
	}
	if resp.OsImageDigest != "" {
		fmt.Fprintf(w, "Image Digest:\t%s\n", resp.OsImageDigest)
	}
	if resp.OsStagedImage != "" {
		fmt.Fprintf(w, "Staged Image:\t%s\n", resp.OsStagedImage)
	}
	return w.Flush()
}

func cmdHealth(ctx context.Context, c pb.MachineServiceClient) error {
	resp, err := c.Health(ctx, &pb.HealthRequest{})
	if err != nil {
		return err
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
		fmt.Fprintf(w, "SERVICE\tSTATE\tSUBSTATE\tHEALTHY\n")
		for _, svc := range resp.Services {
			healthy := "no"
			if svc.Healthy {
				healthy = "yes"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", svc.Name, svc.State, svc.SubState, healthy)
		}
		w.Flush()
	}
	return nil
}

func cmdStats(ctx context.Context, c pb.MachineServiceClient) error {
	resp, err := c.Stats(ctx, &pb.StatsRequest{})
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	if resp.Memory != nil {
		fmt.Fprintf(w, "Memory Total:\t%s\n", humanBytes(resp.Memory.TotalBytes))
		fmt.Fprintf(w, "Memory Available:\t%s\n", humanBytes(resp.Memory.AvailableBytes))
		fmt.Fprintf(w, "Memory Used:\t%s\n", humanBytes(resp.Memory.UsedBytes))
	}
	if resp.Cpu != nil {
		fmt.Fprintf(w, "CPU Count:\t%d\n", resp.Cpu.Count)
		fmt.Fprintf(w, "CPU Usage:\t%.1f%%\n", resp.Cpu.UsagePercent)
	}
	if resp.Load != nil {
		fmt.Fprintf(w, "Load:\t%.2f %.2f %.2f\n", resp.Load.Load1, resp.Load.Load5, resp.Load.Load15)
	}
	w.Flush()

	if len(resp.Disks) > 0 {
		fmt.Println()
		dw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(dw, "MOUNT\tTOTAL\tAVAILABLE\tUSED\n")
		for _, d := range resp.Disks {
			fmt.Fprintf(dw, "%s\t%s\t%s\t%s\n", d.MountPoint, humanBytes(d.TotalBytes), humanBytes(d.AvailableBytes), humanBytes(d.UsedBytes))
		}
		dw.Flush()
	}
	return nil
}

func cmdLogs(ctx context.Context, c pb.MachineServiceClient, args []string) error {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	follow := fs.Bool("f", false, "follow log output")
	unit := fs.String("u", "", "filter by systemd unit")
	lines := fs.Int("n", 100, "number of lines")
	fs.Parse(args)

	if *follow {
		ctx = context.WithoutCancel(ctx)
	}

	stream, err := c.Logs(ctx, &pb.LogsRequest{
		Follow: *follow,
		Unit:   *unit,
		Lines:  int32(*lines),
	})
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
		if entry.Unit != "" {
			fmt.Printf("%s %s: %s\n", entry.Timestamp, entry.Unit, entry.Message)
		} else {
			fmt.Printf("%s %s\n", entry.Timestamp, entry.Message)
		}
	}
}

func cmdDmesg(ctx context.Context, c pb.MachineServiceClient, args []string) error {
	fs := flag.NewFlagSet("dmesg", flag.ExitOnError)
	follow := fs.Bool("f", false, "follow output")
	lines := fs.Int("n", 100, "number of lines")
	fs.Parse(args)

	if *follow {
		ctx = context.WithoutCancel(ctx)
	}

	stream, err := c.Dmesg(ctx, &pb.DmesgRequest{
		Follow: *follow,
		Lines:  int32(*lines),
	})
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
		fmt.Printf("[%s] %s\n", entry.Priority, entry.Message)
	}
}

func cmdServiceStatus(ctx context.Context, c pb.MachineServiceClient, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: hbctl service-status <unit-name>")
	}

	resp, err := c.ServiceStatus(ctx, &pb.ServiceStatusRequest{Name: args[0]})
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Name:\t%s\n", resp.Name)
	fmt.Fprintf(w, "Description:\t%s\n", resp.Description)
	fmt.Fprintf(w, "Load State:\t%s\n", resp.LoadState)
	fmt.Fprintf(w, "Active State:\t%s\n", resp.ActiveState)
	fmt.Fprintf(w, "Sub State:\t%s\n", resp.SubState)
	if resp.UnitFileState != "" {
		fmt.Fprintf(w, "Unit File State:\t%s\n", resp.UnitFileState)
	}
	if resp.MainPid > 0 {
		fmt.Fprintf(w, "Main PID:\t%d\n", resp.MainPid)
	}
	if resp.MemoryBytes > 0 {
		fmt.Fprintf(w, "Memory:\t%s\n", humanBytes(resp.MemoryBytes))
	}
	return w.Flush()
}

func cmdConfigGet(ctx context.Context, c pb.MachineServiceClient) error {
	resp, err := c.GetConfig(ctx, &pb.GetConfigRequest{})
	if err != nil {
		return err
	}

	cfg := resp.Config
	if cfg == nil {
		fmt.Println("no config")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if cfg.Hostname != "" {
		fmt.Fprintf(w, "Hostname:\t%s\n", cfg.Hostname)
	}
	if len(cfg.DnsServers) > 0 {
		fmt.Fprintf(w, "DNS Servers:\t%s\n", strings.Join(cfg.DnsServers, ", "))
	}
	if len(cfg.NtpServers) > 0 {
		fmt.Fprintf(w, "NTP Servers:\t%s\n", strings.Join(cfg.NtpServers, ", "))
	}
	if len(cfg.KernelArgs) > 0 {
		fmt.Fprintf(w, "Kernel Args:\t%s\n", strings.Join(cfg.KernelArgs, " "))
	}
	w.Flush()

	if cfg.Network != nil && len(cfg.Network.Interfaces) > 0 {
		fmt.Println()
		nw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(nw, "INTERFACE\tDHCP\tADDRESSES\tGATEWAY\tMTU\n")
		for _, iface := range cfg.Network.Interfaces {
			dhcp := "no"
			if iface.Dhcp {
				dhcp = "yes"
			}
			addrs := strings.Join(iface.Addresses, ", ")
			mtu := ""
			if iface.Mtu > 0 {
				mtu = fmt.Sprintf("%d", iface.Mtu)
			}
			fmt.Fprintf(nw, "%s\t%s\t%s\t%s\t%s\n", iface.Name, dhcp, addrs, iface.Gateway, mtu)
		}
		nw.Flush()
	}
	return nil
}

func cmdUpgrade(ctx context.Context, c pb.MachineServiceClient, args []string) error {
	fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
	image := fs.String("image", "", "target OS image (required)")
	fs.Parse(args)

	if *image == "" {
		return fmt.Errorf("usage: hbctl upgrade --image <image-ref>")
	}

	resp, err := c.Upgrade(ctx, &pb.UpgradeRequest{Image: *image})
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Current Image:\t%s\n", resp.CurrentImage)
	fmt.Fprintf(w, "Current Digest:\t%s\n", resp.CurrentDigest)
	fmt.Fprintf(w, "Staged Image:\t%s\n", resp.StagedImage)
	fmt.Fprintf(w, "Reboot Required:\t%v\n", resp.RebootRequired)
	return w.Flush()
}

func cmdRollback(ctx context.Context, c pb.MachineServiceClient) error {
	resp, err := c.Rollback(ctx, &pb.RollbackRequest{})
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Current Image:\t%s\n", resp.CurrentImage)
	fmt.Fprintf(w, "Rollback Image:\t%s\n", resp.RollbackImage)
	fmt.Fprintf(w, "Reboot Required:\t%v\n", resp.RebootRequired)
	return w.Flush()
}

func cmdReboot(ctx context.Context, c pb.MachineServiceClient) error {
	_, err := c.Reboot(ctx, &pb.RebootRequest{})
	if err != nil {
		return err
	}
	fmt.Println("reboot initiated")
	return nil
}

func humanBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func cmdBootstrap(endpoint string, args []string) {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	token := fs.String("token", "", "bootstrap token (required)")
	fingerprint := fs.String("ca-fingerprint", "", "expected CA fingerprint sha256:<hex> (required)")
	outputDir := fs.String("output-dir", "", "directory to write certs (required)")
	fs.Parse(args)

	if *token == "" || *fingerprint == "" || *outputDir == "" {
		fmt.Fprintf(os.Stderr, "usage: hbctl bootstrap --endpoint <addr> --token <token> --ca-fingerprint sha256:<hex> --output-dir <dir>\n")
		os.Exit(1)
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: verifyFingerprint(*fingerprint),
	}

	conn, err := grpc.NewClient(
		endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		fatal(fmt.Errorf("connect: %w", err))
	}
	defer conn.Close()

	c := pb.NewMachineServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	hostname, _ := os.Hostname()
	cn := fmt.Sprintf("hbctl-%s", hostname)
	csrPEM, keyPEM, err := pki.GenerateCSR(cn)
	if err != nil {
		fatal(fmt.Errorf("generate CSR: %w", err))
	}

	resp, err := c.BootstrapAuth(ctx, &pb.BootstrapAuthRequest{Token: *token, Csr: csrPEM})
	if err != nil {
		fatal(fmt.Errorf("bootstrap: %w", err))
	}

	if err := os.MkdirAll(*outputDir, 0o700); err != nil {
		fatal(fmt.Errorf("create output dir: %w", err))
	}

	writeFile := func(name string, data []byte, perm os.FileMode) {
		path := *outputDir + "/" + name
		if err := os.WriteFile(path, data, perm); err != nil {
			fatal(fmt.Errorf("write %s: %w", path, err))
		}
	}

	writeFile("ca.crt", resp.CaCert, 0o644)
	writeFile("client.crt", resp.ClientCert, 0o600)
	writeFile("client.key", keyPEM, 0o600)

	fmt.Printf("Bootstrap successful\n")
	fmt.Printf("  CA fingerprint: %s\n", resp.CaFingerprint)
	fmt.Printf("  Client CN:      %s\n", cn)
	fmt.Printf("  Certs written:  %s/\n", *outputDir)
	fmt.Printf("\nUsage:\n")
	fmt.Printf("  HBCTL_TLS_DIR=%s hbctl --endpoint %s version\n", *outputDir, endpoint)
}

func cmdGenToken() {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		fatal(fmt.Errorf("generate random: %w", err))
	}
	token := hex.EncodeToString(b)
	h := sha256.Sum256([]byte(token))
	hash := "sha256:" + hex.EncodeToString(h[:])

	fmt.Printf("Token: %s\n", token)
	fmt.Printf("Hash:  %s\n", hash)
	fmt.Printf("\nOn the node, write the hash to the PKI directory:\n")
	fmt.Printf("  echo '%s' > /var/lib/hummingbird/pki/bootstrap-token-hash\n", hash)
}

func verifyFingerprint(expected string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("server presented no certificate")
		}
		for _, raw := range rawCerts {
			h := sha256.Sum256(raw)
			got := "sha256:" + hex.EncodeToString(h[:])
			if got == expected {
				return nil
			}
		}
		h := sha256.Sum256(rawCerts[0])
		got := "sha256:" + hex.EncodeToString(h[:])
		return fmt.Errorf("fingerprint mismatch:\n  expected: %s\n  got:      %s", expected, got)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
