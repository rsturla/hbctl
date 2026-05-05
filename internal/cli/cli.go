package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
)

type Command interface {
	Name() string
	Help() string
	Run(globals Globals, args []string) error
}

type Globals struct {
	Endpoint string
	TLSDir   string
}

type App struct {
	name     string
	desc     string
	commands []Command
	globals  Globals
	out      io.Writer
}

func New(name, desc string) *App {
	return &App{
		name: name,
		desc: desc,
		out:  os.Stderr,
	}
}

func (a *App) Register(cmds ...Command) {
	a.commands = append(a.commands, cmds...)
}

func (a *App) Run(osArgs []string) error {
	globals, cmd, args, err := a.parse(osArgs[1:])
	if err != nil {
		return err
	}
	a.globals = globals

	if cmd == "" || cmd == "help" || cmd == "--help" || cmd == "-h" {
		a.usage()
		return nil
	}

	for _, c := range a.commands {
		if c.Name() == cmd {
			return c.Run(globals, args)
		}
	}

	_, _ = fmt.Fprintf(a.out, "unknown command: %s\n\n", cmd)
	a.usage()
	return fmt.Errorf("unknown command: %s", cmd)
}

func (a *App) parse(args []string) (Globals, string, []string, error) {
	g := Globals{
		Endpoint: envOr("HBCTL_ENDPOINT", "127.0.0.1:50000"),
		TLSDir:   envOr("HBCTL_TLS_DIR", "/var/lib/hummingbird/pki"),
	}

	for len(args) > 0 {
		switch {
		case args[0] == "--endpoint" && len(args) > 1:
			g.Endpoint = args[1]
			args = args[2:]
		case strings.HasPrefix(args[0], "--endpoint="):
			g.Endpoint = strings.TrimPrefix(args[0], "--endpoint=")
			args = args[1:]
		case args[0] == "--tls-dir" && len(args) > 1:
			g.TLSDir = args[1]
			args = args[2:]
		case strings.HasPrefix(args[0], "--tls-dir="):
			g.TLSDir = strings.TrimPrefix(args[0], "--tls-dir=")
			args = args[1:]
		default:
			return g, args[0], args[1:], nil
		}
	}

	return g, "", nil, nil
}

func (a *App) usage() {
	_, _ = fmt.Fprintf(a.out, "%s — %s\n\n", a.name, a.desc)
	_, _ = fmt.Fprintf(a.out, "Usage: %s [--endpoint <addr>] [--tls-dir <dir>] <command> [flags]\n\n", a.name)
	_, _ = fmt.Fprintf(a.out, "Global flags:\n")
	_, _ = fmt.Fprintf(a.out, "  --endpoint <addr>  Agent address (default: 127.0.0.1:50000, env: HBCTL_ENDPOINT)\n")
	_, _ = fmt.Fprintf(a.out, "  --tls-dir <dir>    TLS cert directory (default: /var/lib/hummingbird/pki, env: HBCTL_TLS_DIR)\n\n")
	_, _ = fmt.Fprintf(a.out, "Commands:\n")

	w := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
	for _, c := range a.commands {
		_, _ = fmt.Fprintf(w, "  %s\t%s\n", c.Name(), c.Help())
	}
	_ = w.Flush()
	_, _ = fmt.Fprintln(a.out)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Flags creates a flag.FlagSet for a subcommand.
func Flags(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ExitOnError)
}
