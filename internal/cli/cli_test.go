package cli

import (
	"bytes"
	"testing"
)

type testCmd struct {
	name    string
	help    string
	called  bool
	globals Globals
	args    []string
}

func (c *testCmd) Name() string { return c.name }
func (c *testCmd) Help() string { return c.help }
func (c *testCmd) Run(g Globals, args []string) error {
	c.called = true
	c.globals = g
	c.args = args
	return nil
}

func TestApp_BasicDispatch(t *testing.T) {
	t.Parallel()

	cmd := &testCmd{name: "version", help: "Show version"}
	app := New("test", "test app")
	app.out = &bytes.Buffer{}
	app.Register(cmd)

	err := app.Run([]string{"test", "version"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !cmd.called {
		t.Error("command not called")
	}
}

func TestApp_GlobalFlags(t *testing.T) {
	t.Parallel()

	cmd := &testCmd{name: "health", help: "Health"}
	app := New("test", "test app")
	app.out = &bytes.Buffer{}
	app.Register(cmd)

	_ = app.Run([]string{"test", "--endpoint", "10.0.0.5:50000", "--tls-dir", "/tmp/certs", "health"})

	if cmd.globals.Endpoint != "10.0.0.5:50000" {
		t.Errorf("Endpoint = %q", cmd.globals.Endpoint)
	}
	if cmd.globals.TLSDir != "/tmp/certs" {
		t.Errorf("TLSDir = %q", cmd.globals.TLSDir)
	}
}

func TestApp_GlobalFlagsEquals(t *testing.T) {
	t.Parallel()

	cmd := &testCmd{name: "stats", help: "Stats"}
	app := New("test", "test app")
	app.out = &bytes.Buffer{}
	app.Register(cmd)

	_ = app.Run([]string{"test", "--endpoint=node:9000", "stats"})

	if cmd.globals.Endpoint != "node:9000" {
		t.Errorf("Endpoint = %q", cmd.globals.Endpoint)
	}
}

func TestApp_SubcommandArgs(t *testing.T) {
	t.Parallel()

	cmd := &testCmd{name: "logs", help: "Logs"}
	app := New("test", "test app")
	app.out = &bytes.Buffer{}
	app.Register(cmd)

	_ = app.Run([]string{"test", "logs", "-f", "-n", "50"})

	if len(cmd.args) != 3 || cmd.args[0] != "-f" {
		t.Errorf("args = %v", cmd.args)
	}
}

func TestApp_UnknownCommand(t *testing.T) {
	t.Parallel()

	app := New("test", "test app")
	app.out = &bytes.Buffer{}

	err := app.Run([]string{"test", "nope"})
	if err == nil {
		t.Error("expected error for unknown command")
	}
}

func TestApp_Help(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	app := New("hbctl", "Hummingbird node management CLI")
	app.out = &buf
	app.Register(&testCmd{name: "version", help: "Show version"})
	app.Register(&testCmd{name: "health", help: "Show health"})

	_ = app.Run([]string{"hbctl", "help"})

	out := buf.String()
	if !contains(out, "version") {
		t.Error("help should list version")
	}
	if !contains(out, "health") {
		t.Error("help should list health")
	}
	if !contains(out, "--endpoint") {
		t.Error("help should show --endpoint")
	}
}

func TestApp_NoArgs(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	app := New("test", "test")
	app.out = &buf

	_ = app.Run([]string{"test"})

	if !contains(buf.String(), "Usage:") {
		t.Error("no args should show usage")
	}
}

func TestApp_DefaultsFromEnv(t *testing.T) {
	t.Setenv("HBCTL_ENDPOINT", "env-host:1234")
	t.Setenv("HBCTL_TLS_DIR", "/env/certs")

	cmd := &testCmd{name: "ver", help: "v"}
	app := New("test", "test")
	app.out = &bytes.Buffer{}
	app.Register(cmd)

	_ = app.Run([]string{"test", "ver"})

	if cmd.globals.Endpoint != "env-host:1234" {
		t.Errorf("Endpoint = %q, want env value", cmd.globals.Endpoint)
	}
	if cmd.globals.TLSDir != "/env/certs" {
		t.Errorf("TLSDir = %q, want env value", cmd.globals.TLSDir)
	}
}

func TestApp_FlagOverridesEnv(t *testing.T) {
	t.Setenv("HBCTL_ENDPOINT", "env-host:1234")

	cmd := &testCmd{name: "ver", help: "v"}
	app := New("test", "test")
	app.out = &bytes.Buffer{}
	app.Register(cmd)

	_ = app.Run([]string{"test", "--endpoint", "flag-host:5678", "ver"})

	if cmd.globals.Endpoint != "flag-host:5678" {
		t.Errorf("Endpoint = %q, flag should override env", cmd.globals.Endpoint)
	}
}

func contains(s, sub string) bool {
	return len(s) > 0 && len(sub) > 0 && bytes.Contains([]byte(s), []byte(sub))
}
