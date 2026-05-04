package kargs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRenderTOML(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
		want string
	}{
		{
			"single arg",
			[]string{"fips=1"},
			"kargs = [\"fips=1\"]\n",
		},
		{
			"multiple args",
			[]string{"console=tty0", "console=ttyS0,115200n8"},
			"kargs = [\"console=tty0\", \"console=ttyS0,115200n8\"]\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := renderTOML(tc.args)
			if got != tc.want {
				t.Errorf("renderTOML = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseTOML(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{
			"single",
			`kargs = ["fips=1"]`,
			[]string{"fips=1"},
		},
		{
			"multiple",
			`kargs = ["console=tty0", "console=ttyS0,115200n8"]`,
			[]string{"console=tty0", "console=ttyS0,115200n8"},
		},
		{
			"with match-architectures",
			"kargs = [\"rw\"]\nmatch-architectures = [\"x86_64\"]",
			[]string{"rw"},
		},
		{
			"empty array",
			`kargs = []`,
			nil,
		},
		{
			"no kargs line",
			"match-architectures = [\"x86_64\"]",
			nil,
		},
		{
			"empty string",
			"",
			nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseTOML(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("parseTOML returned %d args, want %d: %v", len(got), len(tc.want), got)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("arg[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestRenderParseRoundTrip(t *testing.T) {
	t.Parallel()

	args := []string{"systemd.unified_cgroup_hierarchy=1", "fips=1", "selinux=1"}
	content := renderTOML(args)
	parsed := parseTOML(content)

	if len(parsed) != len(args) {
		t.Fatalf("round-trip: got %d args, want %d", len(parsed), len(args))
	}
	for i := range args {
		if parsed[i] != args[i] {
			t.Errorf("arg[%d] = %q, want %q", i, parsed[i], args[i])
		}
	}
}

func TestWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager()

	args := []string{"fips=1", "selinux=1"}
	if err := mgr.Write(dir, args); err != nil {
		t.Fatalf("Write: %v", err)
	}

	read, err := mgr.Read(dir)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if len(read) != 2 {
		t.Fatalf("Read returned %d args, want 2", len(read))
	}
	if read[0] != "fips=1" {
		t.Errorf("arg[0] = %q", read[0])
	}
}

func TestWrite_EmptyArgs_RemovesFile(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager()

	mgr.Write(dir, []string{"fips=1"})

	if err := mgr.Write(dir, nil); err != nil {
		t.Fatalf("Write empty: %v", err)
	}

	path := filepath.Join(dir, filename)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should be removed for empty args")
	}
}

func TestRead_NonexistentDir(t *testing.T) {
	mgr := NewManager()
	args, err := mgr.Read("/nonexistent-12345")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(args) != 0 {
		t.Errorf("expected empty, got %v", args)
	}
}

func TestRead_NoFile(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager()

	args, err := mgr.Read(dir)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(args) != 0 {
		t.Errorf("expected empty, got %v", args)
	}
}

func TestWrite_CreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "kargs")
	mgr := NewManager()

	if err := mgr.Write(dir, []string{"test=1"}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, filename)); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

func FuzzParseTOML(f *testing.F) {
	f.Add(`kargs = ["fips=1"]`)
	f.Add(`kargs = ["a", "b", "c"]`)
	f.Add(`kargs = []`)
	f.Add(``)
	f.Add(`not toml at all`)
	f.Add(`kargs = ["console=ttyS0,115200n8"]` + "\nmatch-architectures = [\"x86_64\"]")

	f.Fuzz(func(t *testing.T, input string) {
		result := parseTOML(input)
		_ = result
	})
}
