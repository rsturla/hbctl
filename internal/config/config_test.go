package config

import (
	"testing"
	"time"
)

func TestLoad_Defaults(t *testing.T) {
	cfg := Load()

	if cfg.ListenAddr != ":50000" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":50000")
	}
	if cfg.TLSDir != "/var/lib/hummingbird/pki" {
		t.Errorf("TLSDir = %q, want %q", cfg.TLSDir, "/var/lib/hummingbird/pki")
	}
	if cfg.LogFormat != "json" {
		t.Errorf("LogFormat = %q, want %q", cfg.LogFormat, "json")
	}
	if cfg.HealthInterval != 10*time.Second {
		t.Errorf("HealthInterval = %v, want %v", cfg.HealthInterval, 10*time.Second)
	}
}

func TestLoad_AllEnvOverrides(t *testing.T) {
	t.Setenv("HB_LISTEN_ADDR", ":9999")
	t.Setenv("HB_TLS_DIR", "/tmp/test-pki")
	t.Setenv("HB_LOG_FORMAT", "text")
	t.Setenv("HB_HEALTH_INTERVAL", "30s")

	cfg := Load()

	if cfg.ListenAddr != ":9999" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":9999")
	}
	if cfg.TLSDir != "/tmp/test-pki" {
		t.Errorf("TLSDir = %q, want %q", cfg.TLSDir, "/tmp/test-pki")
	}
	if cfg.LogFormat != "text" {
		t.Errorf("LogFormat = %q, want %q", cfg.LogFormat, "text")
	}
	if cfg.HealthInterval != 30*time.Second {
		t.Errorf("HealthInterval = %v, want %v", cfg.HealthInterval, 30*time.Second)
	}
}

func TestLoad_PartialEnvOverride(t *testing.T) {
	t.Setenv("HB_LISTEN_ADDR", "0.0.0.0:8443")

	cfg := Load()

	if cfg.ListenAddr != "0.0.0.0:8443" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, "0.0.0.0:8443")
	}
	if cfg.TLSDir != "/var/lib/hummingbird/pki" {
		t.Errorf("TLSDir should remain default, got %q", cfg.TLSDir)
	}
	if cfg.LogFormat != "json" {
		t.Errorf("LogFormat should remain default, got %q", cfg.LogFormat)
	}
}

func TestEnvOrDuration_ValidFormats(t *testing.T) {
	cases := []struct {
		input string
		want  time.Duration
	}{
		{"5s", 5 * time.Second},
		{"100ms", 100 * time.Millisecond},
		{"2m", 2 * time.Minute},
		{"1h", time.Hour},
		{"1m30s", 90 * time.Second},
	}

	for _, tc := range cases {
		t.Setenv("TEST_DUR", tc.input)
		got := envOrDuration("TEST_DUR", time.Second)
		if got != tc.want {
			t.Errorf("envOrDuration(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestEnvOrDuration_InvalidFallsBack(t *testing.T) {
	cases := []string{
		"not-a-duration",
		"abc",
		"123",
		"-",
		"5x",
	}

	fallback := 10 * time.Second
	for _, input := range cases {
		t.Setenv("TEST_DUR", input)
		got := envOrDuration("TEST_DUR", fallback)
		if got != fallback {
			t.Errorf("envOrDuration(%q) = %v, want fallback %v", input, got, fallback)
		}
	}
}

func TestEnvOr_EmptyValueUsesDefault(t *testing.T) {
	t.Setenv("HB_LISTEN_ADDR", "")
	got := envOr("HB_LISTEN_ADDR", ":50000")
	if got != ":50000" {
		t.Errorf("empty env should use default, got %q", got)
	}
}

func TestLoad_HealthUnits_Default(t *testing.T) {
	cfg := Load()
	if len(cfg.HealthUnits) != 2 {
		t.Fatalf("HealthUnits = %v, want 2 defaults", cfg.HealthUnits)
	}
	if cfg.HealthUnits[0] != "crio.service" || cfg.HealthUnits[1] != "kubelet.service" {
		t.Errorf("HealthUnits = %v", cfg.HealthUnits)
	}
}

func TestLoad_HealthUnits_Override(t *testing.T) {
	t.Setenv("HB_HEALTH_UNITS", "sshd.service,chronyd.service,nginx.service")
	cfg := Load()
	if len(cfg.HealthUnits) != 3 {
		t.Fatalf("HealthUnits = %v, want 3", cfg.HealthUnits)
	}
	if cfg.HealthUnits[0] != "sshd.service" {
		t.Errorf("HealthUnits[0] = %q", cfg.HealthUnits[0])
	}
}

func TestEnvOrStringSlice_Whitespace(t *testing.T) {
	t.Setenv("TEST_UNITS", " a.service , b.service , ")
	got := envOrStringSlice("TEST_UNITS", nil)
	if len(got) != 2 {
		t.Fatalf("got %v, want 2 items", got)
	}
	if got[0] != "a.service" || got[1] != "b.service" {
		t.Errorf("got %v", got)
	}
}

func TestEnvOrStringSlice_Empty(t *testing.T) {
	t.Setenv("TEST_UNITS", "")
	got := envOrStringSlice("TEST_UNITS", []string{"default.service"})
	if len(got) != 1 || got[0] != "default.service" {
		t.Errorf("got %v, want [default.service]", got)
	}
}

func FuzzEnvOrDuration(f *testing.F) {
	f.Add("10s")
	f.Add("100ms")
	f.Add("1h30m")
	f.Add("")
	f.Add("not-duration")
	f.Add("-1s")
	f.Add("999999h")
	f.Add("0")

	fallback := 5 * time.Second
	f.Fuzz(func(t *testing.T, input string) {
		for _, c := range input {
			if c == 0 {
				return
			}
		}
		t.Setenv("FUZZ_DUR", input)
		d := envOrDuration("FUZZ_DUR", fallback)
		_ = d
	})
}

func FuzzEnvOrStringSlice(f *testing.F) {
	f.Add("a,b,c")
	f.Add("")
	f.Add(",,,")
	f.Add("single")
	f.Add(" spaces , everywhere , ")

	f.Fuzz(func(t *testing.T, input string) {
		for _, c := range input {
			if c == 0 {
				return
			}
		}
		t.Setenv("FUZZ_SLICE", input)
		result := envOrStringSlice("FUZZ_SLICE", nil)
		for _, s := range result {
			if s == "" {
				t.Error("empty string in result slice")
			}
		}
	})
}
