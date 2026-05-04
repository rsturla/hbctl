package config

import (
	"os"
	"strings"
	"time"
)

type Config struct {
	ListenAddr     string
	TLSDir         string
	LogFormat      string
	HealthInterval time.Duration
	HealthUnits    []string
	AuthMethod     string
	AuthConfig     string
	AuthzMethod    string
	AuthzConfig    string
}

func Load() *Config {
	return &Config{
		ListenAddr:     envOr("HB_LISTEN_ADDR", ":50000"),
		TLSDir:         envOr("HB_TLS_DIR", "/var/lib/hummingbird/pki"),
		LogFormat:      envOr("HB_LOG_FORMAT", "json"),
		HealthInterval: envOrDuration("HB_HEALTH_INTERVAL", 10*time.Second),
		HealthUnits:    envOrStringSlice("HB_HEALTH_UNITS", []string{"crio.service", "kubelet.service"}),
		AuthMethod:     envOr("HB_AUTH_METHOD", "mtls"),
		AuthConfig:     envOr("HB_AUTH_CONFIG", ""),
		AuthzMethod:    envOr("HB_AUTHZ_METHOD", "allow-all"),
		AuthzConfig:    envOr("HB_AUTHZ_CONFIG", ""),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func envOrStringSlice(key string, fallback []string) []string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var result []string
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			result = append(result, s)
		}
	}
	if len(result) == 0 {
		return fallback
	}
	return result
}
