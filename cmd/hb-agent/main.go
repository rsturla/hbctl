package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/rsturla/hbctl/internal/agent"
	apiv1 "github.com/rsturla/hbctl/internal/api/v1alpha1"
	"github.com/rsturla/hbctl/internal/authn"
	authnmtls "github.com/rsturla/hbctl/internal/authn/mtls"
	authntoken "github.com/rsturla/hbctl/internal/authn/token"
	"github.com/rsturla/hbctl/internal/authz"
	authzcedar "github.com/rsturla/hbctl/internal/authz/cedar"
	"github.com/rsturla/hbctl/internal/bootstrap"
	"github.com/rsturla/hbctl/internal/config"
	"github.com/rsturla/hbctl/internal/health"
	"github.com/rsturla/hbctl/internal/pki"
	"github.com/rsturla/hbctl/internal/plugin"
	configplugin "github.com/rsturla/hbctl/plugins/config"
	"github.com/rsturla/hbctl/plugins/diagnostics"
	"github.com/rsturla/hbctl/plugins/lifecycle"
	"github.com/rsturla/hbctl/plugins/services"
	"golang.org/x/sync/errgroup"
)

// Ensure plugins are registered via init()
var _ = services.Plugin{}
var _ = diagnostics.Plugin{}
var _ = lifecycle.Plugin{}
var _ = configplugin.Plugin{}

var version = "0.1.0-dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("hb-agent %s\n", version)
		return
	}

	cfg := config.Load()
	setupLogging(cfg.LogFormat)

	slog.Info("hb-agent starting", "version", version, "plugins", cfg.Plugins)

	if err := run(cfg); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(cfg *config.Config) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if err := pki.Bootstrap(cfg.TLSDir); err != nil {
		return fmt.Errorf("pki bootstrap: %w", err)
	}

	tlsCfg, err := pki.LoadServerTLS(cfg.TLSDir)
	if err != nil {
		return fmt.Errorf("load TLS: %w", err)
	}

	auth, err := createAuthenticator(cfg)
	if err != nil {
		return fmt.Errorf("create authenticator: %w", err)
	}

	az, err := createAuthorizer(cfg)
	if err != nil {
		return fmt.Errorf("create authorizer: %w", err)
	}
	if cfg.AuthzMethod == "allow-all" {
		slog.Warn("SECURITY: using allow-all authorizer — all authenticated users have full access. Set HB_AUTHZ_METHOD=cedar for production use.")
	}

	healthAgg := health.NewAggregator()
	deps := apiv1.Deps{}

	plugins, err := loadPlugins(cfg)
	if err != nil {
		return fmt.Errorf("load plugins: %w", err)
	}
	for _, p := range plugins {
		healthAgg.Register(p.HealthChecks()...)
		buildDeps(p, &deps)
		slog.Info("plugin loaded", "name", p.Name())
	}

	bm := bootstrap.NewManager(cfg.TLSDir)
	deps.Bootstrap = bm

	if fp, err := bootstrap.CAFingerprint(cfg.TLSDir); err == nil {
		slog.Info("CA fingerprint", "fingerprint", fp)
	}
	if fp, err := bootstrap.ServerFingerprint(cfg.TLSDir); err == nil {
		slog.Info("server fingerprint", "fingerprint", fp)
	}

	srv := agent.NewServer(agent.Options{
		TLS:             tlsCfg,
		Deps:            deps,
		Auth:            auth,
		Authz:           az,
		BootstrapActive: bm.Enabled(),
	})

	lis, err := agent.Listen(ctx, cfg.ListenAddr)
	if err != nil {
		return err
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return srv.Serve(lis)
	})

	g.Go(func() error {
		<-gctx.Done()
		slog.Info("shutting down gRPC server")
		srv.GracefulStop()
		return nil
	})

	g.Go(func() error {
		return watchdogLoop(gctx, healthAgg, cfg.HealthInterval)
	})

	if _, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		slog.Warn("sd_notify READY failed", "error", err)
	}

	return g.Wait()
}

func loadPlugins(cfg *config.Config) ([]plugin.Plugin, error) {
	var plugins []plugin.Plugin
	for _, name := range cfg.Plugins {
		p, err := plugin.Create(name, nil)
		if err != nil {
			return nil, fmt.Errorf("plugin %q: %w", name, err)
		}
		if err := p.Init(); err != nil {
			return nil, fmt.Errorf("plugin %q init: %w", name, err)
		}
		plugins = append(plugins, p)
	}
	return plugins, nil
}

func buildDeps(p plugin.Plugin, deps *apiv1.Deps) {
	switch v := p.(type) {
	case *services.Plugin:
		deps.Systemd = v.Systemd()
	case *diagnostics.Plugin:
		deps.Journal = v.Journal()
		deps.Proc = v.Proc()
	case *lifecycle.Plugin:
		deps.Bootc = v.Bootc()
	case *configplugin.Plugin:
		deps.Network = v.Network()
		deps.Kargs = v.Kargs()
	}
}

func createAuthenticator(cfg *config.Config) (authn.Authenticator, error) {
	registry := authn.NewRegistry()
	registry.Register("mtls", authnmtls.New)
	registry.Register("token", authntoken.New)

	var cfgJSON json.RawMessage
	if cfg.AuthConfig != "" {
		cfgJSON = json.RawMessage(cfg.AuthConfig)
	}

	return registry.Create(cfg.AuthMethod, cfgJSON)
}

func createAuthorizer(cfg *config.Config) (authz.Authorizer, error) {
	registry := authz.NewRegistry()
	registry.Register("allow-all", authz.NewAllowAll)
	registry.Register("cedar", authzcedar.New)

	var cfgJSON json.RawMessage
	if cfg.AuthzConfig != "" {
		cfgJSON = json.RawMessage(cfg.AuthzConfig)
	}

	return registry.Create(cfg.AuthzMethod, cfgJSON)
}

func watchdogLoop(ctx context.Context, checker health.Checker, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			result, err := checker.Check(ctx)
			if err != nil {
				slog.Warn("health check failed", "error", err)
				continue
			}
			if result.Status != health.Unhealthy {
				if _, err := daemon.SdNotify(false, daemon.SdNotifyWatchdog); err != nil {
					slog.Warn("sd_notify WATCHDOG failed", "error", err)
				}
			} else {
				slog.Warn("health check unhealthy, skipping watchdog ping")
			}
		}
	}
}

func setupLogging(format string) {
	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	} else {
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	slog.SetDefault(slog.New(handler))
}
