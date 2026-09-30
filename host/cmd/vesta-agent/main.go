// SPDX-License-Identifier: Apache-2.0

// Command vesta-agent is the vesta node agent (ARCHITECTURE §2.2): an NRI
// plugin that connects to vesta-guestd in every vesta Kata sandbox, gates
// container start on policy binds, and exports guest events.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	channelv1 "github.com/dbcrit/vesta/api/gen/go/vesta/channel/v1"
	"github.com/dbcrit/vesta/host/internal/agentconfig"
	"github.com/dbcrit/vesta/host/internal/events"
	"github.com/dbcrit/vesta/host/internal/httpserver"
	"github.com/dbcrit/vesta/host/internal/metrics"
	"github.com/dbcrit/vesta/host/internal/nriplugin"
	"github.com/dbcrit/vesta/host/internal/policy"
	"github.com/dbcrit/vesta/host/internal/sandbox"
	"github.com/dbcrit/vesta/host/internal/transport"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "0.0.0-dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(os.Stderr, "Usage of vesta-agent:\n"+agentconfig.Usage())
			os.Exit(2)
		}
		slog.Error("vesta-agent failed", "err", err)
		os.Exit(1)
	}
}

func parseLevel(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo
	}
	return l
}

func globalMode(s string) channelv1.GlobalMode {
	switch s {
	case "AuditOnly":
		return channelv1.GlobalMode_GLOBAL_MODE_AUDIT_ONLY
	case "Detached":
		return channelv1.GlobalMode_GLOBAL_MODE_DETACHED
	default:
		return channelv1.GlobalMode_GLOBAL_MODE_NORMAL
	}
}

func run(args []string) error {
	cfg, err := agentconfig.Load(args, os.Getenv)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	// Logs go to stderr; stdout carries only exported events.
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)}))
	slog.SetDefault(log)

	var set *policy.Set
	if cfg.PolicyFile != "" {
		set, err = policy.LoadFile(cfg.PolicyFile, 0, time.Now())
		if err != nil {
			return err
		}
	} else {
		set, err = policy.Compile(nil, uint64(time.Now().UnixMilli()))
		if err != nil {
			return err
		}
	}
	log.Info("starting vesta-agent", "version", version, "node", cfg.NodeName, "handlers", cfg.Handlers,
		"policies", len(set.Policies), "generation", set.Generation, "global_mode", cfg.GlobalMode)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	m := metrics.New()
	exporter := events.NewJSONLines(os.Stdout)
	pipeline := events.NewPipeline(events.PipelineConfig{
		QueueSize: cfg.EventQueue, PerSandboxRate: cfg.EventRate, PerSandboxBurst: cfg.EventBurst,
	}, exporter, m, log.With("component", "events"))

	shim := transport.ShimClient{RunDirs: cfg.KataRunDirs}
	reg := sandbox.NewRegistry(ctx, sandbox.Config{
		Node:         cfg.NodeName,
		AgentVersion: version,
		CtrlPort:     cfg.CtrlPort,
		EvtPort:      cfg.EvtPort,
		GlobalMode:   globalMode(cfg.GlobalMode),
		Discover:     shim.AgentEndpoint,
		DialerFor: func(ep transport.Endpoint) (transport.Dialer, error) {
			return transport.DialerFor(ep, cfg.KataRunDirs)
		},
		HeartbeatGrace: cfg.HeartbeatGrace,
		Metrics:        m,
		Log:            log.With("component", "sandbox"),
		Pipeline:       pipeline,
	}, set)

	plugin, err := nriplugin.New(nriplugin.Config{
		Handlers:       cfg.Handlers,
		GateTimeout:    cfg.GateTimeout.Duration,
		DefaultFailure: cfg.DefaultFailure,
		PluginName:     cfg.PluginName,
	}, nriplugin.RegistryManager{R: reg}, m, log.With("component", "nri"))
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	pctx, cancelPipeline := context.WithCancel(context.Background())
	wg.Add(1)
	go func() { defer wg.Done(); pipeline.Run(pctx) }()
	wg.Add(1)
	go func() { defer wg.Done(); reg.RunMonitor(ctx, time.Second) }()

	errc := make(chan error, 2)
	if cfg.MetricsAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready := func() error {
				if !plugin.Registered() {
					return errors.New("NRI plugin not registered")
				}
				return nil
			}
			if err := httpserver.Serve(ctx, cfg.MetricsAddr, m.Registry, ready, log.With("component", "http")); err != nil {
				errc <- err
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := nriplugin.Run(ctx, plugin, nriplugin.RunOptions{
			SocketPath: cfg.NRISocket, Name: cfg.PluginName, Index: cfg.PluginIndex,
		}); err != nil {
			errc <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err = <-errc:
		log.Error("fatal error, shutting down", "err", err)
	}
	stop()
	reg.Close()
	cancelPipeline()
	wg.Wait()
	return err
}
