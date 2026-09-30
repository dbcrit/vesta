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
	"sync/atomic"
	"syscall"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	channelv1 "github.com/dbcrit/vesta/api/gen/go/vesta/channel/v1"
	"github.com/dbcrit/vesta/host/internal/agentconfig"
	"github.com/dbcrit/vesta/host/internal/events"
	"github.com/dbcrit/vesta/host/internal/httpserver"
	"github.com/dbcrit/vesta/host/internal/metrics"
	"github.com/dbcrit/vesta/host/internal/nriplugin"
	"github.com/dbcrit/vesta/host/internal/policy"
	"github.com/dbcrit/vesta/host/internal/policysource"
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

// kubeSource watches VestaPolicy objects with the pod's service account.
func kubeSource(node string, reg *sandbox.Registry, m *metrics.Metrics, log *slog.Logger) (*policysource.Kube, error) {
	rc, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("kubernetes policy source: %w", err)
	}
	rc.UserAgent = "vesta-agent/" + version
	client, err := dynamic.NewForConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("kubernetes policy source: %w", err)
	}
	return &policysource.Kube{
		Client: client, Status: policysource.DynamicStatus{Client: client, Node: node},
		Stats: reg, Node: node, Metrics: m, Log: log,
	}, nil
}

func run(args []string) error {
	cfg, err := agentconfig.Load(args, os.Getenv)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	// Logs go to stderr; stdout carries only exported events.
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)}))
	slog.SetDefault(log)

	m := metrics.New()
	source := cfg.EffectivePolicySource()
	var (
		set        *policy.Set
		fileSource *policysource.File
		fileDigest [32]byte
	)
	switch source {
	case agentconfig.PolicySourceFile:
		fileSource = &policysource.File{
			Path: cfg.PolicyFile, Interval: cfg.PolicyReloadInterval.Duration,
			Metrics: m, Log: log.With("component", "policy"),
		}
		// An invalid file at startup is fatal; later changes that are invalid
		// keep the running set.
		if set, fileDigest, err = fileSource.Load(); err != nil {
			return err
		}
	default:
		// Kubernetes: empty until the first VestaPolicy sync.
		if set, err = policy.Compile(nil, policy.NextGeneration(0, time.Now())); err != nil {
			return err
		}
	}
	m.PoliciesLoaded.Set(float64(len(set.Policies)))
	m.PolicySetGeneration.Set(float64(set.Generation))
	log.Info("starting vesta-agent", "version", version, "node", cfg.NodeName, "handlers", cfg.Handlers,
		"policy_source", source, "policies", len(set.Policies), "generation", set.Generation, "global_mode", cfg.GlobalMode)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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

	errc := make(chan error, 3)
	var policiesSynced atomic.Bool
	switch source {
	case agentconfig.PolicySourceFile:
		policiesSynced.Store(true)
		wg.Add(1)
		go func() { defer wg.Done(); fileSource.Run(ctx, reg, fileDigest) }()
	case agentconfig.PolicySourceKubernetes:
		kube, err := kubeSource(cfg.NodeName, reg, m, log.With("component", "policy"))
		if err != nil {
			stop()
			reg.Close()
			cancelPipeline()
			wg.Wait()
			return err
		}
		synced := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := kube.Run(ctx, reg, synced); err != nil && ctx.Err() == nil {
				errc <- fmt.Errorf("VestaPolicy watch: %w", err)
			}
		}()
		// Hold NRI back until the policies are known, so containers created
		// right after an agent start are gated with the right failure policy.
		select {
		case <-synced:
			policiesSynced.Store(true)
		case <-time.After(cfg.PolicySyncTimeout.Duration):
			log.Warn("VestaPolicy sync not complete; starting NRI with no policies", "timeout", cfg.PolicySyncTimeout.Duration)
			go func() {
				select {
				case <-synced:
					policiesSynced.Store(true)
				case <-ctx.Done():
				}
			}()
		case <-ctx.Done():
		}
	default:
		policiesSynced.Store(true)
	}
	if cfg.MetricsAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready := func() error {
				if !plugin.Registered() {
					return errors.New("NRI plugin not registered")
				}
				if !policiesSynced.Load() {
					return errors.New("VestaPolicy objects not synced")
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
