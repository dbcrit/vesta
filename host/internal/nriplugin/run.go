// SPDX-License-Identifier: Apache-2.0

package nriplugin

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/containerd/nri/pkg/stub"

	"github.com/dbcrit/vesta/host/internal/events"
	"github.com/dbcrit/vesta/host/internal/policy"
	"github.com/dbcrit/vesta/host/internal/sandbox"
)

// RegistryManager adapts *sandbox.Registry to Manager.
type RegistryManager struct{ R *sandbox.Registry }

func (a RegistryManager) Ensure(info events.SandboxInfo) (Sandbox, bool) {
	s, ok := a.R.Ensure(info)
	if !ok {
		return nil, false
	}
	return s, true
}

func (a RegistryManager) Get(id string) (Sandbox, bool) {
	s, ok := a.R.Get(id)
	if !ok {
		return nil, false
	}
	return s, true
}

func (a RegistryManager) Remove(id string)            { a.R.Remove(id) }
func (a RegistryManager) Retain(keep map[string]bool) { a.R.Retain(keep) }
func (a RegistryManager) Policies() *policy.Set       { return a.R.Policies() }

// RunOptions configures the NRI connection.
type RunOptions struct {
	SocketPath string
	Name       string
	Index      string
}

// Run registers the plugin with the runtime and re-registers after the
// connection drops (e.g. a containerd restart) until ctx ends. Synchronize
// then rebuilds the registry.
func Run(ctx context.Context, p *Plugin, o RunOptions) error {
	const minDelay, maxDelay = 500 * time.Millisecond, 10 * time.Second
	delay := minDelay
	for {
		started := time.Now()
		st, err := stub.New(p,
			stub.WithPluginName(o.Name),
			stub.WithPluginIdx(o.Index),
			stub.WithSocketPath(o.SocketPath),
			stub.WithLogger(nriLogger{p.log}),
			stub.WithOnClose(func() { p.setRegistered(false) }),
		)
		if err != nil {
			return fmt.Errorf("create NRI stub: %w", err)
		}
		err = st.Run(ctx)
		p.setRegistered(false)
		if ctx.Err() != nil {
			return nil
		}
		p.log.Warn("NRI connection ended; reconnecting", "err", err, "in", delay)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		// A connection that stayed up for a while resets the backoff.
		if time.Since(started) > time.Minute {
			delay = minDelay
		} else {
			delay = min(delay*2, maxDelay)
		}
	}
}

// nriLogger routes the stub's logging into slog.
type nriLogger struct{ l *slog.Logger }

func (n nriLogger) Debugf(ctx context.Context, f string, a ...any) {
	n.l.DebugContext(ctx, fmt.Sprintf(f, a...), "component", "nri")
}
func (n nriLogger) Infof(ctx context.Context, f string, a ...any) {
	n.l.InfoContext(ctx, fmt.Sprintf(f, a...), "component", "nri")
}
func (n nriLogger) Warnf(ctx context.Context, f string, a ...any) {
	n.l.WarnContext(ctx, fmt.Sprintf(f, a...), "component", "nri")
}
func (n nriLogger) Errorf(ctx context.Context, f string, a ...any) {
	n.l.ErrorContext(ctx, fmt.Sprintf(f, a...), "component", "nri")
}
