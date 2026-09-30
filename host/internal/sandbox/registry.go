// SPDX-License-Identifier: Apache-2.0

// Package sandbox is vesta-agent's sandbox registry: one Session per vesta
// sandbox, each owning the CTRL and EVT connections to that guest
// (ARCHITECTURE §2.2, §2.3). Sessions are independent, so one guest can only
// affect its own session's state.
package sandbox

import (
	"context"
	"sync"
	"time"

	"github.com/dbcrit/vesta/host/internal/events"
	"github.com/dbcrit/vesta/host/internal/metrics"
	"github.com/dbcrit/vesta/host/internal/policy"
	"github.com/dbcrit/vesta/host/internal/transport"
)

// Registry tracks sessions by sandbox ID.
type Registry struct {
	cfg *Config
	set *policy.Set
	ctx context.Context

	mu       sync.Mutex
	sessions map[string]*Session
}

// NewRegistry creates a registry. Sessions live until removed or until ctx
// ends.
func NewRegistry(ctx context.Context, cfg Config, set *policy.Set) *Registry {
	cfg.defaults()
	return &Registry{cfg: &cfg, set: set, ctx: ctx, sessions: make(map[string]*Session)}
}

// Policies returns the current compiled policy set.
func (r *Registry) Policies() *policy.Set {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.set
}

// PolicyStats is one policy's use on this node.
type PolicyStats struct {
	// Sandboxes have at least one container the policy selects.
	Sandboxes int
	// Programmed of those have the set in force (ApplyPolicy acked).
	Programmed int
	Containers int
}

// PolicyStats reports, per policy id of set, how many sandboxes and
// containers use it and how many of those sandboxes have set applied.
func (r *Registry) PolicyStats(set *policy.Set) map[uint32]PolicyStats {
	r.mu.Lock()
	all := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		all = append(all, s)
	}
	r.mu.Unlock()
	out := map[uint32]PolicyStats{}
	for _, s := range all {
		use, programmed := s.policyUse(set)
		for id, n := range use {
			st := out[id]
			st.Sandboxes++
			st.Containers += n
			if programmed {
				st.Programmed++
			}
			out[id] = st
		}
	}
	return out
}

// SetPolicies swaps the policy set and pushes it to every session. Sessions
// created afterwards start with it.
func (r *Registry) SetPolicies(set *policy.Set) {
	r.mu.Lock()
	r.set = set
	all := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		all = append(all, s)
	}
	r.mu.Unlock()
	for _, s := range all {
		s.setPolicies(set)
	}
}

// Ensure returns the session for info.SandboxID, creating and starting it
// if needed. It never blocks on the guest.
func (r *Registry) Ensure(info events.SandboxInfo) (*Session, bool) {
	if !transport.ValidSandboxID(info.SandboxID) {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[info.SandboxID]; ok {
		return s, true
	}
	info.Node = r.cfg.Node
	s := newSession(r.cfg, info, r.set)
	r.sessions[info.SandboxID] = s
	s.start(r.ctx)
	return s, true
}

// Get returns the session for id.
func (r *Registry) Get(id string) (*Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	return s, ok
}

// Remove forgets the session for id and stops it in the background: NRI
// hooks call this, and a guest must not be able to stall them.
func (r *Registry) Remove(id string) {
	r.remove(id)
}

func (r *Registry) remove(id string) <-chan struct{} {
	r.mu.Lock()
	s, ok := r.sessions[id]
	delete(r.sessions, id)
	r.mu.Unlock()
	if !ok {
		done := make(chan struct{})
		close(done)
		return done
	}
	stopped := s.StopAsync()
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-stopped
		// A new session for the same sandbox id may exist by now; only drop
		// the series if no live session reports it.
		if _, again := r.Get(id); !again {
			s.forgetMetrics()
		}
	}()
	return done
}

// Retain removes every session whose ID is not in keep, without waiting.
func (r *Registry) Retain(keep map[string]bool) {
	r.retain(keep)
}

func (r *Registry) retain(keep map[string]bool) []<-chan struct{} {
	r.mu.Lock()
	var drop []string
	for id := range r.sessions {
		if !keep[id] {
			drop = append(drop, id)
		}
	}
	r.mu.Unlock()
	waits := make([]<-chan struct{}, 0, len(drop))
	for _, id := range drop {
		waits = append(waits, r.remove(id))
	}
	return waits
}

// Close stops every session and waits for them.
func (r *Registry) Close() {
	for _, w := range r.retain(nil) {
		<-w
	}
}

// RunMonitor checks heartbeats and refreshes the sandbox-state gauge every
// interval until ctx ends.
func (r *Registry) RunMonitor(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			r.mu.Lock()
			all := make([]*Session, 0, len(r.sessions))
			for _, s := range r.sessions {
				all = append(all, s)
			}
			r.mu.Unlock()
			counts := map[string]float64{metrics.StateMonitored: 0, metrics.StateUnmonitored: 0, metrics.StateIneligible: 0}
			for _, s := range all {
				s.checkHeartbeat(now)
				counts[s.State()]++
			}
			for st, n := range counts {
				r.cfg.Metrics.Sandboxes.WithLabelValues(st).Set(n)
			}
		}
	}
}
