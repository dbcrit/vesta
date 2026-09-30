// SPDX-License-Identifier: Apache-2.0

// Package policysource keeps vesta-agent's policy set current (ARCHITECTURE
// §2.8, Phase 2): from a policy file that is re-read when its content
// changes, or from VestaPolicy objects watched through the API server. Each
// change is compiled against the previous set, so policy ids stay stable,
// and handed to the sandbox registry, which pushes it to every live guest.
package policysource

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"time"

	"github.com/dbcrit/vesta/host/internal/metrics"
	"github.com/dbcrit/vesta/host/internal/policy"
)

// Sink receives compiled policy sets; *sandbox.Registry implements it.
type Sink interface {
	Policies() *policy.Set
	SetPolicies(*policy.Set)
}

// Reload results for vesta_policy_reloads_total.
const (
	resultApplied  = "applied"
	resultRejected = "rejected"
	resultError    = "error"
)

func publish(sink Sink, set *policy.Set, rejected int, m *metrics.Metrics) {
	sink.SetPolicies(set)
	m.PoliciesLoaded.Set(float64(len(set.Policies)))
	m.PoliciesRejected.Set(float64(rejected))
	m.PolicySetGeneration.Set(float64(set.Generation))
}

// File re-reads a policy file (typically a mounted ConfigMap, which the
// kubelet updates by swapping a symlink) and applies it when its content
// changes. A file that fails to read, parse or validate keeps the current
// set in force; policies in a file are all-or-nothing.
type File struct {
	Path     string
	Interval time.Duration
	Metrics  *metrics.Metrics
	Log      *slog.Logger
	// Now is the clock for generations; nil means time.Now.
	Now func() time.Time
}

func (f *File) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// Load compiles the file for the initial set.
func (f *File) Load() (*policy.Set, [32]byte, error) {
	data, err := policy.ReadFile(f.Path)
	if err != nil {
		return nil, [32]byte{}, err
	}
	set, err := f.compile(data, nil)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return set, sha256.Sum256(data), nil
}

func (f *File) compile(data []byte, prev *policy.Set) (*policy.Set, error) {
	pols, err := policy.Parse(data)
	if err != nil {
		return nil, err
	}
	var prevGen uint64
	if prev != nil {
		prevGen = prev.Generation
	}
	set, rejected, err := policy.CompileWith(pols, policy.NextGeneration(prevGen, f.now()), prev)
	if err != nil {
		return nil, err
	}
	// Same rule as Compile: one invalid policy rejects the file.
	if err := policy.RejectedError(rejected); err != nil {
		return nil, err
	}
	return set, nil
}

// Run polls until ctx ends. last is the digest of the content already applied.
func (f *File) Run(ctx context.Context, sink Sink, last [32]byte) {
	t := time.NewTicker(f.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		data, err := policy.ReadFile(f.Path)
		if err != nil {
			f.Metrics.PolicyReloads.WithLabelValues("file", resultError).Inc()
			f.Log.Warn("reading the policy file failed; keeping the current policies", "path", f.Path, "err", err)
			continue
		}
		sum := sha256.Sum256(data)
		if sum == last {
			continue
		}
		set, err := f.compile(data, sink.Policies())
		if err != nil {
			f.Metrics.PolicyReloads.WithLabelValues("file", resultRejected).Inc()
			f.Log.Error("changed policy file is invalid; keeping the current policies", "path", f.Path, "err", err)
			// Do not retry the same content every tick.
			last = sum
			continue
		}
		last = sum
		publish(sink, set, 0, f.Metrics)
		f.Metrics.PolicyReloads.WithLabelValues("file", resultApplied).Inc()
		f.Log.Info("policy file reloaded", "path", f.Path, "policies", len(set.Policies), "generation", set.Generation)
	}
}
