// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/dbcrit/vesta/host/internal/metrics"
)

// Drop reasons for vesta_events_dropped_total.
const (
	DropInvalid     = "invalid"
	DropRateLimited = "rate_limited"
	DropQueueFull   = "queue_full"
	DropExportError = "export_error"
)

// PipelineConfig sizes the pipeline.
type PipelineConfig struct {
	// QueueSize is the shared export queue length.
	QueueSize int
	// PerSandboxRate and PerSandboxBurst bound each sandbox's event rate.
	PerSandboxRate  float64
	PerSandboxBurst int
	// PerSandboxInflight bounds one sandbox's share of the queue, so a
	// flooding guest cannot starve the others.
	PerSandboxInflight int64
	// FlushInterval bounds how long exported lines sit in the buffer.
	FlushInterval time.Duration
}

func (c *PipelineConfig) defaults() {
	if c.QueueSize <= 0 {
		c.QueueSize = 8192
	}
	if c.PerSandboxRate <= 0 {
		c.PerSandboxRate = 1000
	}
	if c.PerSandboxBurst <= 0 {
		c.PerSandboxBurst = 2000
	}
	if c.PerSandboxInflight <= 0 {
		c.PerSandboxInflight = 1024
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = time.Second
	}
}

type item struct {
	rec Record
	src *Source
}

// Pipeline fans records from all sandboxes into one exporter.
type Pipeline struct {
	cfg PipelineConfig
	exp Exporter
	m   *metrics.Metrics
	log *slog.Logger
	q   chan item
}

// NewPipeline builds a pipeline; call Run to start exporting.
func NewPipeline(cfg PipelineConfig, exp Exporter, m *metrics.Metrics, log *slog.Logger) *Pipeline {
	cfg.defaults()
	return &Pipeline{cfg: cfg, exp: exp, m: m, log: log, q: make(chan item, cfg.QueueSize)}
}

// Source is one sandbox's entry point into the pipeline.
type Source struct {
	p        *Pipeline
	limiter  *rate.Limiter
	inflight atomic.Int64
}

// NewSource returns a rate-limited source for one sandbox.
func (p *Pipeline) NewSource() *Source {
	return &Source{p: p, limiter: rate.NewLimiter(rate.Limit(p.cfg.PerSandboxRate), p.cfg.PerSandboxBurst)}
}

// Submit enqueues r without blocking. It returns false and counts the drop
// when the sandbox is over its rate or share, or the queue is full.
func (s *Source) Submit(r Record) bool {
	if !s.limiter.Allow() {
		s.p.m.EventsDropped.WithLabelValues(DropRateLimited).Inc()
		return false
	}
	if s.inflight.Add(1) > s.p.cfg.PerSandboxInflight {
		s.inflight.Add(-1)
		s.p.m.EventsDropped.WithLabelValues(DropQueueFull).Inc()
		return false
	}
	select {
	case s.p.q <- item{rec: r, src: s}:
		return true
	default:
		s.inflight.Add(-1)
		s.p.m.EventsDropped.WithLabelValues(DropQueueFull).Inc()
		return false
	}
}

// Run exports until ctx is done, then drains what is queued and flushes.
func (p *Pipeline) Run(ctx context.Context) {
	t := time.NewTicker(p.cfg.FlushInterval)
	defer t.Stop()
	for {
		select {
		case it := <-p.q:
			p.export(it)
		case <-t.C:
			p.flush()
		case <-ctx.Done():
			for {
				select {
				case it := <-p.q:
					p.export(it)
				default:
					p.flush()
					return
				}
			}
		}
	}
}

func (p *Pipeline) export(it item) {
	it.src.inflight.Add(-1)
	e := it.rec.Event
	if err := p.exp.Export(it.rec); err != nil {
		p.m.EventsDropped.WithLabelValues(DropExportError).Inc()
		p.log.Warn("event export failed", "err", err)
		return
	}
	p.m.EventsTotal.WithLabelValues(enumName(e.GetType().String(), "EVENT_TYPE_"), enumName(e.GetAction().String(), "ACTION_")).Inc()
}

func (p *Pipeline) flush() {
	if err := p.exp.Flush(); err != nil {
		p.log.Warn("event export flush failed", "err", err)
	}
}
