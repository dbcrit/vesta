// SPDX-License-Identifier: Apache-2.0

// Package metrics defines vesta-agent's Prometheus metrics (ARCHITECTURE
// §2.7). Label values are always host-chosen (enum names, NRI metadata),
// never guest-supplied strings, so a guest cannot inflate cardinality.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Sandbox states for vesta_sandboxes.
const (
	StateMonitored   = "monitored"
	StateUnmonitored = "unmonitored"
	StateIneligible  = "ineligible"
)

// Metrics holds every collector. Construct with New; a zero value is not
// usable.
type Metrics struct {
	Registry *prometheus.Registry

	EventsTotal         *prometheus.CounterVec // type, action
	EventsDropped       *prometheus.CounterVec // reason
	RingbufDrops        *prometheus.CounterVec // type
	ChannelDrops        prometheus.Counter     //
	EventSeqGaps        prometheus.Counter     //
	HeartbeatAge        *prometheus.GaugeVec   // namespace, pod, sandbox_id
	PolicyGenerationLag *prometheus.GaugeVec   // namespace, pod, sandbox_id
	ProgramLoadFailures prometheus.Counter     //
	ChannelRTT          prometheus.Histogram   //
	Sandboxes           *prometheus.GaugeVec   // state
	TamperAlerts        *prometheus.CounterVec // reason
	ProtocolErrors      *prometheus.CounterVec // conn
	GateDecisions       *prometheus.CounterVec // hook, result
	ChannelConnects     *prometheus.CounterVec // result
	NRIConnected        prometheus.Gauge       //
	ChannelThrottled    *prometheus.CounterVec // kind
}

// Sandbox gauge labels. sandbox_id keeps series of a recreated pod (same
// namespace and name) apart; it is NRI-reported and validated, not guest data.
var sandboxLabels = []string{"namespace", "pod", "sandbox_id"}

// New registers all collectors on a fresh registry, plus the Go and process
// collectors.
func New() *Metrics {
	r := prometheus.NewRegistry()
	m := &Metrics{
		Registry: r,
		EventsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vesta_events_total", Help: "Guest events accepted and exported, by type and action.",
		}, []string{"type", "action"}),
		EventsDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vesta_events_dropped_total", Help: "Guest events dropped on the host, by reason.",
		}, []string{"reason"}),
		RingbufDrops: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vesta_ringbuf_drops_total", Help: "Guest BPF ring buffer drops reported in heartbeats, by event type.",
		}, []string{"type"}),
		ChannelDrops: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vesta_channel_drops_total", Help: "Events evicted by vesta-guestd under backpressure, reported in heartbeats.",
		}),
		EventSeqGaps: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vesta_event_seq_gaps_total", Help: "Events missing from the EVT stream (sequence gaps).",
		}),
		HeartbeatAge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "vesta_guest_heartbeat_age_seconds", Help: "Seconds since the last guest heartbeat.",
		}, sandboxLabels),
		PolicyGenerationLag: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "vesta_policy_generation_lag", Help: "1 when the guest's applied policy generation differs from the desired one, else 0.",
		}, sandboxLabels),
		ProgramLoadFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vesta_program_load_failures_total", Help: "Guest BPF programs reported as failed at handshake.",
		}),
		ChannelRTT: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "vesta_channel_rtt_seconds", Help: "CTRL request round-trip time.",
			Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5},
		}),
		Sandboxes: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "vesta_sandboxes", Help: "vesta sandboxes on this node by state.",
		}, []string{"state"}),
		TamperAlerts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vesta_tamper_alerts_total", Help: "Tamper-evidence alerts (heartbeat missing, sequence gap, program change).",
		}, []string{"reason"}),
		ProtocolErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vesta_channel_protocol_errors_total", Help: "Connections closed because the guest violated the protocol.",
		}, []string{"conn"}),
		GateDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vesta_gate_decisions_total", Help: "NRI gate outcomes for vesta containers.",
		}, []string{"hook", "result"}),
		ChannelConnects: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vesta_channel_connects_total", Help: "Channel connection attempts by result.",
		}, []string{"result"}),
		NRIConnected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vesta_nri_connected", Help: "1 while the NRI plugin is registered with the runtime.",
		}),
		ChannelThrottled: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vesta_channel_throttled_total", Help: "Guest EVT frames delayed or dropped by the per-sandbox rate limits, by kind.",
		}, []string{"kind"}),
	}
	r.MustRegister(
		m.EventsTotal, m.EventsDropped, m.RingbufDrops, m.ChannelDrops, m.EventSeqGaps,
		m.HeartbeatAge, m.PolicyGenerationLag, m.ProgramLoadFailures, m.ChannelRTT,
		m.Sandboxes, m.TamperAlerts, m.ProtocolErrors, m.GateDecisions, m.ChannelConnects,
		m.NRIConnected, m.ChannelThrottled,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	for _, s := range []string{StateMonitored, StateUnmonitored, StateIneligible} {
		m.Sandboxes.WithLabelValues(s).Set(0)
	}
	return m
}
