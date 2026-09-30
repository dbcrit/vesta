// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"bytes"
	"fmt"
	"time"

	channelv1 "github.com/dbcrit/vesta/api/gen/go/vesta/channel/v1"
)

// Tamper alert reasons (vesta_tamper_alerts_total{reason}).
const (
	AlertHeartbeatMissing    = "heartbeat_missing"
	AlertHeartbeatSeqGap     = "heartbeat_seq_gap"
	AlertHeartbeatRegression = "heartbeat_seq_regression"
	AlertProgramChanged      = "program_changed"
	AlertProgramMissing      = "program_missing"
	AlertProgramAdded        = "program_added"
	AlertEventSeqRegression  = "event_seq_regression"
)

const (
	defaultHeartbeatInterval = 5 * time.Second
	minHeartbeatInterval     = time.Second
	maxHeartbeatInterval     = time.Minute
)

// Alert is one tamper-evidence finding.
type Alert struct {
	Reason string
	Detail string
}

type progKey struct {
	state  channelv1.ProgState
	progID uint32
	linkID uint32
	tag    []byte
}

// hbMonitor tracks one guest's heartbeats (ARCHITECTURE §1.4.2 item 6). It
// is not safe for concurrent use; the session serializes access.
type hbMonitor struct {
	interval time.Duration
	grace    float64

	since       time.Time // last heartbeat, or when monitoring started
	lastSeq     uint64
	baseline    map[string]progKey
	ringbuf     map[uint32]uint64
	channel     uint64
	missing     bool
	seenFirstHB bool
}

func newHBMonitor(grace float64, now time.Time) *hbMonitor {
	if grace < 1 {
		grace = 2
	}
	return &hbMonitor{interval: defaultHeartbeatInterval, grace: grace, since: now, ringbuf: map[uint32]uint64{}}
}

// setBaseline records the program set reported at the handshake. Changes
// against it are alerts. A guest reconnect with the same boot keeps the
// earlier baseline, so a swap between connections is still detected.
func (m *hbMonitor) setBaseline(progs []*channelv1.ProgStatus) {
	if m.baseline != nil {
		return
	}
	m.baseline = make(map[string]progKey, len(progs))
	for _, p := range progs {
		m.baseline[p.GetId()] = progKey{state: p.GetState(), progID: p.GetProgId(), linkID: p.GetLinkId(), tag: bytes.Clone(p.GetTag())}
	}
}

// restart resets the age clock after a (re)connect.
func (m *hbMonitor) restart(now time.Time) {
	m.since = now
	m.missing = false
}

// hbDeltas are counter increments derived from cumulative heartbeat fields.
type hbDeltas struct {
	ringbuf map[uint32]uint64
	channel uint64
}

// observe processes a validated heartbeat.
func (m *hbMonitor) observe(h *channelv1.Heartbeat, now time.Time) ([]Alert, hbDeltas) {
	var alerts []Alert
	if iv := time.Duration(h.GetIntervalMs()) * time.Millisecond; iv > 0 {
		m.interval = min(max(iv, minHeartbeatInterval), maxHeartbeatInterval)
	}
	if m.seenFirstHB {
		switch {
		case h.GetSeq() <= m.lastSeq:
			alerts = append(alerts, Alert{AlertHeartbeatRegression, fmt.Sprintf("heartbeat seq %d after %d (guestd restarted?)", h.GetSeq(), m.lastSeq)})
		case h.GetSeq() != m.lastSeq+1:
			alerts = append(alerts, Alert{AlertHeartbeatSeqGap, fmt.Sprintf("heartbeat seq %d after %d", h.GetSeq(), m.lastSeq)})
		}
	}
	m.seenFirstHB = true
	m.lastSeq = h.GetSeq()
	m.since = now
	m.missing = false

	if m.baseline != nil && h.GetGlobalMode() != channelv1.GlobalMode_GLOBAL_MODE_DETACHED {
		seen := make(map[string]bool, len(h.GetProgs()))
		for _, p := range h.GetProgs() {
			seen[p.GetId()] = true
			b, ok := m.baseline[p.GetId()]
			if !ok {
				alerts = append(alerts, Alert{AlertProgramAdded, "program " + p.GetId() + " not present at handshake"})
				continue
			}
			if b.state == channelv1.ProgState_PROG_STATE_ATTACHED &&
				(p.GetState() != b.state || p.GetProgId() != b.progID || p.GetLinkId() != b.linkID || !bytes.Equal(p.GetTag(), b.tag)) {
				alerts = append(alerts, Alert{AlertProgramChanged, fmt.Sprintf("program %s: state %s prog %d link %d tag %x, handshake had prog %d link %d tag %x",
					p.GetId(), p.GetState(), p.GetProgId(), p.GetLinkId(), p.GetTag(), b.progID, b.linkID, b.tag)})
			}
		}
		for id, b := range m.baseline {
			if !seen[id] && b.state == channelv1.ProgState_PROG_STATE_ATTACHED {
				alerts = append(alerts, Alert{AlertProgramMissing, "program " + id + " no longer reported"})
			}
		}
	}

	d := hbDeltas{ringbuf: map[uint32]uint64{}}
	for _, c := range h.GetRingbufDrops() {
		prev := m.ringbuf[c.GetEventType()]
		if c.GetCount() >= prev {
			d.ringbuf[c.GetEventType()] = c.GetCount() - prev
		} else {
			d.ringbuf[c.GetEventType()] = c.GetCount() // counter reset
		}
		m.ringbuf[c.GetEventType()] = c.GetCount()
	}
	if h.GetChannelDrops() >= m.channel {
		d.channel = h.GetChannelDrops() - m.channel
	} else {
		d.channel = h.GetChannelDrops()
	}
	m.channel = h.GetChannelDrops()
	return alerts, d
}

// check returns the heartbeat age and, once per episode, an alert when it
// exceeds grace x interval.
func (m *hbMonitor) check(now time.Time) (time.Duration, *Alert) {
	age := now.Sub(m.since)
	limit := time.Duration(float64(m.interval) * m.grace)
	if age > limit && !m.missing {
		m.missing = true
		return age, &Alert{AlertHeartbeatMissing, fmt.Sprintf("no heartbeat for %s (limit %s)", age.Round(time.Millisecond), limit)}
	}
	return age, nil
}

// stale reports whether the heartbeat is overdue.
func (m *hbMonitor) stale() bool { return m.missing }
