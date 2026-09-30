// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/dbcrit/vesta/api/channel"
	channelv1 "github.com/dbcrit/vesta/api/gen/go/vesta/channel/v1"
	eventv1 "github.com/dbcrit/vesta/api/gen/go/vesta/event/v1"
	"github.com/dbcrit/vesta/host/internal/events"
	"github.com/dbcrit/vesta/host/internal/transport"
	"github.com/dbcrit/vesta/host/internal/wire"
)

// minEvtIdle is the floor of the EVT read timeout; the guest sends a
// heartbeat at least every interval, so silence beyond a few intervals means
// the stream is dead and should be re-established.
const minEvtIdle = 5 * time.Second

// maxGapPerBatch bounds the gap one batch can report, so a hostile guest
// cannot push the shared gap counter arbitrarily.
const maxGapPerBatch = 1 << 20

// Per-session EVT limits (ARCHITECTURE §1.4.3). Frames beyond the frame
// rate are read later (backpressure on the guest). Heartbeats are expected
// about once per interval (at least 1 s); beyond the heartbeat rate they are
// dropped unprocessed, so a guest cannot turn them into a stream of
// validation work and alerts.
const (
	evtFrameRate      = 200
	evtFrameBurst     = 400
	heartbeatRate     = 2
	heartbeatBurst    = 4
	throttleFrame     = "evt_frame"
	throttleHeartbeat = "heartbeat"
)

// streamEvents subscribes on the EVT port and processes batches and
// heartbeats until the stream fails or ctx ends.
func (s *Session) streamEvents(ctx context.Context, d transport.Dialer, major uint32) error {
	nc, err := s.dial(ctx, d, s.cfg.EvtPort)
	if err != nil {
		return fmt.Errorf("dial event port: %w", err)
	}
	conn := wire.NewConn(nc, s.cfg.Wire)
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	s.mu.Lock()
	from := uint64(0)
	if s.lastSeq > 0 {
		from = s.lastSeq + 1
	}
	s.mu.Unlock()
	minor := uint32(0)
	if major == channel.ProtoMajor {
		minor = channel.ProtoMinor
	}
	if err := conn.Send(&channelv1.EventStreamMessage{Msg: &channelv1.EventStreamMessage_Subscribe{Subscribe: &channelv1.Subscribe{
		ProtoMajor: major, ProtoMinor: minor, FromSeq: from,
	}}}); err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	frames := rate.NewLimiter(evtFrameRate, evtFrameBurst)
	heartbeats := rate.NewLimiter(heartbeatRate, heartbeatBurst)
	for {
		s.mu.Lock()
		idle := max(3*s.hb.interval, minEvtIdle)
		s.mu.Unlock()
		if !frames.Allow() {
			s.cfg.Metrics.ChannelThrottled.WithLabelValues(throttleFrame).Inc()
			if err := frames.Wait(ctx); err != nil {
				return nil // ctx ended: a normal shutdown, not a stream error
			}
		}
		var msg channelv1.EventStreamMessage
		if err := conn.Recv(&msg, idle); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("event read: %w", err)
		}
		switch m := msg.GetMsg().(type) {
		case *channelv1.EventStreamMessage_EventBatch:
			acked, err := s.handleBatch(m.EventBatch)
			if err != nil {
				s.cfg.Metrics.ProtocolErrors.WithLabelValues("evt").Inc()
				return err
			}
			if err := conn.Send(&channelv1.EventStreamMessage{Msg: &channelv1.EventStreamMessage_EventAck{EventAck: &channelv1.EventAck{AckedSeq: acked}}}); err != nil {
				return fmt.Errorf("event ack: %w", err)
			}
		case *channelv1.EventStreamMessage_Heartbeat:
			if !heartbeats.Allow() {
				s.cfg.Metrics.ChannelThrottled.WithLabelValues(throttleHeartbeat).Inc()
				continue
			}
			if err := s.handleHeartbeat(m.Heartbeat); err != nil {
				s.cfg.Metrics.ProtocolErrors.WithLabelValues("evt").Inc()
				return err
			}
		case *channelv1.EventStreamMessage_Error:
			return fmt.Errorf("guest stream error %s: %.1024s", m.Error.GetCode(), m.Error.GetMessage())
		default:
			// subscribe/event_ack are host->guest only; an empty oneof is
			// malformed.
			s.cfg.Metrics.ProtocolErrors.WithLabelValues("evt").Inc()
			return &ProtocolError{Msg: fmt.Sprintf("unexpected event stream message %T", m)}
		}
	}
}

// handleBatch validates a batch, exports its valid events and returns the
// sequence number to ack. Structural violations close the stream; a single
// bad event is dropped and counted.
func (s *Session) handleBatch(b *channelv1.EventBatch) (uint64, error) {
	evs := b.GetEvents()
	if n := len(evs); n == 0 || n > maxBatchEvents {
		return 0, &ProtocolError{Msg: fmt.Sprintf("batch of %d events", n)}
	}
	if b.GetFirstSeq() != evs[0].GetSeq() {
		return 0, &ProtocolError{Msg: "batch first_seq does not match first event"}
	}
	for i := 1; i < len(evs); i++ {
		if evs[i].GetSeq() <= evs[i-1].GetSeq() {
			return 0, &ProtocolError{Msg: "batch sequence not strictly increasing"}
		}
	}

	s.mu.Lock()
	expected := s.lastSeq + 1
	if s.lastSeq > 0 && b.GetFirstSeq() < expected {
		s.mu.Unlock()
		s.alert(Alert{AlertEventSeqRegression, fmt.Sprintf("event seq %d after %d (guestd restarted?)", b.GetFirstSeq(), expected-1)})
		s.mu.Lock()
		expected = b.GetFirstSeq()
	}
	var gaps uint64
	if s.lastSeq > 0 && b.GetFirstSeq() > expected {
		gaps += b.GetFirstSeq() - expected
	}
	for i := 1; i < len(evs); i++ {
		gaps += evs[i].GetSeq() - evs[i-1].GetSeq() - 1
	}
	last := evs[len(evs)-1].GetSeq()
	s.lastSeq = last
	s.mu.Unlock()
	if gaps > 0 {
		// Cap what one batch can add to the node-wide counter.
		s.cfg.Metrics.EventSeqGaps.Add(float64(min(gaps, maxGapPerBatch)))
	}

	info := s.sandboxInfo()
	now := time.Now()
	for _, e := range evs {
		if err := events.Validate(e); err != nil {
			s.cfg.Metrics.EventsDropped.WithLabelValues(events.DropInvalid).Inc()
			s.log.Debug("dropping invalid guest event", "seq", e.GetSeq(), "err", err)
			continue
		}
		s.source.Submit(events.Enrich(e, info, s, now))
	}
	return last, nil
}

func (s *Session) handleHeartbeat(h *channelv1.Heartbeat) error {
	if err := validateHeartbeat(h); err != nil {
		return &ProtocolError{Msg: "heartbeat: " + err.Error()}
	}
	s.mu.Lock()
	alerts, d := s.hb.observe(h, time.Now())
	desired := s.appliedGen
	s.mu.Unlock()
	for _, a := range alerts {
		s.alert(a)
	}
	for t, n := range d.ringbuf {
		if n > 0 && t <= math.MaxInt32 {
			name := strings.ToLower(strings.TrimPrefix(eventv1.EventType(int32(t)).String(), "EVENT_TYPE_"))
			s.cfg.Metrics.RingbufDrops.WithLabelValues(name).Add(float64(n))
		}
	}
	if d.channel > 0 {
		s.cfg.Metrics.ChannelDrops.Add(float64(d.channel))
	}
	lag := 0.0
	if h.GetAppliedGeneration() != desired {
		lag = 1
	}
	s.cfg.Metrics.PolicyGenerationLag.WithLabelValues(s.metricLabels()...).Set(lag)
	return nil
}
