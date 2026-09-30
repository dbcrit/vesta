// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"errors"
	"net"
	"testing"
	"time"

	channelv1 "github.com/dbcrit/vesta/api/gen/go/vesta/channel/v1"
	"github.com/dbcrit/vesta/host/internal/wire"
)

func prog(id string, progID, link uint32, tag byte, st channelv1.ProgState) *channelv1.ProgStatus {
	t := make([]byte, 8)
	t[0] = tag
	return &channelv1.ProgStatus{Id: id, ProgId: progID, LinkId: link, Tag: t, State: st}
}

func reasons(a []Alert) map[string]int {
	m := map[string]int{}
	for _, x := range a {
		m[x.Reason]++
	}
	return m
}

func TestHBMonitor(t *testing.T) {
	now := time.Unix(1000, 0)
	m := newHBMonitor(2, now)
	att := channelv1.ProgState_PROG_STATE_ATTACHED
	m.setBaseline([]*channelv1.ProgStatus{prog("P1", 1, 1, 1, att), prog("N1", 2, 2, 2, att), prog("P2", 0, 0, 0, channelv1.ProgState_PROG_STATE_FAILED)})
	// A second handshake does not reset the baseline.
	m.setBaseline([]*channelv1.ProgStatus{prog("P1", 9, 9, 9, att)})

	steps := []struct {
		hb   *channelv1.Heartbeat
		want map[string]int
	}{
		{hb: &channelv1.Heartbeat{Seq: 1, IntervalMs: 5000, Progs: []*channelv1.ProgStatus{prog("P1", 1, 1, 1, att), prog("N1", 2, 2, 2, att)}}, want: map[string]int{}},
		{hb: &channelv1.Heartbeat{Seq: 2, Progs: []*channelv1.ProgStatus{prog("P1", 1, 1, 1, att), prog("N1", 2, 7, 2, att)}}, want: map[string]int{AlertProgramChanged: 1}},
		{hb: &channelv1.Heartbeat{Seq: 4, Progs: []*channelv1.ProgStatus{prog("P1", 1, 1, 1, att)}}, want: map[string]int{AlertHeartbeatSeqGap: 1, AlertProgramMissing: 1}},
		{hb: &channelv1.Heartbeat{Seq: 1, Progs: []*channelv1.ProgStatus{prog("P1", 1, 1, 1, att), prog("N1", 2, 2, 2, att), prog("X", 3, 3, 3, att)}}, want: map[string]int{AlertHeartbeatRegression: 1, AlertProgramAdded: 1}},
		{hb: &channelv1.Heartbeat{Seq: 2, GlobalMode: channelv1.GlobalMode_GLOBAL_MODE_DETACHED}, want: map[string]int{}},
	}
	for i, s := range steps {
		got, _ := m.observe(s.hb, now)
		r := reasons(got)
		if len(r) != len(s.want) {
			t.Fatalf("step %d: alerts %v, want %v", i, r, s.want)
		}
		for k, v := range s.want {
			if r[k] != v {
				t.Fatalf("step %d: alerts %v, want %v", i, r, s.want)
			}
		}
	}
	if m.interval != 5*time.Second {
		t.Fatalf("interval %v", m.interval)
	}

	// Missing heartbeat: alert once per episode.
	if _, a := m.check(now.Add(9 * time.Second)); a != nil {
		t.Fatal("alerted within 2x interval")
	}
	if _, a := m.check(now.Add(11 * time.Second)); a == nil || a.Reason != AlertHeartbeatMissing {
		t.Fatal("no missing alert")
	}
	if _, a := m.check(now.Add(20 * time.Second)); a != nil {
		t.Fatal("alerted twice for one episode")
	}
	if !m.stale() {
		t.Fatal("not stale")
	}
}

func TestHBMonitorIntervalClampAndDeltas(t *testing.T) {
	m := newHBMonitor(2, time.Now())
	m.observe(&channelv1.Heartbeat{Seq: 1, IntervalMs: 1}, time.Now())
	if m.interval != minHeartbeatInterval {
		t.Fatalf("interval %v", m.interval)
	}
	m.observe(&channelv1.Heartbeat{Seq: 2, IntervalMs: 3_600_000}, time.Now())
	if m.interval != maxHeartbeatInterval {
		t.Fatalf("interval %v", m.interval)
	}
	_, d := m.observe(&channelv1.Heartbeat{Seq: 3, ChannelDrops: 10, RingbufDrops: []*channelv1.DropCount{{EventType: 1, Count: 5}}}, time.Now())
	if d.channel != 10 || d.ringbuf[1] != 5 {
		t.Fatalf("%+v", d)
	}
	_, d = m.observe(&channelv1.Heartbeat{Seq: 4, ChannelDrops: 12, RingbufDrops: []*channelv1.DropCount{{EventType: 1, Count: 5}}}, time.Now())
	if d.channel != 2 || d.ringbuf[1] != 0 {
		t.Fatalf("%+v", d)
	}
	// Counter reset (guestd restart) counts the new value.
	_, d = m.observe(&channelv1.Heartbeat{Seq: 5, ChannelDrops: 3}, time.Now())
	if d.channel != 3 {
		t.Fatalf("%+v", d)
	}
}

func TestValidateHeartbeatAndHello(t *testing.T) {
	bad := []*channelv1.Heartbeat{
		{PolicyHash: make([]byte, 31)},
		{GlobalMode: 9},
		{Progs: make([]*channelv1.ProgStatus, 65)},
		{Progs: []*channelv1.ProgStatus{{Id: ""}}},
		{Progs: []*channelv1.ProgStatus{{Id: "P1", Tag: make([]byte, 4)}}},
		{Progs: []*channelv1.ProgStatus{{Id: "P1", State: 42}}},
		{RingbufDrops: []*channelv1.DropCount{{EventType: 16}}},
		{RingbufDrops: make([]*channelv1.DropCount, 17)},
	}
	for i, h := range bad {
		if err := validateHeartbeat(h); err == nil {
			t.Errorf("heartbeat %d accepted", i)
		}
	}
	long := string(make([]byte, 200))
	badHello := []*channelv1.HelloReply{
		nil,
		{GuestImageVersion: long},
		{KernelRelease: long + long},
		{ActiveLsms: make([]string, 33)},
		{Features: []string{long}},
		{GlobalMode: 7},
	}
	for i, h := range badHello {
		if err := validateHelloReply(h); err == nil {
			t.Errorf("hello %d accepted", i)
		}
	}
	if err := validateAck(&channelv1.Ack{Warnings: make([]string, 65)}); err == nil {
		t.Error("ack with too many warnings accepted")
	}
}

func TestCtrlUnknownResponseClosesConnection(t *testing.T) {
	host, guest := net.Pipe()
	cc := newCtrlConn(host, wire.Options{}, nil)
	g := wire.NewConn(guest, wire.Options{})
	defer g.Close()
	go func() {
		_ = g.Send(&channelv1.ControlResponse{RequestId: 77, Body: &channelv1.ControlResponse_Ack{Ack: &channelv1.Ack{}}})
	}()
	select {
	case <-cc.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("unknown response id did not close the connection")
	}
	var perr *ProtocolError
	if !errors.As(cc.Err(), &perr) {
		t.Fatalf("err = %v", cc.Err())
	}
}
