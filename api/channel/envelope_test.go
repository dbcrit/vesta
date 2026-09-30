// SPDX-License-Identifier: Apache-2.0

package channel

import (
	"testing"

	"google.golang.org/protobuf/proto"

	channelv1 "github.com/dbcrit/vesta/api/gen/go/vesta/channel/v1"
	eventv1 "github.com/dbcrit/vesta/api/gen/go/vesta/event/v1"
)

func TestEnvelopesRoundTrip(t *testing.T) {
	req := &channelv1.ControlRequest{
		RequestId: 7,
		Body: &channelv1.ControlRequest_Hello{Hello: &channelv1.Hello{
			ProtoMajor: ProtoMajor, ProtoMinor: ProtoMinor, AgentVersion: "0.1.0",
		}},
	}
	b, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got channelv1.ControlRequest
	if err := proto.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.GetHello().GetProtoMajor() != ProtoMajor || got.GetRequestId() != 7 {
		t.Fatalf("round trip mismatch: %v", &got)
	}

	msg := &channelv1.EventStreamMessage{Msg: &channelv1.EventStreamMessage_EventBatch{
		EventBatch: &channelv1.EventBatch{FirstSeq: 1, Events: []*eventv1.Event{{
			Seq: 1, Type: eventv1.EventType_EVENT_TYPE_EXEC, Action: eventv1.Action_ACTION_AUDITED,
			Detail: &eventv1.Event_Exec{Exec: &eventv1.Exec{Argc: 2}},
		}}},
	}}
	if b, err = proto.Marshal(msg); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(b)+FrameHeaderSize > MaxFrameSize {
		t.Fatalf("test frame unexpectedly large: %d", len(b))
	}
}
