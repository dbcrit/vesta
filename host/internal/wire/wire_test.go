// SPDX-License-Identifier: Apache-2.0

package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/dbcrit/vesta/api/channel"
	channelv1 "github.com/dbcrit/vesta/api/gen/go/vesta/channel/v1"
)

func frame(n uint32, body []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, n)
	return append(b, body...)
}

func TestReadFrame(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		max     int
		want    []byte
		wantErr error
	}{
		{name: "ok", in: frame(3, []byte("abc")), want: []byte("abc")},
		{name: "zero length", in: frame(0, nil), wantErr: ErrFrameSize},
		{name: "over 1MiB", in: frame(channel.MaxFrameSize+1, nil), wantErr: ErrFrameSize},
		{name: "over custom max", in: frame(5, []byte("abcde")), max: 4, wantErr: ErrFrameSize},
		{name: "max accepted", in: frame(4, []byte("abcd")), max: 4, want: []byte("abcd")},
		{name: "huge length does not allocate", in: frame(0xFFFFFFFF, nil), wantErr: ErrFrameSize},
		{name: "truncated body", in: frame(10, []byte("abc")), wantErr: io.ErrUnexpectedEOF},
		{name: "truncated header", in: []byte{0, 0}, wantErr: io.ErrUnexpectedEOF},
		{name: "clean eof", in: nil, wantErr: io.EOF},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadFrame(bytes.NewReader(tc.in), tc.max)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestAppendFrameLimits(t *testing.T) {
	if _, err := AppendFrame(nil, nil); !errors.Is(err, ErrFrameSize) {
		t.Fatalf("empty payload: %v", err)
	}
	if _, err := AppendFrame(nil, make([]byte, channel.MaxFrameSize+1)); !errors.Is(err, ErrFrameSize) {
		t.Fatalf("oversized payload: %v", err)
	}
	b, err := AppendFrame(nil, []byte{1, 2})
	if err != nil || !bytes.Equal(b, []byte{0, 0, 0, 2, 1, 2}) {
		t.Fatalf("got %v, %v", b, err)
	}
}

func TestConnRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	ca, cb := NewConn(a, Options{}), NewConn(b, Options{})
	defer ca.Close()
	defer cb.Close()
	want := &channelv1.ControlRequest{RequestId: 9, Body: &channelv1.ControlRequest_GetStatus{GetStatus: &channelv1.GetStatus{}}}
	errc := make(chan error, 1)
	go func() { errc <- ca.Send(want) }()
	var got channelv1.ControlRequest
	if err := cb.Recv(&got, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if got.GetRequestId() != 9 || got.GetGetStatus() == nil {
		t.Fatalf("got %v", &got)
	}
}

func TestConnRejectsGarbage(t *testing.T) {
	a, b := net.Pipe()
	c := NewConn(b, Options{})
	defer c.Close()
	go func() {
		_, _ = a.Write(frame(3, []byte{0xff, 0xff, 0xff}))
		a.Close()
	}()
	var m channelv1.ControlResponse
	if err := c.Recv(&m, time.Second); err == nil {
		t.Fatal("decoding garbage succeeded")
	}
}

func TestConnFrameTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	c := NewConn(b, Options{FrameTimeout: 50 * time.Millisecond})
	defer c.Close()
	// Send only the first header byte, then stall: the idle wait is
	// unbounded, but the rest of the frame must arrive within FrameTimeout.
	go func() { _, _ = a.Write([]byte{0}) }()
	var m channelv1.ControlResponse
	start := time.Now()
	err := c.Recv(&m, 0)
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("err = %v, want timeout", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("frame timeout not applied")
	}
}

func TestConnIdleTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	c := NewConn(b, Options{})
	defer c.Close()
	var m channelv1.ControlResponse
	err := c.Recv(&m, 30*time.Millisecond)
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("err = %v, want timeout", err)
	}
}
