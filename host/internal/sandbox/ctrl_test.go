// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	channelv1 "github.com/dbcrit/vesta/api/gen/go/vesta/channel/v1"
	"github.com/dbcrit/vesta/host/internal/wire"
)

func unbindReq() *channelv1.ControlRequest {
	return &channelv1.ControlRequest{Body: &channelv1.ControlRequest_Unbind{Unbind: &channelv1.Unbind{ContainerId: "c1"}}}
}

// A guest that never reads must not hold a caller beyond its context.
func TestCtrlStartBoundedByContext(t *testing.T) {
	host, guest := net.Pipe()
	defer guest.Close()
	cc := newCtrlConn(host, wire.Options{WriteTimeout: 5 * time.Second}, nil)
	defer cc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, _, err := cc.Start(ctx, unbindReq()); err == nil {
		t.Fatal("send to a stalled guest succeeded")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Start took %s, want about 100ms", d)
	}
	select {
	case <-cc.Done():
	case <-time.After(time.Second):
		t.Fatal("a cut-off write must fail the connection")
	}
	if _, _, err := cc.Start(context.Background(), unbindReq()); !errors.Is(err, ErrClosed) {
		t.Fatalf("later request: %v, want ErrClosed", err)
	}
}

// Waiting behind another writer ends with ErrNotSent and keeps the connection.
func TestCtrlStartNotSentKeepsConnection(t *testing.T) {
	host, guest := net.Pipe()
	defer guest.Close()
	cc := newCtrlConn(host, wire.Options{WriteTimeout: 5 * time.Second}, nil)
	defer cc.Close()

	first := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		defer cancel()
		_, _, err := cc.Start(ctx, unbindReq())
		first <- err
	}()
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, err := cc.Start(ctx, unbindReq())
	if !errors.Is(err, wire.ErrNotSent) {
		t.Fatalf("second request: %v, want ErrNotSent", err)
	}
	if n := cc.outstanding(); n != 1 {
		t.Fatalf("outstanding %d, want 1 (the unsent request is not pending)", n)
	}
	if err := <-first; err == nil {
		t.Fatal("first request to a stalled guest succeeded")
	}
}

// Requests the guest never answers are reclaimed, and too many of them
// fail the connection instead of wedging it.
func TestCtrlAbandonedRequestsAreReclaimed(t *testing.T) {
	host, guest := net.Pipe()
	defer guest.Close()
	g := wire.NewConn(guest, wire.Options{})
	go func() {
		for {
			var req channelv1.ControlRequest
			if g.Recv(&req, 0) != nil {
				return
			}
		}
	}()
	cc := newCtrlConn(host, wire.Options{}, nil)
	defer cc.Close()
	for i := 0; i <= maxAbandoned; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		_, err := cc.Call(ctx, unbindReq())
		cancel()
		if err == nil {
			t.Fatal("unanswered call succeeded")
		}
		if i < maxAbandoned && cc.outstanding() != 0 {
			t.Fatalf("pending entries leak: %d", cc.outstanding())
		}
	}
	select {
	case <-cc.Done():
	case <-time.After(time.Second):
		t.Fatal("connection not failed after too many unanswered requests")
	}
}
