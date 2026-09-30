// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	channelv1 "github.com/dbcrit/vesta/api/gen/go/vesta/channel/v1"
	"github.com/dbcrit/vesta/host/internal/wire"
)

// maxInflight bounds outstanding CTRL requests per connection.
const maxInflight = 1024

// maxAbandoned bounds requests given up on (timed out) whose late responses
// are still tolerated. Past it the guest is not answering, and the connection
// is failed so the session reconnects instead of silently refusing requests.
const maxAbandoned = 256

// ErrClosed is returned for requests on a closed CTRL connection.
var ErrClosed = errors.New("control connection closed")

// ProtocolError marks a guest protocol violation; the connection is closed.
type ProtocolError struct{ Msg string }

func (e *ProtocolError) Error() string { return "protocol violation: " + e.Msg }

// ctrlConn multiplexes ControlRequests over one CTRL connection. Responses
// are matched by request_id and may arrive in any order.
type ctrlConn struct {
	c *wire.Conn

	mu        sync.Mutex
	nextID    uint64
	pending   map[uint64]chan *channelv1.ControlResponse
	abandoned map[uint64]struct{}
	err       error
	done      chan struct{}

	onRTT func(time.Duration)
}

func newCtrlConn(nc net.Conn, o wire.Options, onRTT func(time.Duration)) *ctrlConn {
	cc := &ctrlConn{
		c:         wire.NewConn(nc, o),
		pending:   make(map[uint64]chan *channelv1.ControlResponse),
		abandoned: make(map[uint64]struct{}),
		done:      make(chan struct{}),
		onRTT:     onRTT,
	}
	go cc.readLoop()
	return cc
}

// Done is closed when the connection has failed or been closed.
func (cc *ctrlConn) Done() <-chan struct{} { return cc.done }

// Err returns why the connection ended.
func (cc *ctrlConn) Err() error {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.err
}

func (cc *ctrlConn) Close() { cc.fail(ErrClosed) }

func (cc *ctrlConn) fail(err error) {
	cc.mu.Lock()
	if cc.err != nil {
		cc.mu.Unlock()
		return
	}
	cc.err = err
	pending := cc.pending
	cc.pending = nil
	cc.mu.Unlock()
	_ = cc.c.Close()
	for _, ch := range pending {
		close(ch)
	}
	close(cc.done)
}

func (cc *ctrlConn) readLoop() {
	for {
		var resp channelv1.ControlResponse
		// CTRL is request/response: the guest has nothing to say while
		// idle, so only the per-frame timeout applies.
		if err := cc.c.Recv(&resp, 0); err != nil {
			cc.fail(fmt.Errorf("control read: %w", err))
			return
		}
		if resp.GetBody() == nil {
			cc.fail(&ProtocolError{Msg: "control response without body"})
			return
		}
		id := resp.GetRequestId()
		cc.mu.Lock()
		ch, ok := cc.pending[id]
		if ok {
			delete(cc.pending, id)
		}
		_, late := cc.abandoned[id]
		delete(cc.abandoned, id)
		cc.mu.Unlock()
		if late {
			continue
		}
		if !ok {
			if id == 0 && resp.GetError() != nil {
				cc.fail(fmt.Errorf("guest error %s: %.1024s", resp.GetError().GetCode(), resp.GetError().GetMessage()))
			} else {
				cc.fail(&ProtocolError{Msg: fmt.Sprintf("response for unknown request %d", id)})
			}
			return
		}
		ch <- &resp // buffered, never blocks
	}
}

// Start sends req within ctx and returns its request id and a channel that
// yields the response, or is closed without a value if the connection fails
// first. A write cut off part-way fails the connection, so later requests
// fail fast instead of queuing behind a stalled guest.
func (cc *ctrlConn) Start(ctx context.Context, req *channelv1.ControlRequest) (uint64, <-chan *channelv1.ControlResponse, error) {
	ch := make(chan *channelv1.ControlResponse, 1)
	cc.mu.Lock()
	if cc.err != nil {
		err := cc.err
		cc.mu.Unlock()
		return 0, nil, fmt.Errorf("%w: %w", ErrClosed, err)
	}
	if len(cc.pending) >= maxInflight {
		cc.mu.Unlock()
		return 0, nil, errors.New("too many outstanding control requests")
	}
	cc.nextID++
	id := cc.nextID
	cc.pending[id] = ch
	cc.mu.Unlock()

	req.RequestId = id
	if err := cc.c.SendContext(ctx, req); err != nil {
		if errors.Is(err, wire.ErrNotSent) {
			cc.mu.Lock()
			if cc.pending != nil {
				delete(cc.pending, id)
			}
			cc.mu.Unlock()
		} else {
			cc.fail(fmt.Errorf("control write: %w", err))
		}
		return 0, nil, fmt.Errorf("send request: %w", err)
	}
	return id, ch, nil
}

// Call sends req and waits for its response.
func (cc *ctrlConn) Call(ctx context.Context, req *channelv1.ControlRequest) (*channelv1.ControlResponse, error) {
	start := time.Now()
	id, ch, err := cc.Start(ctx, req)
	if err != nil {
		return nil, err
	}
	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, fmt.Errorf("%w: %w", ErrClosed, cc.Err())
		}
		if cc.onRTT != nil {
			cc.onRTT(time.Since(start))
		}
		return resp, nil
	case <-ctx.Done():
		cc.forget(id)
		return nil, fmt.Errorf("waiting for response: %w", ctx.Err())
	}
}

// forget abandons request id: its pending slot is freed now, and a late
// response is discarded. Too many unanswered requests fail the connection.
func (cc *ctrlConn) forget(id uint64) {
	cc.mu.Lock()
	if cc.pending == nil {
		cc.mu.Unlock()
		return
	}
	if _, ok := cc.pending[id]; !ok {
		cc.mu.Unlock()
		return
	}
	delete(cc.pending, id)
	cc.abandoned[id] = struct{}{}
	over := len(cc.abandoned) > maxAbandoned
	cc.mu.Unlock()
	if over {
		cc.fail(fmt.Errorf("guest left more than %d control requests unanswered", maxAbandoned))
	}
}

// outstanding returns the number of requests awaiting a response.
func (cc *ctrlConn) outstanding() int {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return len(cc.pending)
}
