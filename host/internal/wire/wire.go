// SPDX-License-Identifier: Apache-2.0

// Package wire implements the vesta channel framing (ARCHITECTURE §2.3.2):
// a big-endian uint32 length N, 1 <= N <= 1 MiB, followed by one protobuf
// message. The peer is untrusted, so reads never allocate more than the
// declared, bounds-checked length and every frame body must arrive within a
// deadline.
package wire

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dbcrit/vesta/api/channel"
)

// ErrFrameSize reports a length prefix outside [1, MaxFrameSize].
var ErrFrameSize = errors.New("frame length out of range")

// ErrNotSent reports that SendContext gave up before writing any byte of
// the frame, so the stream is still usable.
var ErrNotSent = errors.New("frame not sent")

// ReadFrame reads one frame from r and returns its payload. max bounds the
// payload length; values <= 0 or above channel.MaxFrameSize are clamped to
// channel.MaxFrameSize.
func ReadFrame(r io.Reader, max int) ([]byte, error) {
	if max <= 0 || max > channel.MaxFrameSize {
		max = channel.MaxFrameSize
	}
	var hdr [channel.FrameHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || uint64(n) > uint64(max) {
		return nil, fmt.Errorf("%w: %d", ErrFrameSize, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("read frame body: %w", err)
	}
	return buf, nil
}

// AppendFrame appends the frame for payload to dst.
func AppendFrame(dst, payload []byte) ([]byte, error) {
	if len(payload) == 0 || len(payload) > channel.MaxFrameSize {
		return nil, fmt.Errorf("%w: %d", ErrFrameSize, len(payload))
	}
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(payload))) //nolint:gosec // G115: len checked against MaxFrameSize (1 MiB) above
	return append(dst, payload...), nil
}

// Conn sends and receives framed protobuf messages over a net.Conn. Send is
// safe for concurrent use; Recv must be called from a single goroutine.
type Conn struct {
	nc           net.Conn
	frameTimeout time.Duration
	writeTimeout time.Duration
	maxFrame     int

	// wsem serializes writers; a channel so that waiting can be abandoned.
	wsem chan struct{}
}

// Options tunes a Conn. Zero values select the defaults.
type Options struct {
	// FrameTimeout bounds the time between the first header byte being
	// available and the full frame being read. Default 10s.
	FrameTimeout time.Duration
	// WriteTimeout bounds each frame write. Default 5s.
	WriteTimeout time.Duration
	// MaxFrame caps the accepted payload size. Default channel.MaxFrameSize.
	MaxFrame int
}

// NewConn wraps nc.
func NewConn(nc net.Conn, o Options) *Conn {
	if o.FrameTimeout <= 0 {
		o.FrameTimeout = 10 * time.Second
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = 5 * time.Second
	}
	if o.MaxFrame <= 0 || o.MaxFrame > channel.MaxFrameSize {
		o.MaxFrame = channel.MaxFrameSize
	}
	return &Conn{
		nc: nc, frameTimeout: o.FrameTimeout, writeTimeout: o.WriteTimeout, maxFrame: o.MaxFrame,
		wsem: make(chan struct{}, 1),
	}
}

// Send marshals m and writes it as one frame within the write timeout.
func (c *Conn) Send(m proto.Message) error {
	return c.SendContext(context.Background(), m)
}

// SendContext is Send, also bounded by ctx: waiting for a concurrent writer
// ends with ErrNotSent when ctx ends, and a write in progress is cut off at
// ctx's deadline or cancellation. A frame cut off part-way leaves the stream
// unusable, and the caller must close the connection.
func (c *Conn) SendContext(ctx context.Context, m proto.Message) error {
	payload, err := proto.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal %T: %w", m, err)
	}
	frame, err := AppendFrame(make([]byte, 0, channel.FrameHeaderSize+len(payload)), payload)
	if err != nil {
		return fmt.Errorf("encode %T: %w", m, err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrNotSent, err)
	}
	select {
	case c.wsem <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("%w: waiting for writer: %w", ErrNotSent, ctx.Err())
	}
	defer func() { <-c.wsem }()

	deadline := time.Now().Add(c.writeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := c.nc.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(fired)
		_ = c.nc.SetWriteDeadline(time.Unix(1, 0))
	})
	defer func() {
		// Never let a late cancellation clobber the next writer's deadline.
		if !stop() {
			<-fired
		}
	}()
	if _, err := c.nc.Write(frame); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

// Recv reads one frame into m. idle bounds the wait for the frame to start
// (zero means no bound); the frame body must then arrive within the frame
// timeout.
func (c *Conn) Recv(m proto.Message, idle time.Duration) error {
	var dl time.Time
	if idle > 0 {
		dl = time.Now().Add(idle)
	}
	if err := c.nc.SetReadDeadline(dl); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}
	r := &deadlineReader{c: c}
	payload, err := ReadFrame(r, c.maxFrame)
	if err != nil {
		return err
	}
	if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(payload, m); err != nil {
		return fmt.Errorf("decode %T: %w", m, err)
	}
	return nil
}

// Close closes the underlying connection.
func (c *Conn) Close() error {
	if err := c.nc.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	return nil
}

// deadlineReader switches the read deadline to the frame timeout once the
// first byte of a frame has arrived, so an idle wait can be long while a
// trickling peer cannot hold a partially read frame open.
type deadlineReader struct {
	c       *Conn
	started bool
}

func (r *deadlineReader) Read(p []byte) (int, error) {
	if !r.started {
		// Read a single byte first so the idle deadline covers only the
		// wait for the frame to begin.
		n, err := r.c.nc.Read(p[:1])
		if n == 0 {
			return n, err
		}
		r.started = true
		if derr := r.c.nc.SetReadDeadline(time.Now().Add(r.c.frameTimeout)); derr != nil {
			return n, fmt.Errorf("set frame deadline: %w", derr)
		}
		return n, err
	}
	return r.c.nc.Read(p)
}
