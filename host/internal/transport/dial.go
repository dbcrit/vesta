// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// handshakeTimeout bounds the hybrid vsock CONNECT exchange when the context
// has no earlier deadline.
const handshakeTimeout = 3 * time.Second

// maxHandshakeLine bounds the hybrid vsock reply ("OK <port>\n").
const maxHandshakeLine = 32

// HybridDialer dials through a hybrid vsock UDS: write "CONNECT <port>\n",
// then require a reply line starting with "OK " (Firecracker vsock.md; Kata
// Go runtime client.go).
type HybridDialer struct {
	Path string
}

// Dial implements Dialer.
func (d HybridDialer) Dial(ctx context.Context, port uint32) (net.Conn, error) {
	var nd net.Dialer
	c, err := nd.DialContext(ctx, "unix", d.Path)
	if err != nil {
		return nil, fmt.Errorf("dial hybrid vsock %s: %w", d.Path, err)
	}
	if err := hybridHandshake(ctx, c, port); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("hybrid vsock %s port %d: %w", d.Path, port, err)
	}
	return c, nil
}

func hybridHandshake(ctx context.Context, c net.Conn, port uint32) error {
	dl := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	if err := c.SetDeadline(dl); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	// Abort a blocked read or write promptly when ctx is cancelled.
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if _, err := fmt.Fprintf(c, "CONNECT %d\n", port); err != nil {
		return fmt.Errorf("write CONNECT: %w", err)
	}
	line, err := readLine(c, maxHandshakeLine)
	if err != nil {
		return fmt.Errorf("read CONNECT reply: %w", err)
	}
	if !strings.HasPrefix(line, "OK ") {
		return fmt.Errorf("CONNECT rejected: %q", line)
	}
	if !stop() {
		return ctx.Err()
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear deadline: %w", err)
	}
	return nil
}

// readLine reads one '\n'-terminated line of at most max bytes one byte at a
// time, so nothing after the newline (the start of the vesta stream) is
// consumed.
func readLine(r io.Reader, max int) (string, error) {
	var b strings.Builder
	var one [1]byte
	for b.Len() < max {
		if _, err := io.ReadFull(r, one[:]); err != nil {
			return "", err
		}
		if one[0] == '\n' {
			return b.String(), nil
		}
		b.WriteByte(one[0])
	}
	return "", errors.New("reply line too long")
}
