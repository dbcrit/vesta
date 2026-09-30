// SPDX-License-Identifier: Apache-2.0

//go:build linux

package transport

import (
	"context"
	"fmt"
	"net"

	"github.com/mdlayher/vsock"
)

// VsockDialer dials the guest over host AF_VSOCK (vhost-vsock).
type VsockDialer struct {
	CID uint32
}

// Dial implements Dialer. vsock.Dial has no context variant, so the dial
// runs in a goroutine; if ctx ends first, a late connection is closed by
// that goroutine and nothing leaks. The kernel bounds the connect itself
// (SO_VM_SOCKETS_CONNECT_TIMEOUT, 2 s by default).
func (d VsockDialer) Dial(ctx context.Context, port uint32) (net.Conn, error) {
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := vsock.Dial(d.CID, port, nil)
		if err != nil {
			ch <- result{err: err}
			return
		}
		ch <- result{c: c}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("dial vsock %d:%d: %w", d.CID, port, r.err)
		}
		return r.c, nil
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.c != nil {
				_ = r.c.Close()
			}
		}()
		return nil, fmt.Errorf("dial vsock %d:%d: %w", d.CID, port, ctx.Err())
	}
}
