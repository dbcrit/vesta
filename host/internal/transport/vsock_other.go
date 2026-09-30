// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package transport

import (
	"context"
	"errors"
	"net"
)

// VsockDialer dials the guest over host AF_VSOCK. AF_VSOCK is Linux-only;
// on other systems Dial always fails.
type VsockDialer struct {
	CID uint32
}

// Dial implements Dialer.
func (d VsockDialer) Dial(context.Context, uint32) (net.Conn, error) {
	return nil, errors.New("vsock is only supported on linux")
}
