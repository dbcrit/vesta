// SPDX-License-Identifier: Apache-2.0

// Package channel holds the wire constants of the vesta host <-> guest
// channel (ARCHITECTURE §2.3). Messages live in api/gen/go/vesta/channel/v1.
// vesta-guestd mirrors these values; keep both in sync.
package channel

const (
	// ProtoMajor and ProtoMinor are the protocol version defined by
	// api/proto/vesta/channel/v1.
	ProtoMajor = 1
	ProtoMinor = 0

	// FrameHeaderSize is the size of the big-endian uint32 length prefix.
	FrameHeaderSize = 4
	// MaxFrameSize is the largest accepted frame payload in bytes (1 MiB).
	MaxFrameSize = 1 << 20

	// DefaultCtrlPort and DefaultEvtPort are the guest vsock ports
	// vesta-guestd listens on (docs/compat/kata-4.2.md §3).
	DefaultCtrlPort = 22085
	DefaultEvtPort  = 22086

	// ABIVersion is VESTA_ABI_VERSION in bpf/include/vesta_abi.h.
	ABIVersion = 1
)
