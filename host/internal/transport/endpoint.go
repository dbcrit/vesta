// SPDX-License-Identifier: Apache-2.0

// Package transport discovers a Kata sandbox's guest endpoint and dials the
// vesta ports on it (ARCHITECTURE §2.2 "Sandbox registry", "Channel Dialer";
// docs/compat/kata-4.2.md §2).
package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
)

// Kind is the transport of a guest endpoint.
type Kind int

const (
	// KindVsock is vhost-vsock: host AF_VSOCK to the guest CID (QEMU).
	KindVsock Kind = iota + 1
	// KindHybridVsock is a per-sandbox UDS with a CONNECT handshake
	// (Cloud Hypervisor, Dragonball, Firecracker).
	KindHybridVsock
)

func (k Kind) String() string {
	switch k {
	case KindVsock:
		return "vsock"
	case KindHybridVsock:
		return "hvsock"
	default:
		return "unknown"
	}
}

// Endpoint is a parsed agent URL with the port dropped: vesta dials its own
// ports, not kata-agent's.
type Endpoint struct {
	Kind Kind
	CID  uint32 // KindVsock
	Path string // KindHybridVsock: absolute UDS path
}

func (e Endpoint) String() string {
	switch e.Kind {
	case KindVsock:
		return fmt.Sprintf("vsock://%d", e.CID)
	case KindHybridVsock:
		return "hvsock://" + e.Path
	default:
		return "invalid"
	}
}

// ErrNotReady means the shim has no agent endpoint yet.
var ErrNotReady = errors.New("agent endpoint not ready")

// maxAgentURL bounds the /agent-url reply.
const maxAgentURL = 4096

// ParseAgentURL parses the plain-text /agent-url body: "vsock://<cid>:<port>"
// or "hvsock://<abs-uds-path>:<port>". An empty body is ErrNotReady (runtime-rs
// returns 200 with an empty body before the agent is up). Other schemes, such
// as remote://, are unsupported.
func ParseAgentURL(body string) (Endpoint, error) {
	s := strings.TrimSpace(body)
	if s == "" {
		return Endpoint{}, ErrNotReady
	}
	if len(s) > maxAgentURL {
		return Endpoint{}, fmt.Errorf("agent url too long (%d bytes)", len(s))
	}
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok {
		return Endpoint{}, fmt.Errorf("agent url %q: missing scheme", s)
	}
	// Both forms end in ":<port>"; the port is kata-agent's and is ignored,
	// but it must be well-formed.
	i := strings.LastIndexByte(rest, ':')
	if i <= 0 {
		return Endpoint{}, fmt.Errorf("agent url %q: missing port", s)
	}
	addr, port := rest[:i], rest[i+1:]
	if _, err := strconv.ParseUint(port, 10, 32); err != nil {
		return Endpoint{}, fmt.Errorf("agent url %q: bad port", s)
	}
	switch scheme {
	case "vsock":
		cid, err := strconv.ParseUint(addr, 10, 32)
		if err != nil {
			return Endpoint{}, fmt.Errorf("agent url %q: bad cid", s)
		}
		// 0-2 are hypervisor/local/host; U32_MAX is VMADDR_CID_ANY.
		if cid <= 2 || cid == 0xFFFFFFFF {
			return Endpoint{}, fmt.Errorf("agent url %q: reserved cid %d", s, cid)
		}
		return Endpoint{Kind: KindVsock, CID: uint32(cid)}, nil
	case "hvsock":
		if !filepath.IsAbs(addr) || filepath.Clean(addr) != addr || strings.ContainsAny(addr, "\x00\n") {
			return Endpoint{}, fmt.Errorf("agent url %q: hybrid vsock path must be absolute and clean", s)
		}
		return Endpoint{Kind: KindHybridVsock, Path: addr}, nil
	default:
		return Endpoint{}, fmt.Errorf("agent url scheme %q is not supported", scheme)
	}
}

// Dialer opens a connection to a vesta port in one sandbox's guest.
type Dialer interface {
	Dial(ctx context.Context, port uint32) (net.Conn, error)
}

// DialerFor returns the Dialer for ep. A hybrid vsock socket must live under
// one of allowedRoots (the Kata run directories the agent mounts), so a
// misbehaving shim cannot point the agent at an arbitrary socket.
func DialerFor(ep Endpoint, allowedRoots []string) (Dialer, error) {
	switch ep.Kind {
	case KindVsock:
		return VsockDialer{CID: ep.CID}, nil
	case KindHybridVsock:
		for _, root := range allowedRoots {
			if root != "" && strings.HasPrefix(ep.Path, filepath.Clean(root)+"/") {
				return HybridDialer{Path: ep.Path}, nil
			}
		}
		return nil, fmt.Errorf("hybrid vsock socket %q is outside the allowed Kata run directories", ep.Path)
	default:
		return nil, fmt.Errorf("no dialer for endpoint %s", ep)
	}
}
