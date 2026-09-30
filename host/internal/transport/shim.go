// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// ShimMonitorSock is the Kata shim management socket name
// (src/libs/shim-interface/src/lib.rs SHIM_MGMT_SOCK_NAME).
const ShimMonitorSock = "shim-monitor.sock"

// DefaultRunDirs are the per-sandbox state roots: runtime-rs first, then the
// Go runtime (docs/compat/kata-4.2.md §1).
var DefaultRunDirs = []string{"/run/kata", "/run/vc/sbs"}

// sandboxIDRe matches CRI sandbox IDs (64 hex chars in practice). It rejects
// anything that could change the socket path ("/", "..", NUL).
var sandboxIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// ValidSandboxID reports whether id is safe to use as a path component.
func ValidSandboxID(id string) bool {
	return sandboxIDRe.MatchString(id) && id != "." && id != ".."
}

// ShimClient queries Kata shim management sockets.
type ShimClient struct {
	// RunDirs are tried in order; the first with an existing socket wins.
	RunDirs []string
	// Timeout bounds one /agent-url request. Default 1s.
	Timeout time.Duration
}

// AgentEndpoint returns the guest endpoint of sandbox id. The ID comes from
// NRI and is validated before a path is built from it.
func (s ShimClient) AgentEndpoint(ctx context.Context, id string) (Endpoint, error) {
	if !ValidSandboxID(id) {
		return Endpoint{}, fmt.Errorf("invalid sandbox id %q", id)
	}
	dirs := s.RunDirs
	if len(dirs) == 0 {
		dirs = DefaultRunDirs
	}
	var sock string
	for _, d := range dirs {
		p := filepath.Join(d, id, ShimMonitorSock)
		fi, err := os.Lstat(p)
		if err == nil && fi.Mode().Type() == fs.ModeSocket {
			sock = p
			break
		}
	}
	if sock == "" {
		return Endpoint{}, fmt.Errorf("no shim management socket for sandbox %s: %w", id, ErrNotReady)
	}
	body, err := s.get(ctx, sock, "/agent-url")
	if err != nil {
		return Endpoint{}, err
	}
	return ParseAgentURL(body)
}

func (s ShimClient) get(ctx context.Context, sock, path string) (string, error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 16 << 10,
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://shim"+path, nil)
	if err != nil {
		return "", fmt.Errorf("build shim request: %w", err)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return "", fmt.Errorf("shim %s GET %s: %w", sock, path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAgentURL+1))
	if err != nil {
		return "", fmt.Errorf("shim %s GET %s: read body: %w", sock, path, err)
	}
	if resp.StatusCode != http.StatusOK {
		// The Go runtime answers 500 with the error text before the
		// agent is ready.
		return "", fmt.Errorf("shim %s GET %s: status %d: %w", sock, path, resp.StatusCode, ErrNotReady)
	}
	if len(body) > maxAgentURL {
		return "", errors.New("shim reply too large")
	}
	return string(body), nil
}
