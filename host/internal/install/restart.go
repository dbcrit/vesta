// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	sddbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
)

// ErrRestartRequired is returned by NoRestart: the containerd config
// changed but nothing may restart containerd.
var ErrRestartRequired = errors.New("containerd config changed and must be restarted by the operator")

// Restarter restarts the unit that runs containerd.
type Restarter interface {
	// Restart restarts the first active unit among candidates and returns
	// its name.
	Restart(ctx context.Context, candidates []string) (string, error)
}

// NoRestart never restarts anything.
type NoRestart struct{}

// Restart implements Restarter.
func (NoRestart) Restart(context.Context, []string) (string, error) {
	return "", ErrRestartRequired
}

// SystemdRestarter talks D-Bus to the host systemd over its private socket
// (/run/systemd/private), the same mechanism kata-deploy uses. It needs
// uid 0 and that socket mounted; no host PID namespace, nsenter or Linux
// capabilities.
type SystemdRestarter struct {
	// Socket is the path of systemd's private socket as seen by this
	// process, e.g. /host/run/systemd/private.
	Socket string
	// Timeout bounds the restart job. Default 3 minutes.
	Timeout time.Duration
}

func (s SystemdRestarter) connect(ctx context.Context) (*sddbus.Conn, error) {
	conn, err := sddbus.NewConnection(func() (*dbus.Conn, error) {
		c, err := dbus.Dial("unix:path="+s.Socket, dbus.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("dial: %w", err)
		}
		// The private socket speaks peer-to-peer D-Bus: EXTERNAL auth, no
		// Hello.
		if err := c.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Getuid()))}); err != nil {
			c.Close()
			return nil, fmt.Errorf("auth: %w", err)
		}
		return c, nil
	})
	if err != nil {
		return nil, fmt.Errorf("systemd D-Bus: %w", err)
	}
	return conn, nil
}

// Restart implements Restarter.
func (s SystemdRestarter) Restart(ctx context.Context, candidates []string) (string, error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := s.connect(ctx)
	if err != nil {
		return "", fmt.Errorf("connect to systemd at %s: %w", s.Socket, err)
	}
	defer conn.Close()

	unit := ""
	for _, c := range candidates {
		p, err := conn.GetUnitPropertyContext(ctx, c, "ActiveState")
		if err != nil {
			continue
		}
		if st, ok := p.Value.Value().(string); ok && st == "active" {
			unit = c
			break
		}
	}
	if unit == "" {
		return "", fmt.Errorf("none of %v is active", candidates)
	}
	done := make(chan string, 1)
	if _, err := conn.RestartUnitContext(ctx, unit, "replace", done); err != nil {
		return unit, fmt.Errorf("restart %s: %w", unit, err)
	}
	select {
	case res := <-done:
		if res != "done" {
			return unit, fmt.Errorf("restart %s: job %s", unit, res)
		}
	case <-ctx.Done():
		return unit, fmt.Errorf("restart %s: %w", unit, ctx.Err())
	}
	// A finished job means the unit started, not that it stayed up.
	for {
		p, err := conn.GetUnitPropertyContext(ctx, unit, "ActiveState")
		if err != nil {
			return unit, fmt.Errorf("query %s: %w", unit, err)
		}
		switch st, _ := p.Value.Value().(string); st {
		case "active":
			return unit, nil
		case "failed", "inactive":
			return unit, fmt.Errorf("%s is %s after restart", unit, st)
		}
		select {
		case <-ctx.Done():
			return unit, fmt.Errorf("waiting for %s: %w", unit, ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}
