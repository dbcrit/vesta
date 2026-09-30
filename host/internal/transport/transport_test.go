// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAgentURL(t *testing.T) {
	tests := []struct {
		in      string
		want    Endpoint
		wantErr bool
		notRdy  bool
	}{
		{in: "vsock://3:1024", want: Endpoint{Kind: KindVsock, CID: 3}},
		{in: "vsock://4294967294:1024", want: Endpoint{Kind: KindVsock, CID: 4294967294}},
		{in: "hvsock:///run/vc/firecracker/abc/root/kata.hvsock:1024", want: Endpoint{Kind: KindHybridVsock, Path: "/run/vc/firecracker/abc/root/kata.hvsock"}},
		{in: " vsock://7:1024\n", want: Endpoint{Kind: KindVsock, CID: 7}},
		{in: "", notRdy: true},
		{in: "  ", notRdy: true},
		{in: "vsock://2:1024", wantErr: true},          // host CID
		{in: "vsock://4294967295:1024", wantErr: true}, // VMADDR_CID_ANY
		{in: "vsock://x:1024", wantErr: true},
		{in: "vsock://3", wantErr: true},
		{in: "vsock://3:port", wantErr: true},
		{in: "hvsock://relative/sock:1024", wantErr: true},
		{in: "hvsock:///run/../etc/sock:1024", wantErr: true},
		{in: "remote://foo:1024", wantErr: true},
		{in: "unix:///run/sock", wantErr: true},
		{in: "vsock://3:1024" + strings.Repeat("0", 5000), wantErr: true},
	}
	for _, tc := range tests {
		got, err := ParseAgentURL(tc.in)
		switch {
		case tc.notRdy:
			if !errors.Is(err, ErrNotReady) {
				t.Errorf("%q: err = %v, want ErrNotReady", tc.in, err)
			}
		case tc.wantErr:
			if err == nil {
				t.Errorf("%q: got %v, want error", tc.in, got)
			}
		default:
			if err != nil || got != tc.want {
				t.Errorf("%q: got %v, %v; want %v", tc.in, got, err, tc.want)
			}
		}
	}
}

func TestDialerForRestrictsHybridPaths(t *testing.T) {
	roots := []string{"/run/kata", "/run/vc"}
	if _, err := DialerFor(Endpoint{Kind: KindHybridVsock, Path: "/run/vc/firecracker/x/kata.hvsock"}, roots); err != nil {
		t.Fatal(err)
	}
	if _, err := DialerFor(Endpoint{Kind: KindHybridVsock, Path: "/var/run/docker.sock"}, roots); err == nil {
		t.Fatal("socket outside the Kata run dirs was accepted")
	}
	if _, err := DialerFor(Endpoint{Kind: KindHybridVsock, Path: "/run/katabad/x.sock"}, roots); err == nil {
		t.Fatal("prefix match without a separator was accepted")
	}
	if d, err := DialerFor(Endpoint{Kind: KindVsock, CID: 5}, roots); err != nil || d.(VsockDialer).CID != 5 {
		t.Fatal(d, err)
	}
}

// shortTempDir returns a directory short enough for UDS paths.
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "vt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// fakeHybrid is a hybrid vsock UDS server: it reads "CONNECT <port>\n" and
// answers with reply, then echoes.
func fakeHybrid(t *testing.T, reply string, stall bool) (string, <-chan string) {
	t.Helper()
	p := filepath.Join(shortTempDir(t), "h.sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan string, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				got <- line
				if stall {
					time.Sleep(5 * time.Second)
					return
				}
				_, _ = io.WriteString(c, reply)
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return p, got
}

func TestHybridDialer(t *testing.T) {
	tests := []struct {
		name    string
		reply   string
		stall   bool
		wantErr bool
	}{
		{name: "ok", reply: "OK 1073741824\n"},
		{name: "rejected", reply: "FAILURE\n", wantErr: true},
		{name: "ok without space", reply: "OK\n", wantErr: true},
		{name: "overlong line", reply: strings.Repeat("O", 100) + "\n", wantErr: true},
		{name: "closed without reply", reply: "", wantErr: true},
		{name: "stalled", stall: true, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, got := fakeHybrid(t, tc.reply, tc.stall)
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			c, err := HybridDialer{Path: p}.Dial(ctx, 22085)
			if line := <-got; line != "CONNECT 22085\n" {
				t.Errorf("handshake line %q", line)
			}
			if tc.wantErr {
				if err == nil {
					c.Close()
					t.Fatal("dial succeeded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			// The stream after the handshake is untouched.
			if _, err := c.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
				t.Fatalf("echo %q, %v", buf, err)
			}
		})
	}
}

func TestShimClientAgentEndpoint(t *testing.T) {
	root := shortTempDir(t)
	const sid = "0123456789abcdef"
	if err := os.MkdirAll(filepath.Join(root, sid), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "vsock://42:1024"
	status := http.StatusOK
	ln, err := net.Listen("unix", filepath.Join(root, sid, ShimMonitorSock))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agent-url" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })

	sc := ShimClient{RunDirs: []string{filepath.Join(root, "missing"), root}}
	ctx := context.Background()
	ep, err := sc.AgentEndpoint(ctx, sid)
	if err != nil || ep != (Endpoint{Kind: KindVsock, CID: 42}) {
		t.Fatalf("got %v, %v", ep, err)
	}

	body = ""
	if _, err := sc.AgentEndpoint(ctx, sid); !errors.Is(err, ErrNotReady) {
		t.Fatalf("empty body: %v", err)
	}
	body, status = "agent not ready", http.StatusInternalServerError
	if _, err := sc.AgentEndpoint(ctx, sid); !errors.Is(err, ErrNotReady) {
		t.Fatalf("500: %v", err)
	}
	if _, err := sc.AgentEndpoint(ctx, "unknownsandbox"); !errors.Is(err, ErrNotReady) {
		t.Fatalf("missing socket: %v", err)
	}
	for _, bad := range []string{"../etc", "a/b", "", ".", "..", strings.Repeat("a", 200), "x\x00y"} {
		if _, err := sc.AgentEndpoint(ctx, bad); err == nil || errors.Is(err, ErrNotReady) {
			t.Errorf("sandbox id %q: err = %v, want validation error", bad, err)
		}
	}
}
