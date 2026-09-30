// SPDX-License-Identifier: Apache-2.0

package agentconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaultsAndEnv(t *testing.T) {
	cfg, err := Load(nil, env(map[string]string{"NODE_NAME": "n1"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NodeName != "n1" || cfg.PluginIndex != "90" || cfg.Handlers[0] != "kata-qemu-vesta" ||
		cfg.CtrlPort != 22085 || cfg.EvtPort != 22086 || cfg.GateTimeout.Duration != 1500*time.Millisecond {
		t.Fatalf("%+v", cfg)
	}
	if _, err := Load(nil, env(nil)); err == nil || !strings.Contains(err.Error(), "node name") {
		t.Fatalf("missing node name: %v", err)
	}
}

func TestFileThenFlags(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(p, []byte("nodeName: file-node\nhandlers: [a, b]\ngateTimeout: 900ms\nlogLevel: debug\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load([]string{"-config", p, "-log-level", "warn", "-handlers", "c,d"}, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NodeName != "file-node" || cfg.LogLevel != "warn" || strings.Join(cfg.Handlers, ",") != "c,d" || cfg.GateTimeout.Duration != 900*time.Millisecond {
		t.Fatalf("%+v", cfg)
	}
}

func TestValidation(t *testing.T) {
	bad := [][]string{
		{"-gate-timeout", "2s"},
		{"-gate-timeout", "0s"},
		{"-plugin-index", "9"},
		{"-plugin-index", "ab"},
		{"-ctrl-port", "22086"},
		{"-default-failure-policy", "Maybe"},
		{"-global-mode", "Off"},
		{"-kata-run-dirs", "run/kata"},
		{"-handlers", ""},
		{"-heartbeat-grace", "0.5"},
		{"-event-rate", "0"},
		{"-log-level", "trace"},
		{"-unknown-flag"},
	}
	for _, args := range bad {
		if _, err := Load(append([]string{"-node-name", "n"}, args...), env(nil)); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	p := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(p, []byte("nodeName: n\nbogus: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load([]string{"-config", p}, env(nil)); err == nil {
		t.Error("unknown file field accepted")
	}
	if u := Usage(); !strings.Contains(u, "-gate-timeout") {
		t.Error("usage missing flags")
	}
}
