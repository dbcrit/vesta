// SPDX-License-Identifier: Apache-2.0

package channel

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// The C header is the source of truth for the ABI version.
func TestABIVersionMatchesHeader(t *testing.T) {
	b, err := os.ReadFile("../../bpf/include/vesta_abi.h")
	if err != nil {
		t.Fatalf("read vesta_abi.h: %v", err)
	}
	m := regexp.MustCompile(`(?m)^#define VESTA_ABI_VERSION (\d+)$`).FindSubmatch(b)
	if m == nil {
		t.Fatal("VESTA_ABI_VERSION not found in vesta_abi.h")
	}
	v, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatalf("parse VESTA_ABI_VERSION: %v", err)
	}
	if v != ABIVersion {
		t.Fatalf("ABIVersion = %d, vesta_abi.h has %d", ABIVersion, v)
	}
}

func TestPortsDoNotCollideWithKata(t *testing.T) {
	// kata-agent 1024, log 1025, debug console 1026, passfd 1027.
	for _, p := range []int{DefaultCtrlPort, DefaultEvtPort} {
		if p >= 1024 && p <= 1027 {
			t.Fatalf("port %d collides with a Kata vsock port", p)
		}
	}
	if DefaultCtrlPort == DefaultEvtPort {
		t.Fatal("CTRL and EVT ports must differ")
	}
}
