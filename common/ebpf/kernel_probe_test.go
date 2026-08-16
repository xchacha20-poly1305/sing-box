//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestClassifyKernelProbeError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status KernelProbeStatus
	}{
		{"supported", nil, KernelProbePass},
		{"unsupported", CiliumEBPF.ErrNotSupported, KernelProbeFail},
		{"wrapped unsupported", errors.Join(errors.New("probe"), CiliumEBPF.ErrNotSupported), KernelProbeFail},
		{"permission denied", unix.EPERM, KernelProbeUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if status := classifyKernelProbeError(test.err); status != test.status {
				t.Fatalf("unexpected status: got %s, want %s", status, test.status)
			}
		})
	}
}

func TestKernelProbeReportCounts(t *testing.T) {
	report := &KernelProbeReport{}
	report.Add(KernelProbePass, "common", KernelProbeRequired, "one", "")
	report.Add(KernelProbeFail, "local", KernelProbeRequired, "two", "")
	report.Add(KernelProbeFail, "local", KernelProbeFallback, "three", "")
	report.Add(KernelProbeUnknown, "shared-network", KernelProbeRequired, "four", "")
	if failures := report.RequiredFailures(); failures != 1 {
		t.Fatalf("unexpected required failure count: %d", failures)
	}
	counts := report.Counts()
	if counts[KernelProbePass] != 1 || counts[KernelProbeFail] != 2 || counts[KernelProbeUnknown] != 1 {
		t.Fatalf("unexpected counts: %v", counts)
	}
}

func TestWriteKernelProbeReport(t *testing.T) {
	report := &KernelProbeReport{
		Platform:      "Linux",
		KernelRelease: "4.19.0-test",
		Architecture:  "arm64",
		Mode:          KernelProbeModeLocal,
	}
	report.Add(KernelProbePass, "common", KernelProbeRequired, "hash map", "available")
	report.Add(KernelProbeUnknown, "local", KernelProbeRequired, "cgroup", "permission required")
	var output bytes.Buffer
	if err := WriteKernelProbeReport(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"kernel: 4.19.0-test",
		"cilium/ebpf direct bpf(2) probes",
		"PASS",
		"UNKNOWN",
		"Summary: PASS=1 WARN=0 FAIL=0 UNKNOWN=1",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("report is missing %q:\n%s", expected, output.String())
		}
	}
}

func TestPathWithin(t *testing.T) {
	for _, test := range []struct {
		path string
		root string
		want bool
	}{
		{"/sys/fs/cgroup", "/sys/fs/cgroup", true},
		{"/sys/fs/cgroup/sing-box", "/sys/fs/cgroup", true},
		{"/sys/fs/cgroup2", "/sys/fs/cgroup", false},
		{"/sys/fs", "/sys/fs/cgroup", false},
	} {
		if got := pathWithin(test.path, test.root); got != test.want {
			t.Fatalf("pathWithin(%q, %q)=%v, want %v", test.path, test.root, got, test.want)
		}
	}
}

func TestKernelVersionCode(t *testing.T) {
	version := kernelVersionCode(5, 2, 300)
	if formatted := formatKernelVersionCode(version); formatted != "5.2.255" {
		t.Fatalf("unexpected formatted version: %s", formatted)
	}
}

func TestParseKernelProbeNetwork(t *testing.T) {
	tcp, udp, network, err := parseKernelProbeNetwork([]string{"udp", "tcp", "udp"})
	if err != nil {
		t.Fatal(err)
	}
	if !tcp || !udp || strings.Join(network, ",") != "tcp,udp" {
		t.Fatalf("unexpected network result: tcp=%v udp=%v network=%v", tcp, udp, network)
	}
	if _, _, _, err = parseKernelProbeNetwork([]string{"icmp"}); err == nil {
		t.Fatal("expected invalid network error")
	}
}
