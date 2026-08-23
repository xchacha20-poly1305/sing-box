//go:build with_ebpf && !ebpf_debug && (linux || android)

package ebpf

import (
	"net/netip"
	"time"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/log"
)

const ebpfRuntimeStatusInterval = 10 * time.Minute

type eBPFDebugState struct{}

type eBPFDebugSnapshot struct{}

type eBPFDebugUDPWriterState struct{}

func (d *eBPFDebugState) observe(task string, duration time.Duration, err error) {}

func (d *eBPFDebugState) bypassPolicyOperationStarted() time.Time { return time.Time{} }

func (d *eBPFDebugState) observeBypassPolicyCompile(
	started time.Time,
	rawPrefixes int,
	policy ECommon.BypassCIDRPolicy,
	err error,
) {
}

func (d *eBPFDebugState) observeBypassPolicyUpdate(started time.Time, err error) {}

func (d *eBPFDebugState) snapshot() *eBPFDebugSnapshot { return nil }

func (d *eBPFDebugState) observeUDPBindingFailure(
	writer *eBPFDebugUDPWriterState,
	shared bool,
	lateReply bool,
	logger log.ContextLogger,
	client netip.AddrPort,
	destination netip.AddrPort,
	state *udpClientState,
) {
}

func ebpfRuntimeStatusReporterEnabled(logger log.ContextLogger) bool {
	return ebpfDebugLoggingEnabled(logger)
}

func logEBPFDebugBuild(logger log.ContextLogger) {}

func (i *Inbound) enableProgramRuntimeStats() {}

func (i *Inbound) disableProgramRuntimeStats() error { return nil }
