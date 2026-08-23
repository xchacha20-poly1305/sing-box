//go:build with_ebpf && ebpf_debug && (linux || android)

package ebpf

import (
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/log"
)

const ebpfRuntimeStatusInterval time.Duration = 0

type eBPFDebugState struct {
	localTCPRedirectSweep     eBPFDebugTaskMetric
	sharedFlowPressurePoll    eBPFDebugTaskMetric
	sharedFlowSweep           eBPFDebugTaskMetric
	sharedFlowReleaseFlush    eBPFDebugTaskMetric
	sharedAttachmentReconcile eBPFDebugTaskMetric
	ipv6RouteProbe            eBPFDebugTaskMetric
	runtimeStatusCollection   eBPFDebugTaskMetric
	bypassPolicyCompile       eBPFDebugTaskMetric
	bypassPolicyUpdate        eBPFDebugTaskMetric
	bypassPolicyRawPrefixes   atomic.Uint64
	bypassPolicyIPv4Prefixes  atomic.Uint64
	bypassPolicyIPv6Prefixes  atomic.Uint64
	localUDPBindingMiss       eBPFDebugUDPBindingMissMetric
	sharedUDPBindingMiss      eBPFDebugUDPBindingMissMetric
	localUDPLateReply         eBPFDebugUDPBindingMissMetric
	sharedUDPLateReply        eBPFDebugUDPBindingMissMetric
}

type eBPFDebugUDPWriterState struct {
	missed atomic.Bool
}

type eBPFDebugUDPBindingMissMetric struct {
	connectedPackets    atomic.Uint64
	unconnectedPackets  atomic.Uint64
	connectedSessions   atomic.Uint64
	unconnectedSessions atomic.Uint64
	warnings            warningLimiter
}

type eBPFDebugUDPBindingMissPathSnapshot struct {
	ConnectedPackets    uint64 `json:"connected_packets"`
	UnconnectedPackets  uint64 `json:"unconnected_packets"`
	ConnectedSessions   uint64 `json:"connected_sessions"`
	UnconnectedSessions uint64 `json:"unconnected_sessions"`
}

type eBPFDebugUDPBindingMissSnapshot struct {
	Local  eBPFDebugUDPBindingMissPathSnapshot `json:"local"`
	Shared eBPFDebugUDPBindingMissPathSnapshot `json:"shared"`
}

type eBPFDebugTaskMetric struct {
	runs               atomic.Uint64
	errors             atomic.Uint64
	totalDurationNanos atomic.Uint64
	maxDurationNanos   atomic.Uint64
	lastDurationNanos  atomic.Uint64
}

type eBPFDebugTaskSnapshot struct {
	Runs               uint64 `json:"runs"`
	Errors             uint64 `json:"errors"`
	TotalDurationNanos uint64 `json:"total_duration_ns"`
	MaxDurationNanos   uint64 `json:"max_duration_ns"`
	LastDurationNanos  uint64 `json:"last_duration_ns"`
}

type eBPFDebugGoRuntimeSnapshot struct {
	Goroutines        int    `json:"goroutines"`
	HeapAllocBytes    uint64 `json:"heap_alloc_bytes"`
	HeapInuseBytes    uint64 `json:"heap_inuse_bytes"`
	HeapObjects       uint64 `json:"heap_objects"`
	StackInuseBytes   uint64 `json:"stack_inuse_bytes"`
	SysBytes          uint64 `json:"sys_bytes"`
	RSSBytes          uint64 `json:"rss_bytes,omitempty"`
	RSSKnown          bool   `json:"rss_known"`
	GCCount           uint32 `json:"gc_count"`
	GCPauseTotalNanos uint64 `json:"gc_pause_total_ns"`
}

type eBPFDebugSnapshot struct {
	Build          bool                             `json:"build"`
	GoRuntime      eBPFDebugGoRuntimeSnapshot       `json:"go_runtime"`
	Maintenance    map[string]eBPFDebugTaskSnapshot `json:"maintenance"`
	BypassPolicy   eBPFDebugBypassPolicySnapshot    `json:"bypass_policy"`
	UDPBindingMiss eBPFDebugUDPBindingMissSnapshot  `json:"udp_binding_miss"`
	UDPLateReply   eBPFDebugUDPBindingMissSnapshot  `json:"udp_late_reply"`
}

type eBPFDebugBypassPolicySnapshot struct {
	RawPrefixes  uint64                `json:"raw_prefixes"`
	IPv4Prefixes uint64                `json:"ipv4_prefixes"`
	IPv6Prefixes uint64                `json:"ipv6_prefixes"`
	Compile      eBPFDebugTaskSnapshot `json:"compile"`
	Update       eBPFDebugTaskSnapshot `json:"update"`
}

func (d *eBPFDebugState) bypassPolicyOperationStarted() time.Time {
	return time.Now()
}

func (d *eBPFDebugState) observeBypassPolicyCompile(
	started time.Time,
	rawPrefixes int,
	policy ECommon.BypassCIDRPolicy,
	err error,
) {
	ipv4Prefixes, ipv6Prefixes := policy.Count()
	d.bypassPolicyRawPrefixes.Store(uint64(rawPrefixes))
	d.bypassPolicyIPv4Prefixes.Store(uint64(ipv4Prefixes))
	d.bypassPolicyIPv6Prefixes.Store(uint64(ipv6Prefixes))
	d.observeTask(&d.bypassPolicyCompile, time.Since(started), err)
}

func (d *eBPFDebugState) observeBypassPolicyUpdate(started time.Time, err error) {
	d.observeTask(&d.bypassPolicyUpdate, time.Since(started), err)
}

func (d *eBPFDebugState) observe(task string, duration time.Duration, err error) {
	metric := d.metric(task)
	if metric == nil {
		return
	}
	d.observeTask(metric, duration, err)
}

func (d *eBPFDebugState) observeTask(metric *eBPFDebugTaskMetric, duration time.Duration, err error) {
	durationNanos := uint64(max(duration.Nanoseconds(), 0))
	metric.runs.Add(1)
	if err != nil {
		metric.errors.Add(1)
	}
	metric.totalDurationNanos.Add(durationNanos)
	metric.lastDurationNanos.Store(durationNanos)
	for previous := metric.maxDurationNanos.Load(); durationNanos > previous; previous = metric.maxDurationNanos.Load() {
		if metric.maxDurationNanos.CompareAndSwap(previous, durationNanos) {
			break
		}
	}
}

func (d *eBPFDebugState) metric(task string) *eBPFDebugTaskMetric {
	switch task {
	case ebpfDebugTaskLocalTCPRedirectSweep:
		return &d.localTCPRedirectSweep
	case ebpfDebugTaskSharedFlowPressurePoll:
		return &d.sharedFlowPressurePoll
	case ebpfDebugTaskSharedFlowSweep:
		return &d.sharedFlowSweep
	case ebpfDebugTaskSharedFlowReleaseFlush:
		return &d.sharedFlowReleaseFlush
	case ebpfDebugTaskSharedAttachmentReconcile:
		return &d.sharedAttachmentReconcile
	case ebpfDebugTaskIPv6RouteProbe:
		return &d.ipv6RouteProbe
	case ebpfDebugTaskRuntimeStatusCollection:
		return &d.runtimeStatusCollection
	default:
		return nil
	}
}

func (m *eBPFDebugTaskMetric) snapshot() eBPFDebugTaskSnapshot {
	return eBPFDebugTaskSnapshot{
		Runs:               m.runs.Load(),
		Errors:             m.errors.Load(),
		TotalDurationNanos: m.totalDurationNanos.Load(),
		MaxDurationNanos:   m.maxDurationNanos.Load(),
		LastDurationNanos:  m.lastDurationNanos.Load(),
	}
}

func (m *eBPFDebugUDPBindingMissMetric) observe(writer *eBPFDebugUDPWriterState, connected bool) bool {
	if connected {
		m.connectedPackets.Add(1)
	} else {
		m.unconnectedPackets.Add(1)
	}
	if !writer.missed.CompareAndSwap(false, true) {
		return false
	}
	if connected {
		m.connectedSessions.Add(1)
	} else {
		m.unconnectedSessions.Add(1)
	}
	return true
}

func (m *eBPFDebugUDPBindingMissMetric) snapshot() eBPFDebugUDPBindingMissPathSnapshot {
	return eBPFDebugUDPBindingMissPathSnapshot{
		ConnectedPackets:    m.connectedPackets.Load(),
		UnconnectedPackets:  m.unconnectedPackets.Load(),
		ConnectedSessions:   m.connectedSessions.Load(),
		UnconnectedSessions: m.unconnectedSessions.Load(),
	}
}

func (d *eBPFDebugState) observeUDPBindingFailure(
	writer *eBPFDebugUDPWriterState,
	shared bool,
	lateReply bool,
	logger log.ContextLogger,
	client netip.AddrPort,
	destination netip.AddrPort,
	state *udpClientState,
) {
	metric := &d.localUDPBindingMiss
	path := "local"
	if shared {
		metric = &d.sharedUDPBindingMiss
		path = "shared"
	}
	kind := "binding miss"
	if lateReply {
		metric = &d.localUDPLateReply
		if shared {
			metric = &d.sharedUDPLateReply
		}
		kind = "late reply"
	}
	state.access.RLock()
	connected := state.connected
	connectedDestination := state.connectedDestination
	bindingCount := len(state.bindings)
	originalCount := len(state.originals)
	state.access.RUnlock()
	if !metric.observe(writer, connected) || logger == nil {
		return
	}
	allowed, suppressed := metric.warnings.allow(time.Now())
	if !allowed {
		return
	}
	args := []any{
		"eBPF debug UDP ", kind, ": path=", path,
		" client=", client,
		" requested_destination=", destination,
		" connected=", connected,
		" connected_destination=", connectedDestination,
		" bindings=", bindingCount,
		" originals=", originalCount,
		" state_current=", !lateReply,
	}
	if suppressed > 0 {
		args = append(args, " (", suppressed, " unique sessions suppressed)")
	}
	logger.Debug(args...)
}

func (d *eBPFDebugState) snapshot() *eBPFDebugSnapshot {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	rssBytes, rssKnown := readProcessRSS()
	return &eBPFDebugSnapshot{
		Build: true,
		GoRuntime: eBPFDebugGoRuntimeSnapshot{
			Goroutines:        runtime.NumGoroutine(),
			HeapAllocBytes:    memory.HeapAlloc,
			HeapInuseBytes:    memory.HeapInuse,
			HeapObjects:       memory.HeapObjects,
			StackInuseBytes:   memory.StackInuse,
			SysBytes:          memory.Sys,
			RSSBytes:          rssBytes,
			RSSKnown:          rssKnown,
			GCCount:           memory.NumGC,
			GCPauseTotalNanos: memory.PauseTotalNs,
		},
		Maintenance: map[string]eBPFDebugTaskSnapshot{
			ebpfDebugTaskLocalTCPRedirectSweep:     d.localTCPRedirectSweep.snapshot(),
			ebpfDebugTaskSharedFlowPressurePoll:    d.sharedFlowPressurePoll.snapshot(),
			ebpfDebugTaskSharedFlowSweep:           d.sharedFlowSweep.snapshot(),
			ebpfDebugTaskSharedFlowReleaseFlush:    d.sharedFlowReleaseFlush.snapshot(),
			ebpfDebugTaskSharedAttachmentReconcile: d.sharedAttachmentReconcile.snapshot(),
			ebpfDebugTaskIPv6RouteProbe:            d.ipv6RouteProbe.snapshot(),
			ebpfDebugTaskRuntimeStatusCollection:   d.runtimeStatusCollection.snapshot(),
		},
		BypassPolicy: eBPFDebugBypassPolicySnapshot{
			RawPrefixes:  d.bypassPolicyRawPrefixes.Load(),
			IPv4Prefixes: d.bypassPolicyIPv4Prefixes.Load(),
			IPv6Prefixes: d.bypassPolicyIPv6Prefixes.Load(),
			Compile:      d.bypassPolicyCompile.snapshot(),
			Update:       d.bypassPolicyUpdate.snapshot(),
		},
		UDPBindingMiss: eBPFDebugUDPBindingMissSnapshot{
			Local:  d.localUDPBindingMiss.snapshot(),
			Shared: d.sharedUDPBindingMiss.snapshot(),
		},
		UDPLateReply: eBPFDebugUDPBindingMissSnapshot{
			Local:  d.localUDPLateReply.snapshot(),
			Shared: d.sharedUDPLateReply.snapshot(),
		},
	}
}

func readProcessRSS() (uint64, bool) {
	contents, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(contents))
	if len(fields) < 2 {
		return 0, false
	}
	residentPages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return residentPages * uint64(os.Getpagesize()), true
}

func ebpfRuntimeStatusReporterEnabled(logger log.ContextLogger) bool {
	return ebpfDebugLoggingEnabled(logger)
}

func logEBPFDebugBuild(logger log.ContextLogger) {
	logger.Info(
		"eBPF debug instrumentation enabled: runtime_status=event_driven",
	)
}

func (i *Inbound) enableProgramRuntimeStats() {
	if i.programStatsRelease != nil {
		return
	}
	release, err := ECommon.AcquireProgramRuntimeStats()
	if err != nil {
		i.logger.Warn("enable eBPF program runtime statistics: ", err)
		return
	}
	i.programStatsRelease = release
	if release != nil {
		i.logger.Debug("eBPF program runtime statistics enabled")
	}
}

func (i *Inbound) disableProgramRuntimeStats() error {
	release := i.programStatsRelease
	i.programStatsRelease = nil
	if release == nil {
		return nil
	}
	return release()
}
