//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"encoding/json"
	"time"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/log"
)

const (
	ebpfDebugTaskLocalTCPRedirectSweep     = "local_tcp_redirect_sweep"
	ebpfDebugTaskSharedFlowPressurePoll    = "shared_flow_pressure_poll"
	ebpfDebugTaskSharedFlowSweep           = "shared_flow_sweep"
	ebpfDebugTaskSharedFlowReleaseFlush    = "shared_flow_release_flush"
	ebpfDebugTaskSharedAttachmentReconcile = "shared_attachment_reconcile"
	ebpfDebugTaskIPv6RouteProbe            = "ipv6_route_probe"
	ebpfDebugTaskRuntimeStatusCollection   = "runtime_status_collection"
	ebpfRuntimeStatusEventMinInterval      = 30 * time.Second
)

type ebpfLocalRuntimeStatus struct {
	Backend ECommon.CgroupRuntimeStatus `json:"backend"`
}

type ebpfSharedRuntimeStatus struct {
	Backend    ECommon.SharedNetworkRuntimeStatus `json:"backend"`
	Attachment sharedTCRuntimeStatus              `json:"attachment"`
}

type ebpfRuntimeStatus struct {
	Timestamp   string                    `json:"timestamp"`
	Phase       string                    `json:"phase"`
	Mode        string                    `json:"mode"`
	Local       *ebpfLocalRuntimeStatus   `json:"local,omitempty"`
	Shared      *ebpfSharedRuntimeStatus  `json:"shared,omitempty"`
	TCPSplice   *ECommon.SpliceStatistics `json:"tcp_splice,omitempty"`
	Diagnostics eBPFDiagnosticSnapshot    `json:"diagnostics"`
	Debug       *eBPFDebugSnapshot        `json:"debug,omitempty"`
}

func ebpfDebugLoggingEnabled(logger log.ContextLogger) bool {
	levelProvider, levelAvailable := logger.(interface{ Level() log.Level })
	return !levelAvailable || levelProvider.Level() >= log.LevelDebug
}

func (i *Inbound) runtimeStatus(phase string) ebpfRuntimeStatus {
	status := ebpfRuntimeStatus{
		Timestamp:   time.Now().Format(time.RFC3339),
		Phase:       phase,
		Diagnostics: i.diagnostics.snapshot(),
		Debug:       i.debug.snapshot(),
	}
	switch {
	case i.cgroupEnabled && i.sharedNetworkEnabled:
		status.Mode = ebpfModeHybrid
	case i.cgroupEnabled:
		status.Mode = ebpfModeLocal
	case i.sharedNetworkEnabled:
		status.Mode = ebpfModeShared
	}
	if backend := i.cgroupBackendInstance(); backend != nil {
		status.Local = &ebpfLocalRuntimeStatus{Backend: backend.RuntimeStatus()}
	}
	if shared := i.sharedNetwork; shared != nil {
		sharedStatus := &ebpfSharedRuntimeStatus{}
		if shared.tcManager != nil {
			sharedStatus.Attachment = shared.tcManager.runtimeStatus()
		}
		if backend := shared.sharedBackendInstance(); backend != nil {
			sharedStatus.Backend = backend.RuntimeStatus()
		}
		for programIndex := range sharedStatus.Backend.Programs {
			program := &sharedStatus.Backend.Programs[programIndex]
			for _, attachment := range sharedStatus.Attachment.Attachments {
				if !attachment.Healthy {
					continue
				}
				if uint32(attachment.IngressProgramID) == program.ID ||
					uint32(attachment.EgressProgramID) == program.ID {
					program.Attached = true
					break
				}
			}
		}
		status.Shared = sharedStatus
	}
	if i.tcpSpliceBackend != nil {
		spliceStatus := i.tcpSpliceBackend.Statistics()
		status.TCPSplice = &spliceStatus
	}
	return status
}

func (i *Inbound) logRuntimeStatus(phase string) {
	if !ebpfDebugLoggingEnabled(i.logger) {
		return
	}
	started := time.Now()
	status := i.runtimeStatus(phase)
	i.warnRuntimeStatus(status)
	encoded, err := json.Marshal(status)
	i.debug.observe(ebpfDebugTaskRuntimeStatusCollection, time.Since(started), err)
	if err != nil {
		i.logger.Debug("marshal eBPF runtime status: ", err)
		return
	}
	i.logger.Debug("eBPF runtime status: ", string(encoded))
}

func (i *Inbound) warnRuntimeStatus(status ebpfRuntimeStatus) {
	if status.Local == nil {
		return
	}
	backend := status.Local.Backend
	if backend.UDPCleanupMode == "invalid" {
		i.runtimeStatusWarn.warn(i.logger, "invalid eBPF UDP cleanup state; restart with a current build")
		return
	}
	if backend.UDPRedirectReservationFailures > 0 {
		i.runtimeStatusWarn.warn(
			i.logger,
			"eBPF UDP redirect reservation failures: ", backend.UDPRedirectReservationFailures,
			", cleanup=", backend.UDPCleanupMode,
		)
		return
	}
	mapStatus, pressured := cgroupUDPMapPressure(backend.Maps)
	if pressured {
		i.runtimeStatusWarn.warn(
			i.logger,
			"eBPF UDP state map pressure: map=", mapStatus.Name,
			", entries=", mapStatus.Entries, "/", mapStatus.Capacity,
			", cleanup=", backend.UDPCleanupMode,
		)
	}
}

func cgroupUDPMapPressure(maps []ECommon.RuntimeMapStatus) (ECommon.RuntimeMapStatus, bool) {
	var highest ECommon.RuntimeMapStatus
	for _, mapStatus := range maps {
		if mapStatus.Name != "cgroup_udp_redirect" && mapStatus.Name != "cgroup_udp_token" {
			continue
		}
		if mapStatus.Type != "Hash" || !mapStatus.EntriesKnown || mapStatus.Capacity == 0 {
			continue
		}
		if uint64(mapStatus.Entries)*100 < uint64(mapStatus.Capacity)*90 {
			continue
		}
		if highest.Capacity == 0 ||
			uint64(mapStatus.Entries)*uint64(highest.Capacity) >
				uint64(highest.Entries)*uint64(mapStatus.Capacity) {
			highest = mapStatus
		}
	}
	return highest, highest.Capacity != 0
}

func (i *Inbound) startRuntimeStatusReporter() {
	if i.runtimeStatusCancel != nil || !ebpfRuntimeStatusReporterEnabled(i.logger) {
		return
	}
	ctx, cancel := context.WithCancel(i.ctx)
	done := make(chan struct{})
	wake := make(chan struct{}, 1)
	i.runtimeStatusCancel = cancel
	i.runtimeStatusDone = done
	i.maintenanceAccess.Lock()
	i.runtimeStatusWake = wake
	i.maintenanceAccess.Unlock()
	go func() {
		defer close(done)
		var ticker *time.Ticker
		var tickerChannel <-chan time.Time
		if ebpfRuntimeStatusInterval > 0 {
			ticker = time.NewTicker(ebpfRuntimeStatusInterval)
			tickerChannel = ticker.C
			defer ticker.Stop()
		}
		lastCollection := time.Now()
		var eventTimer *time.Timer
		var eventTimerChannel <-chan time.Time
		defer func() {
			if eventTimer != nil {
				eventTimer.Stop()
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tickerChannel:
				i.logRuntimeStatus("periodic")
				lastCollection = time.Now()
			case <-wake:
				remaining := ebpfRuntimeStatusEventMinInterval - time.Since(lastCollection)
				if remaining > 0 {
					if eventTimer == nil {
						eventTimer = time.NewTimer(remaining)
						eventTimerChannel = eventTimer.C
					}
					continue
				}
				i.logRuntimeStatus("event")
				lastCollection = time.Now()
			case <-eventTimerChannel:
				eventTimerChannel = nil
				eventTimer = nil
				i.logRuntimeStatus("event")
				lastCollection = time.Now()
			}
		}
	}()
}

func (i *Inbound) stopRuntimeStatusReporter() {
	if i.runtimeStatusCancel == nil {
		return
	}
	i.runtimeStatusCancel()
	<-i.runtimeStatusDone
	i.runtimeStatusCancel = nil
	i.runtimeStatusDone = nil
	i.maintenanceAccess.Lock()
	i.runtimeStatusWake = nil
	i.maintenanceAccess.Unlock()
}

func (i *Inbound) requestRuntimeStatus() {
	i.maintenanceAccess.RLock()
	wake := i.runtimeStatusWake
	i.maintenanceAccess.RUnlock()
	if wake == nil {
		return
	}
	select {
	case wake <- struct{}{}:
	default:
	}
}
