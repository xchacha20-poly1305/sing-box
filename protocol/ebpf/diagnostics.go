//go:build with_ebpf && (linux || android)

package ebpf

import "sync/atomic"

type eBPFDiagnostics struct {
	localTCPRedirectMiss      atomic.Uint64
	localTCPLookupError       atomic.Uint64
	localUDPPacketInfoError   atomic.Uint64
	localUDPRedirectMiss      atomic.Uint64
	localUDPRedirectRecovery  atomic.Uint64
	localUDPConnectedRecovery atomic.Uint64
	localUDPLookupError       atomic.Uint64
	localUDPBindingMiss       atomic.Uint64
	localUDPBindingRecovery   atomic.Uint64
	localUDPLateReply         atomic.Uint64
	localUDPCleanupError      atomic.Uint64
	sharedTCPRedirectMiss     atomic.Uint64
	sharedTCPLookupError      atomic.Uint64
	sharedUDPPacketInfoError  atomic.Uint64
	sharedUDPRedirectMiss     atomic.Uint64
	sharedUDPLookupError      atomic.Uint64
	sharedUDPBindingMiss      atomic.Uint64
	sharedUDPBindingRecovery  atomic.Uint64
	sharedUDPLateReply        atomic.Uint64
	sharedFlowReleaseError    atomic.Uint64
}

type eBPFDiagnosticPathSnapshot struct {
	TCPRedirectMiss      uint64 `json:"tcp_redirect_miss"`
	TCPLookupError       uint64 `json:"tcp_lookup_error"`
	UDPPacketInfoError   uint64 `json:"udp_packet_info_error"`
	UDPRedirectMiss      uint64 `json:"udp_redirect_miss"`
	UDPRedirectRecovery  uint64 `json:"udp_redirect_recovery"`
	UDPConnectedRecovery uint64 `json:"udp_connected_recovery"`
	UDPLookupError       uint64 `json:"udp_lookup_error"`
	UDPBindingMiss       uint64 `json:"udp_binding_miss"`
	UDPBindingRecovery   uint64 `json:"udp_binding_recovery"`
	UDPLateReply         uint64 `json:"udp_late_reply"`
	CleanupError         uint64 `json:"cleanup_error"`
}

type eBPFDiagnosticSnapshot struct {
	Local  eBPFDiagnosticPathSnapshot `json:"local"`
	Shared eBPFDiagnosticPathSnapshot `json:"shared"`
}

func (d *eBPFDiagnostics) snapshot() eBPFDiagnosticSnapshot {
	return eBPFDiagnosticSnapshot{
		Local: eBPFDiagnosticPathSnapshot{
			TCPRedirectMiss:      d.localTCPRedirectMiss.Load(),
			TCPLookupError:       d.localTCPLookupError.Load(),
			UDPPacketInfoError:   d.localUDPPacketInfoError.Load(),
			UDPRedirectMiss:      d.localUDPRedirectMiss.Load(),
			UDPRedirectRecovery:  d.localUDPRedirectRecovery.Load(),
			UDPConnectedRecovery: d.localUDPConnectedRecovery.Load(),
			UDPLookupError:       d.localUDPLookupError.Load(),
			UDPBindingMiss:       d.localUDPBindingMiss.Load(),
			UDPBindingRecovery:   d.localUDPBindingRecovery.Load(),
			UDPLateReply:         d.localUDPLateReply.Load(),
			CleanupError:         d.localUDPCleanupError.Load(),
		},
		Shared: eBPFDiagnosticPathSnapshot{
			TCPRedirectMiss:    d.sharedTCPRedirectMiss.Load(),
			TCPLookupError:     d.sharedTCPLookupError.Load(),
			UDPPacketInfoError: d.sharedUDPPacketInfoError.Load(),
			UDPRedirectMiss:    d.sharedUDPRedirectMiss.Load(),
			UDPLookupError:     d.sharedUDPLookupError.Load(),
			UDPBindingMiss:     d.sharedUDPBindingMiss.Load(),
			UDPBindingRecovery: d.sharedUDPBindingRecovery.Load(),
			UDPLateReply:       d.sharedUDPLateReply.Load(),
			CleanupError:       d.sharedFlowReleaseError.Load(),
		},
	}
}

func (s eBPFDiagnosticPathSnapshot) total() uint64 {
	return s.TCPRedirectMiss + s.TCPLookupError + s.UDPPacketInfoError +
		s.UDPRedirectMiss + s.UDPRedirectRecovery + s.UDPConnectedRecovery + s.UDPLookupError +
		s.UDPBindingMiss + s.UDPBindingRecovery + s.UDPLateReply + s.CleanupError
}

func (s eBPFDiagnosticPathSnapshot) failures() uint64 {
	return s.TCPRedirectMiss + s.TCPLookupError + s.UDPPacketInfoError +
		s.UDPRedirectMiss + s.UDPLookupError + s.UDPBindingMiss + s.CleanupError
}

func (s eBPFDiagnosticSnapshot) empty() bool {
	return s.Local.total() == 0 && s.Shared.total() == 0
}

func (i *Inbound) logDiagnosticSummary() {
	snapshot := i.diagnostics.snapshot()
	if snapshot.empty() {
		return
	}
	message := []any{
		"eBPF traffic diagnostic summary: local={tcp_redirect_miss:", snapshot.Local.TCPRedirectMiss,
		", tcp_lookup_error:", snapshot.Local.TCPLookupError,
		", udp_packet_info_error:", snapshot.Local.UDPPacketInfoError,
		", udp_redirect_miss:", snapshot.Local.UDPRedirectMiss,
		", udp_redirect_recovery:", snapshot.Local.UDPRedirectRecovery,
		", udp_connected_recovery:", snapshot.Local.UDPConnectedRecovery,
		", udp_lookup_error:", snapshot.Local.UDPLookupError,
		", udp_binding_miss:", snapshot.Local.UDPBindingMiss,
		", udp_binding_recovery:", snapshot.Local.UDPBindingRecovery,
		", udp_late_reply:", snapshot.Local.UDPLateReply,
		", cleanup_error:", snapshot.Local.CleanupError,
		"}, shared={tcp_redirect_miss:", snapshot.Shared.TCPRedirectMiss,
		", tcp_lookup_error:", snapshot.Shared.TCPLookupError,
		", udp_packet_info_error:", snapshot.Shared.UDPPacketInfoError,
		", udp_redirect_miss:", snapshot.Shared.UDPRedirectMiss,
		", udp_lookup_error:", snapshot.Shared.UDPLookupError,
		", udp_binding_miss:", snapshot.Shared.UDPBindingMiss,
		", udp_binding_recovery:", snapshot.Shared.UDPBindingRecovery,
		", udp_late_reply:", snapshot.Shared.UDPLateReply,
		", cleanup_error:", snapshot.Shared.CleanupError,
		"}",
	}
	if snapshot.Local.failures()+snapshot.Shared.failures() > 0 {
		i.logger.Warn(message...)
	} else {
		i.logger.Debug(message...)
	}
}
