package easyconnect

import (
	"slices"

	"github.com/sagernet/sing-box/adapter"
)

var _ adapter.EasyConnectEndpoint = (*Endpoint)(nil)

func (e *Endpoint) EasyConnectStatus() adapter.EasyConnectStatus {
	var status adapter.EasyConnectStatus
	clientState := e.state.Load()
	e.statusAccess.Lock()
	status.Error = e.terminalError
	e.statusAccess.Unlock()
	switch {
	case status.Error != "":
		status.State = adapter.EasyConnectStateError
	case clientState.started && clientState.tunnelConfigured && e.client.Ready():
		status.State = adapter.EasyConnectStateConnected
		tunnelInfo := clientState.tunnelInfo
		tunnelInfo.IPv4 = slices.Clone(tunnelInfo.IPv4)
		tunnelInfo.DNS = slices.Clone(tunnelInfo.DNS)
		status.TunnelInfo = &tunnelInfo
	default:
		status.State = adapter.EasyConnectStateConnecting
	}
	return status
}

func (e *Endpoint) StatusUpdated() <-chan struct{} {
	e.statusAccess.Lock()
	defer e.statusAccess.Unlock()
	return e.statusUpdated
}

func (e *Endpoint) notifyStatusUpdated() {
	e.statusAccess.Lock()
	e.notifyStatusUpdatedLocked()
	e.statusAccess.Unlock()
}

func (e *Endpoint) notifyStatusUpdatedLocked() {
	close(e.statusUpdated)
	e.statusUpdated = make(chan struct{})
}

func (e *Endpoint) setTerminalError(err error) {
	e.statusAccess.Lock()
	e.terminalError = err.Error()
	e.notifyStatusUpdatedLocked()
	e.statusAccess.Unlock()
}
