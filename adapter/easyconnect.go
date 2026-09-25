package adapter

import (
	"net/netip"
	"time"
)

const (
	EasyConnectStateConnecting = "connecting"
	EasyConnectStateConnected  = "connected"
	EasyConnectStateError      = "error"
)

type EasyConnectEndpoint interface {
	Endpoint
	EasyConnectStatus() EasyConnectStatus
	StatusUpdated() <-chan struct{}
}

type EasyConnectStatus struct {
	State      string
	Error      string
	TunnelInfo *EasyConnectTunnelInfo
}

type EasyConnectTunnelInfo struct {
	Server         string
	IPv4           []netip.Prefix
	DNS            []netip.Addr
	MTU            uint32
	ConnectedSince time.Time
}
