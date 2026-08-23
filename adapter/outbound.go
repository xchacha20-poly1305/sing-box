package adapter

import (
	"context"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
)

// ConnectionSplicer is an optional kernel relay for an already-routed TCP
// connection. Returning false leaves both connections owned by the caller.
type ConnectionSplicer interface {
	TrySpliceTCP(ctx context.Context, dialer N.Dialer, local, remote net.Conn, metadata InboundContext, onClose N.CloseHandlerFunc) bool
}

// KernelTrafficCounter accepts traffic that bypassed userspace copy accounting.
type KernelTrafficCounter interface {
	CountKernelTraffic(upload, download int64)
}

// Note: for proxy protocols, outbound creates early connections by default.

type Outbound interface {
	Type() string
	Tag() string
	Network() []string
	Dependencies() []string
	N.Dialer
}

type OutboundWithPreferredRoutes interface {
	Outbound
	PreferredDomain(metadata *InboundContext, domain string) bool
	PreferredAddress(metadata *InboundContext, address netip.Addr) bool
}

type OutboundWithMultiplex interface {
	Outbound
	MultiplexEnabled() bool
}

type FlowOutbound interface {
	Outbound
	tun.Port
	PreMatchFlow(network string, destination netip.Addr) PreMatchAction
}

type FlowOutboundDomainResolver interface {
	FlowOutbound
	FlowDomainResolveOptions() DNSQueryOptions
}

type OutboundRegistry interface {
	option.OutboundOptionsRegistry
	CreateOutbound(ctx context.Context, router Router, logger log.ContextLogger, tag string, outboundType string, options any) (Outbound, error)
}

type OutboundManager interface {
	Lifecycle
	Outbounds() []Outbound
	Outbound(tag string) (Outbound, bool)
	Default() Outbound
	Remove(tag string) error
	Create(ctx context.Context, router Router, logger log.ContextLogger, tag string, outboundType string, options any) error
}
