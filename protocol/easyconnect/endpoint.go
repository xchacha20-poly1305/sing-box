package easyconnect

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	easyconnecttransport "github.com/sagernet/sing-box/transport/easyconnect"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/xchacha20-poly1305/sing-easyconnect"
	"go4.org/netipx"
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.EasyConnectEndpointOptions](registry, C.TypeEasyConnect, NewEndpoint)
}

type endpointBase struct {
	endpoint.Adapter
	router adapter.Router
	logger log.ContextLogger
}

func (e *endpointBase) SupportsFlow(network string) bool {
	return slices.Contains(e.Network(), network)
}

func (e *endpointBase) newConnection(ctx context.Context, endpoint adapter.Endpoint, localAddresses []netip.Prefix, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = endpoint.Tag()
	metadata.InboundType = endpoint.Type()
	metadata.Source = source
	if isEndpointLocalAddress(localAddresses, destination.Addr) {
		metadata.OriginDestination = destination
		destination.Addr = loopbackAddressFor(destination.Addr)
	}
	metadata.Destination = destination
	e.logger.InfoContext(ctx, "inbound connection from ", source)
	e.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	e.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (e *endpointBase) newPacketConnection(ctx context.Context, endpoint adapter.Endpoint, localAddresses []netip.Prefix, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = endpoint.Tag()
	metadata.InboundType = endpoint.Type()
	metadata.Source = source
	if isEndpointLocalAddress(localAddresses, destination.Addr) {
		metadata.OriginDestination = destination
		destination.Addr = loopbackAddressFor(destination.Addr)
		conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), metadata.OriginDestination, destination)
	}
	metadata.Destination = destination
	e.logger.InfoContext(ctx, "inbound packet connection from ", source)
	e.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
	e.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (e *endpointBase) newDNSPacket(ctx context.Context, endpoint adapter.Endpoint, payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	var metadata adapter.InboundContext
	metadata.Inbound = endpoint.Tag()
	metadata.InboundType = endpoint.Type()
	metadata.Network = N.NetworkUDP
	metadata.Source = source
	metadata.Destination = destination
	metadata.Protocol = C.ProtocolDNS
	e.logger.InfoContext(ctx, "inbound DNS packet from ", source)
	e.router.HijackDNSPacket(ctx, payload, writer, metadata)
}

func isEndpointLocalAddress(localAddresses []netip.Prefix, address netip.Addr) bool {
	for _, localPrefix := range localAddresses {
		if address == localPrefix.Addr() {
			return true
		}
	}
	return false
}

func loopbackAddressFor(address netip.Addr) netip.Addr {
	if address.Is4() {
		return netip.AddrFrom4([4]uint8{127, 0, 0, 1})
	}
	return netip.IPv6Loopback()
}

func judgeEasyConnectFlow(router adapter.Router, tag string, endpointType string, localAddresses []netip.Prefix, network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	for _, localPrefix := range localAddresses {
		if destination.Addr() == localPrefix.Addr() {
			return tun.FlowVerdict{Action: tun.ActionAccept}
		}
	}
	return adapter.JudgeFlow(router, tag, endpointType, network, source, destination, firstPacket)
}

func materialSource(name string, inlineValues []string, path string) (easyconnect.Material, error) {
	material := easyconnect.Material{Path: path}
	if len(inlineValues) > 0 {
		material.Content = []byte(strings.Join(inlineValues, "\n"))
	}
	return material, material.Validate(name)
}

func configurationFromClientEvent(event easyconnect.TunnelConfigurationEvent) easyconnecttransport.Configuration {
	configuration := event.Configuration
	mtu := configuration.MTU
	if mtu == 0 {
		mtu = easyconnecttransport.DefaultMTU
	}
	routes := common.Map(configuration.Routes, func(route easyconnect.TunnelRoute) easyconnecttransport.Route {
		return easyconnecttransport.Route{Prefix: route.Prefix}
	})
	for _, dnsAddress := range configuration.DNS {
		if !dnsAddress.IsValid() {
			continue
		}
		dnsIncluded := false
		for _, route := range routes {
			if route.Prefix.Contains(dnsAddress) {
				dnsIncluded = true
				break
			}
		}
		if !dnsIncluded {
			routes = append(routes, easyconnecttransport.Route{
				Prefix: netip.PrefixFrom(dnsAddress, dnsAddress.BitLen()),
			})
		}
	}
	return easyconnecttransport.Configuration{
		MTU:           mtu,
		Addresses:     configuration.Addresses,
		Routes:        routes,
		DNS:           configuration.DNS,
		Hosts:         common.Map(configuration.Hosts, easyConnectDNSHost),
		SearchDomains: configuration.SearchDomains,
	}
}

func easyConnectDNSHost(host easyconnect.DNSHost) easyconnecttransport.DNSHost {
	return easyconnecttransport.DNSHost{Domain: host.Domain, Addresses: host.Addresses}
}

func buildIPSet(routes []easyconnecttransport.Route) (*netipx.IPSet, error) {
	var builder netipx.IPSetBuilder
	for _, route := range routes {
		builder.AddPrefix(route.Prefix)
	}
	return builder.IPSet()
}

func buildPreferredDomains(configuration easyconnecttransport.Configuration) map[string]bool {
	preferredDomains := make(map[string]bool)
	for _, domain := range configuration.SearchDomains {
		canonicalDomain := canonicalEasyConnectDomain(domain)
		if canonicalDomain != "" {
			preferredDomains[canonicalDomain] = true
		}
	}
	for _, host := range configuration.Hosts {
		canonicalDomain := canonicalEasyConnectDomain(host.Domain)
		if canonicalDomain != "" {
			preferredDomains[canonicalDomain] = true
		}
	}
	return preferredDomains
}

func canonicalEasyConnectDomain(domain string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
}

func easyConnectDomainMatchesAny(domain string, suffixes map[string]bool) bool {
	for domain != "" {
		if suffixes[domain] {
			return true
		}
		dotIndex := strings.IndexByte(domain, '.')
		if dotIndex == -1 {
			break
		}
		domain = domain[dotIndex+1:]
	}
	return false
}
