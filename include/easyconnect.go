//go:build with_easyconnect

package include

import (
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/protocol/easyconnect"
)

func registerEasyConnectEndpoint(registry *endpoint.Registry) {
	easyconnect.RegisterEndpoint(registry)
}

func registerEasyConnectDNSTransport(registry *dns.TransportRegistry) {
	easyconnect.RegisterDNSTransport(registry)
}
