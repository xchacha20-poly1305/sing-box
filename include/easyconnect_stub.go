//go:build !with_easyconnect

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerEasyConnectEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.EasyConnectEndpointOptions](registry, C.TypeEasyConnect, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.EasyConnectEndpointOptions) (adapter.Endpoint, error) {
		if !options.System {
			return nil, E.New(`EasyConnect is not included in this build, rebuild with -tags with_easyconnect,with_gvisor for system:false`)
		}
		return nil, E.New(`EasyConnect is not included in this build, rebuild with -tags with_easyconnect`)
	})
}

func registerEasyConnectDNSTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.EasyConnectDNSServerOptions](registry, C.DNSTypeEasyConnect, func(ctx context.Context, logger log.ContextLogger, tag string, options option.EasyConnectDNSServerOptions) (adapter.DNSTransport, error) {
		return nil, E.New(`EasyConnect is not included in this build, rebuild with -tags with_easyconnect`)
	})
}
