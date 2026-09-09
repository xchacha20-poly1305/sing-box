package easyconnect

import (
	"cmp"
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/iponly"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	easyconnecttransport "github.com/sagernet/sing-box/transport/easyconnect"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/xchacha20-poly1305/sing-easyconnect"
	"go4.org/netipx"
)

var (
	_ adapter.OutboundWithPreferredRoutes = (*Endpoint)(nil)
	_ adapter.FlowOutbound                = (*Endpoint)(nil)
	_ adapter.InterfaceUpdateListener     = (*Endpoint)(nil)
	_ dialer.PacketDialerWithDestination  = (*Endpoint)(nil)
	_ tun.Port                            = (*Endpoint)(nil)
)

type Endpoint struct {
	endpointBase
	loopContext        context.Context
	cancelLoop         context.CancelFunc
	dnsRouter          adapter.DNSRouter
	client             *easyconnect.Client
	device             easyconnecttransport.Device
	onDemand           bool
	server             string
	stateAccess        sync.Mutex
	state              atomic.Pointer[clientState]
	dnsTransportAccess sync.Mutex
	dnsTransport       *DNSTransport
	deviceStarted      bool
	readLoopDone       chan struct{}
	statusAccess       sync.Mutex
	statusUpdated      chan struct{}
	terminalError      string
}

type clientState struct {
	started          bool
	tunnelConfigured bool
	localAddresses   []netip.Prefix
	routeSet         *netipx.IPSet
	preferredDomains map[string]bool
	configuration    easyconnecttransport.Configuration
	tunnelInfo       adapter.EasyConnectTunnelInfo
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.EasyConnectEndpointOptions) (adapter.Endpoint, error) {
	loopContext, cancelLoop := context.WithCancel(ctx)
	easyConnectEndpoint := &Endpoint{
		endpointBase: endpointBase{
			Adapter: endpoint.NewAdapterWithDialerOptions(C.TypeEasyConnect, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions),
			router:  router,
			logger:  logger,
		},
		loopContext:   loopContext,
		cancelLoop:    cancelLoop,
		dnsRouter:     service.FromContext[adapter.DNSRouter](ctx),
		statusUpdated: make(chan struct{}),
		onDemand:      options.OnDemand,
	}
	easyConnectEndpoint.state.Store(new(clientState))
	success := false
	defer func() {
		if success {
			return
		}
		if easyConnectEndpoint.device != nil {
			_ = easyConnectEndpoint.device.Close()
		}
		cancelLoop()
	}()
	server := options.Server
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, E.Cause(err, "parse server")
	}
	serverPort := cmp.Or(serverURL.Port(), "443")
	easyConnectEndpoint.server = net.JoinHostPort(serverURL.Hostname(), serverPort)
	serverAddress, serverAddressErr := netip.ParseAddr(serverURL.Hostname())
	remoteIsDomain := serverURL.Hostname() != "" && serverAddressErr != nil && !serverAddress.IsValid()
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   remoteIsDomain,
		ResolverOnDetour: true,
		NewDialer:        true,
	})
	if err != nil {
		return nil, err
	}
	udpTimeout := cmp.Or(options.UDPTimeout.Build(), C.UDPTimeout)
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	device, err := easyconnecttransport.NewDevice(easyconnecttransport.DeviceOptions{
		Context:         ctx,
		Logger:          logger,
		System:          options.System,
		Handler:         easyConnectEndpoint,
		UDPTimeout:      udpTimeout,
		ICMPTimeout:     C.ICMPTimeout,
		UDPMapping:      tun.NATMapping(options.UDPMapping),
		UDPFiltering:    tun.NATFiltering(options.UDPFiltering),
		UDPNATMax:       options.UDPNATMax,
		InterfaceFinder: networkManager.InterfaceFinder(),
		Name:            options.Name,
		MTU:             easyconnecttransport.DefaultMTU,
		Configuration: easyconnecttransport.Configuration{
			MTU: easyconnecttransport.DefaultMTU,
		},
	})
	if err != nil {
		return nil, err
	}
	easyConnectEndpoint.device = device
	device.SetPacketWriter(easyConnectEndpoint.writePacketBuffers)
	clientOptions, err := easyConnectEndpoint.buildClientOptions(options, outboundDialer)
	if err != nil {
		return nil, err
	}
	client, err := easyconnect.NewClient(clientOptions)
	if err != nil {
		return nil, err
	}
	easyConnectEndpoint.client = client
	success = true
	return easyConnectEndpoint, nil
}

func (e *Endpoint) buildClientOptions(options option.EasyConnectEndpointOptions, outboundDialer N.Dialer) (easyconnect.ClientOptions, error) {
	var tlsConfig *tls.Config
	if options.TLS.Insecure {
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
	}
	certificateAuthority, err := materialSource("tls.certificate_authority", options.TLS.CertificateAuthority, options.TLS.CertificateAuthorityPath)
	if err != nil {
		return easyconnect.ClientOptions{}, err
	}
	return easyconnect.ClientOptions{
		Context:                           e.loopContext,
		Server:                            options.Server,
		Username:                          options.Username,
		Password:                          options.Password,
		Device:                            options.Device,
		Language:                          options.Language,
		MTU:                               options.MTU,
		QueueLength:                       options.QueueLength,
		KeepAliveInterval:                 time.Duration(options.KeepAliveInterval),
		KeepAliveTimeout:                  time.Duration(options.KeepAliveTimeout),
		KeepAliveSequenceDisguiseDisabled: options.KeepAliveSequenceDisguiseDisabled,
		DataChannelTimeout:                time.Duration(options.DataChannelTimeout),
		DataChannelKeepAliveInterval:      time.Duration(options.DataChannelKeepAliveInterval),
		DataChannelKeepAliveDestination:   common.PtrValueOrDefault((*netip.Addr)(options.DataChannelKeepAliveDestination)),
		DataChannelKeepAliveTimeout:       time.Duration(options.DataChannelKeepAliveTimeout),
		ReconnectTimeout:                  time.Duration(options.ReconnectTimeout),
		ResourceRoutesDisabled:            options.ResourceRoutesDisabled,
		ResourceFilterDisabled:            options.ResourceFilterDisabled,
		TLSConfig: easyconnect.ClientTLSOptions{
			Config:               tlsConfig,
			ServerName:           options.TLS.ServerName,
			Insecure:             options.TLS.Insecure,
			SystemTrustDisabled:  options.TLS.SystemTrustDisabled,
			CertificateAuthority: certificateAuthority,
		},
		Dialer:                outboundDialer,
		Logger:                e.logger,
		OnTunnelConfiguration: e.handleTunnelConfiguration,
	}, nil
}

func (e *Endpoint) handleTunnelConfiguration(event easyconnect.TunnelConfigurationEvent) error {
	configuration := configurationFromClientEvent(event)
	defer e.notifyStatusUpdated()
	e.stateAccess.Lock()
	defer e.stateAccess.Unlock()
	e.updateState(func(state *clientState) {
		state.tunnelConfigured = false
	})
	routeSet, err := buildIPSet(configuration.Routes)
	if err != nil {
		return E.Cause(err, "build route set")
	}
	err = e.device.UpdateConfiguration(easyconnecttransport.Configuration{
		MTU:       configuration.MTU,
		Addresses: configuration.Addresses,
	})
	if err != nil {
		return E.Cause(err, "update device configuration")
	}
	if !e.deviceStarted {
		err = e.device.Start()
		if err != nil {
			return E.Cause(err, "start device")
		}
		e.deviceStarted = true
	}
	preferredDomains := buildPreferredDomains(configuration)
	var ipv4Addresses []netip.Prefix
	for _, address := range configuration.Addresses {
		if address.Addr().Is4() {
			ipv4Addresses = append(ipv4Addresses, address)
		}
	}
	e.updateState(func(state *clientState) {
		connectedSince := state.tunnelInfo.ConnectedSince
		if event.Reason == easyconnect.TunnelConfigurationEventInitial ||
			event.Reason == easyconnect.TunnelConfigurationEventReestablishment ||
			connectedSince.IsZero() {
			connectedSince = time.Now()
		}
		state.tunnelConfigured = true
		state.localAddresses = configuration.Addresses
		state.routeSet = routeSet
		state.preferredDomains = preferredDomains
		state.configuration = configuration
		state.tunnelInfo = adapter.EasyConnectTunnelInfo{
			Server:         e.server,
			IPv4:           ipv4Addresses,
			DNS:            configuration.DNS,
			MTU:            configuration.MTU,
			ConnectedSince: connectedSince,
		}
	})
	e.dnsTransportAccess.Lock()
	dnsTransport := e.dnsTransport
	e.dnsTransportAccess.Unlock()
	if dnsTransport != nil {
		dnsTransport.updateConfiguration(configuration)
	}
	return nil
}

func (e *Endpoint) updateState(update func(state *clientState)) {
	newState := *e.state.Load()
	update(&newState)
	e.state.Store(&newState)
}

func (e *Endpoint) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	err := e.client.Start()
	if err != nil {
		return err
	}
	e.stateAccess.Lock()
	e.updateState(func(state *clientState) {
		state.started = true
	})
	e.readLoopDone = make(chan struct{})
	e.stateAccess.Unlock()
	go e.readLoop()
	e.notifyStatusUpdated()
	return nil
}

func (e *Endpoint) readLoop() {
	defer close(e.readLoopDone)
	for {
		packetBuffers, err := e.client.ReadDataPackets(e.loopContext)
		if err != nil {
			if E.IsClosedOrCanceled(err) || e.loopContext.Err() != nil {
				return
			}
			e.logger.Error(E.Cause(err, "client terminated"))
			e.setTerminalError(err)
			return
		}
		err = e.device.WriteInboundBuffers(packetBuffers)
		buf.ReleaseMulti(packetBuffers)
		if err != nil {
			err = E.Cause(err, "write packet to device")
			e.logger.Error(err)
			e.setTerminalError(err)
			return
		}
	}
}

func (e *Endpoint) Close() error {
	e.stateAccess.Lock()
	e.updateState(func(state *clientState) {
		state.started = false
	})
	readLoopDone := e.readLoopDone
	e.stateAccess.Unlock()
	e.cancelLoop()
	err := E.Errors(e.client.Close(), e.device.Close())
	if readLoopDone != nil {
		<-readLoopDone
	}
	e.notifyStatusUpdated()
	return err
}

func (e *Endpoint) InterfaceUpdated(ctx context.Context) {
	e.client.RestartSession()
}

func (e *Endpoint) OnDemand() bool {
	return e.onDemand
}

func (e *Endpoint) SetKeepIdleConnections(keep bool) {
	if !keep {
		e.client.Suspend()
	}
}

func (e *Endpoint) waitReady(ctx context.Context) error {
	if !e.onDemand {
		if !e.ready() || !e.client.Ready() {
			return E.New("endpoint is not ready yet")
		}
		return nil
	}
	e.client.Resume()
	waitCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	err := e.client.WaitReady(waitCtx)
	if err != nil {
		return err
	}
	for {
		e.statusAccess.Lock()
		statusUpdated := e.statusUpdated
		terminalError := e.terminalError
		e.statusAccess.Unlock()
		if terminalError != "" {
			return E.New(terminalError)
		}
		if e.ready() {
			return nil
		}
		select {
		case <-waitCtx.Done():
			return waitCtx.Err()
		case <-statusUpdated:
		}
	}
}

func (e *Endpoint) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	return adapter.PreMatchFlow
}

func (e *Endpoint) PortAddresses() (netip.Addr, netip.Addr) {
	return e.device.PortAddresses()
}

func (e *Endpoint) PortMTU() uint32 {
	return e.device.PortMTU()
}

func (e *Endpoint) AttachReturn(returnPath tun.Return) error {
	return e.device.AttachReturn(returnPath)
}

func (e *Endpoint) DetachReturn(returnPath tun.Return) error {
	return e.device.DetachReturn(returnPath)
}

func (e *Endpoint) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	return judgeEasyConnectFlow(e.router, e.Tag(), e.Type(), e.state.Load().localAddresses, network, source, destination, firstPacket)
}

func (e *Endpoint) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	e.newDNSPacket(log.ContextWithNewID(e.loopContext), e, payload, source, destination, writer)
}

func (e *Endpoint) ready() bool {
	state := e.state.Load()
	return state.started && state.tunnelConfigured
}

func (e *Endpoint) WritePackets(packets [][]byte) error {
	if e.onDemand {
		e.client.Resume()
	}
	if !e.ready() {
		return E.New("endpoint is not ready yet")
	}
	err := e.client.WriteDataPackets(packets)
	if E.IsMulti(err, easyconnect.ErrDataChannelNotReady) {
		return E.New("endpoint is not ready yet")
	}
	return err
}

func (e *Endpoint) writePacketBuffers(packetBuffers []*buf.Buffer) error {
	if e.onDemand {
		e.client.Resume()
	}
	if !e.ready() {
		buf.ReleaseMulti(packetBuffers)
		return nil
	}
	err := e.client.WriteDataPacketBuffers(packetBuffers)
	if E.IsMulti(err, easyconnect.ErrDataChannelNotReady) {
		return nil
	}
	return err
}

func (e *Endpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	e.newConnection(ctx, e, e.state.Load().localAddresses, conn, source, destination, onClose)
}

func (e *Endpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	e.newPacketConnection(ctx, e, e.state.Load().localAddresses, conn, source, destination, onClose)
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		e.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		e.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	readyErr := e.waitReady(ctx)
	if readyErr != nil {
		return nil, readyErr
	}
	if destination.IsDomain() {
		destinationAddresses, err := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, e.device, network, destination, destinationAddresses)
	}
	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return e.device.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	e.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	readyErr := e.waitReady(ctx)
	if readyErr != nil {
		return nil, netip.Addr{}, readyErr
	}
	if destination.IsDomain() {
		destinationAddresses, err := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, netip.Addr{}, err
		}
		packetConn, destinationAddress, err := N.ListenSerial(ctx, e.device, destination, destinationAddresses)
		if err != nil {
			return nil, netip.Addr{}, err
		}
		return iponly.NewPacketConn(e.logger, packetConn), destinationAddress, nil
	}
	packetConn, err := e.device.ListenPacket(ctx, destination)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsIP() {
		return iponly.NewPacketConn(e.logger, packetConn), destination.Addr, nil
	}
	return iponly.NewPacketConn(e.logger, packetConn), netip.Addr{}, nil
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, destinationAddress, err := e.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if destinationAddress.IsValid() && destination != M.SocksaddrFrom(destinationAddress, destination.Port) {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(packetConn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
	}
	return packetConn, nil
}

func (e *Endpoint) PreferredDomain(metadata *adapter.InboundContext, domain string) bool {
	state := e.state.Load()
	if !state.started || !state.tunnelConfigured || !e.client.Ready() {
		return false
	}
	canonicalDomain := canonicalEasyConnectDomain(domain)
	return easyConnectDomainMatchesAny(canonicalDomain, state.preferredDomains)
}

func (e *Endpoint) PreferredAddress(metadata *adapter.InboundContext, address netip.Addr) bool {
	state := e.state.Load()
	if !state.started || !state.tunnelConfigured || state.routeSet == nil || !e.client.Ready() {
		return false
	}
	return state.routeSet.Contains(address)
}
