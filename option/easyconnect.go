package option

import "github.com/sagernet/sing/common/json/badoption"

type EasyConnectEndpointOptions struct {
	DialerOptions
	System                            bool                  `json:"system,omitempty"`
	Name                              string                `json:"name,omitempty"`
	UDPTimeout                        badoption.Duration    `json:"udp_timeout,omitempty"`
	UDPMapping                        UDPNATBehavior        `json:"udp_mapping,omitempty"`
	UDPFiltering                      UDPNATBehavior        `json:"udp_filtering,omitempty"`
	UDPNATMax                         uint32                `json:"udp_nat_max,omitempty"`
	Server                            string                `json:"server"`
	Username                          string                `json:"username,omitempty"`
	Password                          string                `json:"password,omitempty"`
	Device                            string                `json:"device,omitempty"`
	Language                          string                `json:"language,omitempty"`
	MTU                               uint32                `json:"mtu,omitempty"`
	QueueLength                       uint32                `json:"queue_length,omitempty"`
	KeepAliveInterval                 badoption.Duration    `json:"keep_alive_interval,omitempty"`
	KeepAliveTimeout                  badoption.Duration    `json:"keep_alive_timeout,omitempty"`
	KeepAliveSequenceDisguiseDisabled bool                  `json:"keep_alive_sequence_disguise_disabled,omitempty"`
	DataChannelTimeout                badoption.Duration    `json:"data_channel_timeout,omitempty"`
	DataChannelKeepAliveInterval      badoption.Duration    `json:"data_channel_keep_alive_interval,omitempty"`
	DataChannelKeepAliveDestination   *badoption.Addr       `json:"data_channel_keep_alive_destination,omitempty"`
	DataChannelKeepAliveTimeout       badoption.Duration    `json:"data_channel_keep_alive_timeout,omitempty"`
	ReconnectTimeout                  badoption.Duration    `json:"reconnect_timeout,omitempty"`
	ResourceRoutesDisabled            bool                  `json:"resource_routes_disabled,omitempty"`
	ResourceFilterDisabled            bool                  `json:"resource_filter_disabled,omitempty"`
	TLS                               EasyConnectTLSOptions `json:"tls,omitempty"`
	OnDemand                          bool                  `json:"on_demand,omitempty"`
}

type EasyConnectTLSOptions struct {
	Insecure                 bool                       `json:"insecure,omitempty"`
	ServerName               string                     `json:"server_name,omitempty"`
	SystemTrustDisabled      bool                       `json:"system_trust_disabled,omitempty"`
	CertificateAuthority     badoption.Listable[string] `json:"certificate_authority,omitempty"`
	CertificateAuthorityPath string                     `json:"certificate_authority_path,omitempty"`
}

type EasyConnectDNSServerOptions struct {
	Endpoint               string `json:"endpoint,omitempty"`
	AcceptDefaultResolvers bool   `json:"accept_default_resolvers,omitempty"`
	AcceptSearchDomain     bool   `json:"accept_search_domain,omitempty"`
}
