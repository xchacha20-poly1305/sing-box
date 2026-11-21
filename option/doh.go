package option

import "github.com/sagernet/sing/common/auth"

type ApiDnsOptions struct {
	Enabled bool   `json:"enabled,omitempty"`
	Path    string `json:"path,omitempty"`
}

type DoHServiceOptions struct {
	ListenOptions
	Path  string      `json:"path,omitempty"`
	Users []auth.User `json:"users,omitempty"`
	InboundTLSOptionsContainer
}
