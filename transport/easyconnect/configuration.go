package easyconnect

import (
	"net/netip"
)

const (
	DefaultMTU     = 1400
	PacketHeadroom = 4096
)

type Configuration struct {
	MTU           uint32
	Addresses     []netip.Prefix
	Routes        []Route
	DNS           []netip.Addr
	Hosts         []DNSHost
	SearchDomains []string
}

type DNSHost struct {
	Domain    string
	Addresses []netip.Addr
}

type Route struct {
	Prefix netip.Prefix
}
