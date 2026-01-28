package option

import (
	"strings"

	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"
)

type TrustTunnelInboundOptions struct {
	ListenOptions
	Users                 []auth.User `json:"users,omitempty"`
	QUICCongestionControl string      `json:"quic_congestion_control,omitempty"`
	Network               NetworkList `json:"network,omitempty"`
	InboundTLSOptionsContainer
}

type TrustTunnelOutboundOptions struct {
	DialerOptions
	ServerOptions
	Network               NetworkListWithICMP `json:"network,omitempty"`
	Username              string              `json:"username,omitempty"`
	Password              string              `json:"password,omitempty"`
	HealthCheck           bool                `json:"health_check,omitempty"`
	QUIC                  bool                `json:"quic,omitempty"`
	QUICCongestionControl string              `json:"quic_congestion_control,omitempty"`
	OutboundTLSOptionsContainer
}

type NetworkListWithICMP string

func (v *NetworkListWithICMP) UnmarshalJSON(content []byte) error {
	var networkList []string
	err := json.Unmarshal(content, &networkList)
	if err != nil {
		var networkItem string
		err = json.Unmarshal(content, &networkItem)
		if err != nil {
			return err
		}
		networkList = []string{networkItem}
	}
	for _, networkName := range networkList {
		switch networkName {
		case N.NetworkTCP, N.NetworkUDP, N.NetworkICMP:
		default:
			return E.New("unknown network: " + networkName)
		}
	}
	*v = NetworkListWithICMP(strings.Join(networkList, "\n"))
	return nil
}

func (v NetworkListWithICMP) Build() []string {
	if v == "" {
		return []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}
	}
	return strings.Split(string(v), "\n")
}

func (v NetworkListWithICMP) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return schema.ListableOf(schema.StringEnum(N.NetworkTCP, N.NetworkUDP, N.NetworkICMP)), nil
}
