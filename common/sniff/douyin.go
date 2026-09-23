package sniff

import (
	"context"
	"encoding/binary"
	"os"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

// DouyinPCDN detects the P2P video distribution protocol of Douyin clients,
// usually on UDP 8567-8569.
//
//	offset |   0  |      1      |      2-3       |  4-19  |   20-29   |
//	       | 0x12 | packet type | payload length | nonce  | sender ID |
//
// Packet type 0x02 is cleartext, 0x03 is the same message XOR-obfuscated.
// The length field is big endian and covers the whole UDP payload.
func DouyinPCDN(_ context.Context, metadata *adapter.InboundContext, packet []byte) error {
	const headerLength = 30
	const magicHeader = 0x12
	if len(packet) < headerLength || packet[0] != magicHeader {
		return os.ErrInvalid
	}
	switch packet[1] {
	case 0x01, 0x02, 0x03:
	default:
		return os.ErrInvalid
	}
	if int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		return os.ErrInvalid
	}
	metadata.Protocol = C.ProtocolDouyinPCDN
	return nil
}
