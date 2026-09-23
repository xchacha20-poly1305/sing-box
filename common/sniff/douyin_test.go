package sniff_test

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

// douyinPacket builds a packet with the observed header layout. Nonce, node
// and resource IDs and addresses are synthetic to prevent put real data,
// which includes unique personal information.
func douyinPacket(t *testing.T, packetType byte, bodyHex string) []byte {
	body, err := hex.DecodeString(bodyHex)
	require.NoError(t, err)
	const (
		nonce  = "000102030405060708090a0b0c0d0e0f"
		nodeID = "00112233445566778899"
	)
	header, err := hex.DecodeString("1200" + "0000" + nonce + nodeID)
	require.NoError(t, err)
	header[1] = packetType
	packet := append(header, body...)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	return packet
}

const douyinResourceID = "00000000112233445566778899aabbcc"

func TestSniffDouyinPCDN(t *testing.T) {
	t.Parallel()
	for name, packet := range map[string][]byte{
		"probe":       douyinPacket(t, 0x02, "0000000100"),
		"probe reply": douyinPacket(t, 0x02, "000000010000"),
		"piece request": douyinPacket(t, 0x02, "01"+douyinResourceID+
			"0000004100000248"+"1000001547"+"0000154800001549"),
		// Candidate addresses 192.0.2.1:8568 and [2001:db8::1]:8568.
		"address exchange": douyinPacket(t, 0x02, "01"+douyinResourceID+
			"000000df0001fa0001000000000003"+"c00002012178"+
			"0020010db8000000000000000000000001"+"2178"+
			"10"+hex.EncodeToString([]byte("v1.douyinvod.com"))),
		"obfuscated probe":   douyinPacket(t, 0x03, "8787878686"),
		"obfuscated request": douyinPacket(t, 0x03, "c7c7c7c7a5a5a5a55a000008cb000008cc000008cd"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var metadata adapter.InboundContext
			err := sniff.DouyinPCDN(t.Context(), &metadata, packet)
			require.NoError(t, err)
			require.Equal(t, C.ProtocolDouyinPCDN, metadata.Protocol)
		})
	}
}

func TestSniffDouyinPCDNInvalid(t *testing.T) {
	t.Parallel()
	mutate := func(f func(packet []byte) []byte) []byte {
		return f(douyinPacket(t, 0x02, "0000000100"))
	}
	for name, packet := range map[string][]byte{
		"truncated":        mutate(func(p []byte) []byte { return p[:29] }),
		"wrong magic":      mutate(func(p []byte) []byte { p[0] = 0x13; return p }),
		"unknown type":     mutate(func(p []byte) []byte { p[1] = 0x04; return p }),
		"length too long":  mutate(func(p []byte) []byte { p[3]++; return p }),
		"length too short": mutate(func(p []byte) []byte { p[3]--; return p }),
		"trailing data":    mutate(func(p []byte) []byte { return append(p, 0) }),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var metadata adapter.InboundContext
			err := sniff.DouyinPCDN(t.Context(), &metadata, packet)
			require.Error(t, err)
		})
	}
}

func TestSniffDouyinPCDNOtherProtocols(t *testing.T) {
	t.Parallel()
	for name, packetHex := range map[string]string{
		"stun":              "000100002112a44224b1a025d0c180c484341306",
		"dtls client hello": "16fefd0000000000000000007e010000720000000000000072fefd668a43523798e064bd806d0c87660de9c611a59bbdfc3892c4e072d94f2cafc40000000cc02bc02fc00ac014c02cc0300100003c000d0010000e0403050306030401050106010807ff01000100000a00080006001d00170018000b00020100000e000900060008000700010000170000",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			packet, err := hex.DecodeString(packetHex)
			require.NoError(t, err)
			var metadata adapter.InboundContext
			err = sniff.DouyinPCDN(t.Context(), &metadata, packet)
			require.Error(t, err)
		})
	}
}
