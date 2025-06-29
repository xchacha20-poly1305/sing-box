//go:build with_quic

package urltest

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

func http3Transport(conn net.Conn, tlsConfig *tls.Config) http.RoundTripper {
	return &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: C.ProtocolTimeouts[C.ProtocolQUIC],
		},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialEarly(ctx, bufio.NewUnbindPacketConn(conn), M.ParseSocksaddr(addr), tlsCfg, cfg)
		},
	}
}
