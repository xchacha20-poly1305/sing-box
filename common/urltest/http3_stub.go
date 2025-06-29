//go:build !with_quic

package urltest

import (
	"crypto/tls"
	"net"
	"net/http"

	C "github.com/sagernet/sing-box/constant"
)

func http3Transport(conn net.Conn, tlsConfig *tls.Config) http.RoundTripper {
	panic(C.ErrQUICNotIncluded)
}
