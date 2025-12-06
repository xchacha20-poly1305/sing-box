package congestioncontrol

import (
	"strings"
	"syscall"

	"github.com/sagernet/sing/common/control"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

// CongestionControl sets the TCP congestion control algorithm for the connection.
func CongestionControl(algorithm string) control.Func {
	return func(network, address string, conn syscall.RawConn) error {
		if !strings.HasPrefix(network, N.NetworkTCP) {
			return nil
		}
		return control.Raw(conn, func(fd uintptr) error {
			return unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, algorithm)
		})
	}
}
