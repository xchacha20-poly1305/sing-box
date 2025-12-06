//go:build !linux

package congestioncontrol

import (
	"os"
	"runtime"
	"syscall"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
)

// CongestionControl sets the TCP congestion control algorithm for the connection.
func CongestionControl(algorithm string) control.Func {
	return func(network, address string, conn syscall.RawConn) error {
		return E.Cause(os.ErrInvalid, "congestion control can't be set on ", runtime.GOOS)
	}
}
