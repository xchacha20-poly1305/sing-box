//go:build with_ebpf && (linux || android)

package adapter

import (
	"sync/atomic"
	"syscall"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
)

var socketProtectFunc atomic.Pointer[control.Func]

func SocketProtectFunc(networkManager NetworkManager) control.Func {
	if networkManager == nil {
		return nil
	}
	return func(network string, address string, conn syscall.RawConn) error {
		protectFunc := socketProtectFunc.Load()
		if protectFunc == nil {
			return nil
		}
		return (*protectFunc)(network, address, conn)
	}
}

func RegisterSocketProtectFunc(networkManager NetworkManager, protectFunc control.Func) error {
	if networkManager == nil {
		return E.New("network manager is nil")
	}
	if protectFunc == nil {
		return E.New("socket protect function is nil")
	}
	if !socketProtectFunc.CompareAndSwap(nil, &protectFunc) {
		return E.New("a socket protect function is already registered")
	}
	return nil
}

func UnregisterSocketProtectFunc(networkManager NetworkManager) {
	if networkManager == nil {
		return
	}
	socketProtectFunc.Store(nil)
}
