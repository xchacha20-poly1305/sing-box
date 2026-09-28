//go:build with_quic

package http

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func startLoopbackHTTP3Server(t *testing.T, udpPath string) loopbackServer {
	t.Helper()
	udpTemplate, err := ParseUDPTemplate(udpPath)
	require.NoError(t, err)
	server := NewServer(ServerOptions{
		Logger:      logger.NOP(),
		UDP:         true,
		UDPTemplate: udpTemplate,
	})
	handler := &loopbackHandler{requests: make(chan M.Socksaddr, 1)}
	http3Server, err := server.ListenHTTP3(context.Background(), logger.NOP(), listener.New(listener.Options{
		Context: context.Background(),
		Logger:  logger.NOP(),
	}), handler, newLoopbackTLSServer(t), option.QUICOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		http3Server.Close()
	})
	address := http3Server.(interface{ Addr() net.Addr }).Addr()
	return loopbackServer{address: M.SocksaddrFromNet(address), requests: handler.requests}
}

func TestConnectUDPLoopbackHTTP3(t *testing.T) {
	t.Parallel()
	for _, udpPath := range loopbackUDPPaths {
		t.Run(udpPath, func(t *testing.T) {
			t.Parallel()
			server := startLoopbackHTTP3Server(t, udpPath)
			testLoopbackUDP(t, server, newLoopbackClient(t, server.address, 3, udpPath))
			testLoopbackMismatch(t, server, 3)
		})
	}
}
