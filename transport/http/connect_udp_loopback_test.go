package http

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

var loopbackUDPPaths = []string{
	"",
	"/masque{?target_host,target_port}",
	"/masque?h={target_host}&p={target_port}",
}

var loopbackUDPTargets = []M.Socksaddr{
	M.ParseSocksaddrHostPort("192.0.2.1", 53),
	M.ParseSocksaddrHostPort("2001:db8::42", 5353),
	M.ParseSocksaddrHostPort("example.com", 443),
}

type loopbackServer struct {
	address  M.Socksaddr
	requests chan M.Socksaddr
}

// loopbackHandler echoes every packet back to its sender and reports the
// destination of each UDP proxying request.
type loopbackHandler struct {
	requests chan M.Socksaddr
}

func (h *loopbackHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	N.CloseOnHandshakeFailure(conn, onClose, nil)
}

func (h *loopbackHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.requests <- destination
	defer func() {
		conn.Close()
		if onClose != nil {
			onClose(nil)
		}
	}()
	for {
		buffer := buf.NewPacket()
		address, err := conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			return
		}
		err = conn.WritePacket(buffer, address)
		if err != nil {
			return
		}
	}
}

func newLoopbackCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
}

func newLoopbackTLSServer(t *testing.T) tls.ServerConfig {
	t.Helper()
	certificate, key := newLoopbackCertificate(t)
	tlsConfig, err := tls.NewServerWithOptions(tls.ServerOptions{
		Context: context.Background(),
		Logger:  logger.NOP(),
		Options: option.InboundTLSOptions{
			Enabled:     true,
			Certificate: []string{certificate},
			Key:         []string{key},
		},
	})
	require.NoError(t, err)
	require.NoError(t, tlsConfig.Start())
	t.Cleanup(func() {
		tlsConfig.Close()
	})
	return tlsConfig
}

// startLoopbackTCPServer serves HTTP/1.1, or HTTP/2 over TLS when tlsConfig
// is set.
func startLoopbackTCPServer(t *testing.T, udpPath string, tlsConfig tls.ServerConfig) loopbackServer {
	t.Helper()
	udpTemplate, err := ParseUDPTemplate(udpPath)
	require.NoError(t, err)
	server := NewServer(ServerOptions{
		Logger:      logger.NOP(),
		HTTP1:       tlsConfig == nil,
		HTTP2:       tlsConfig != nil,
		UDP:         true,
		UDPTemplate: udpTemplate,
	})
	if tlsConfig != nil {
		server.ConfigureTLS(tlsConfig)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		listener.Close()
	})
	handler := &loopbackHandler{requests: make(chan M.Socksaddr, 1)}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				ctx := context.Background()
				if tlsConfig != nil {
					tlsConn, err := tls.ServerHandshake(ctx, conn, tlsConfig)
					if err != nil {
						conn.Close()
						return
					}
					conn = tlsConn
				}
				server.ServeConnection(ctx, conn, NewReader(conn), handler, M.SocksaddrFromNet(conn.RemoteAddr()), nil)
			}()
		}
	}()
	return loopbackServer{address: M.SocksaddrFromNet(listener.Addr()), requests: handler.requests}
}

func newLoopbackClient(t *testing.T, server M.Socksaddr, version int, udpPath string) *Client {
	t.Helper()
	var (
		client *Client
		err    error
	)
	if version == 1 {
		client, err = NewClient(ClientOptions{
			Server:  server,
			UDPPath: udpPath,
			Version: 1,
		})
	} else {
		client, err = NewClientWithTLS(context.Background(), logger.NOP(), N.SystemDialer, option.ServerOptions{
			Server:     server.AddrString(),
			ServerPort: server.Port,
		}, option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "localhost",
			Insecure:   true,
		}, ClientOptions{
			UDPPath:                udpPath,
			Version:                version,
			DisableVersionFallback: true,
		})
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		client.Close()
	})
	return client
}

// testLoopbackUDP opens a UDP proxying request for each target, checks the
// target seen by the server and echoes a datagram through the tunnel.
func testLoopbackUDP(t *testing.T, server loopbackServer, client *Client) {
	t.Helper()
	for _, target := range loopbackUDPTargets {
		packetConn, err := client.listenPacket(context.Background(), target)
		require.NoError(t, err, target)
		select {
		case destination := <-server.requests:
			require.Equal(t, target, destination)
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for UDP proxying request to ", target)
		}
		payload := []byte("hello " + target.String())
		buffer := buf.As(payload)
		require.NoError(t, packetConn.WritePacket(buffer, target), target)
		type readResult struct {
			source M.Socksaddr
			data   []byte
			err    error
		}
		done := make(chan readResult, 1)
		go func() {
			response := buf.NewPacket()
			defer response.Release()
			source, err := packetConn.ReadPacket(response)
			done <- readResult{source, append([]byte(nil), response.Bytes()...), err}
		}()
		select {
		case result := <-done:
			require.NoError(t, result.err, target)
			require.Equal(t, target, result.source)
			require.Equal(t, payload, result.data, target)
		case <-time.After(5 * time.Second):
			packetConn.Close()
			t.Fatal("timeout waiting for echo from ", target)
		}
		packetConn.Close()
	}
}

// testLoopbackMismatch checks that a request outside the server template is
// rejected with 404.
func testLoopbackMismatch(t *testing.T, server loopbackServer, version int) {
	t.Helper()
	client := newLoopbackClient(t, server.address, version, "/other/{target_host}/{target_port}/")
	_, err := client.listenPacket(context.Background(), loopbackUDPTargets[0])
	require.ErrorContains(t, err, "404")
}

func TestConnectUDPLoopbackHTTP1(t *testing.T) {
	t.Parallel()
	for _, udpPath := range loopbackUDPPaths {
		t.Run(udpPath, func(t *testing.T) {
			t.Parallel()
			server := startLoopbackTCPServer(t, udpPath, nil)
			testLoopbackUDP(t, server, newLoopbackClient(t, server.address, 1, udpPath))
			testLoopbackMismatch(t, server, 1)
		})
	}
}

func TestConnectUDPLoopbackHTTP2(t *testing.T) {
	t.Parallel()
	if !extendedConnectAvailable {
		t.Skip("extended CONNECT is not available in this build")
	}
	for _, udpPath := range loopbackUDPPaths {
		t.Run(udpPath, func(t *testing.T) {
			t.Parallel()
			server := startLoopbackTCPServer(t, udpPath, newLoopbackTLSServer(t))
			testLoopbackUDP(t, server, newLoopbackClient(t, server.address, 2, udpPath))
			testLoopbackMismatch(t, server, 2)
		})
	}
}
