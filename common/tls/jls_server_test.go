//go:build with_utls

package tls

import (
	"context"
	stdTLS "crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

func TestJLSServerFallback(t *testing.T) {
	privateKey, certificate, err := GenerateCertificate(nil, nil, time.Now, "localhost", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	keyPair, err := stdTLS.X509KeyPair(certificate, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	fallbackListener, err := net.Listen(N.NetworkTCP, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fallbackListener.Close()
	fallbackAddress := fallbackListener.Addr().(*net.TCPAddr)

	config, err := NewJLSServer(context.Background(), logger.NOP(), option.InboundTLSOptions{
		Enabled:     true,
		Certificate: strings.Split(strings.TrimSpace(string(certificate)), "\n"),
		Key:         strings.Split(strings.TrimSpace(string(privateKey)), "\n"),
		JLS: &option.InboundJLSOptions{
			Enabled: true,
			Users:   []auth.User{{Username: "user", Password: "password"}},
			Fallback: option.InboundJLSFallbackOptions{ServerOptions: option.ServerOptions{
				Server:     fallbackAddress.IP.String(),
				ServerPort: uint16(fallbackAddress.Port),
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	fallbackDone := make(chan error, 1)
	go func() {
		conn, acceptErr := fallbackListener.Accept()
		if acceptErr != nil {
			fallbackDone <- acceptErr
			return
		}
		defer conn.Close()
		fallbackDone <- stdTLS.Server(conn, &stdTLS.Config{Certificates: []stdTLS.Certificate{keyPair}}).Handshake()
	}()

	clientConn, serverConn := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	_ = clientConn.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)
	serverDone := make(chan error, 1)
	go func() {
		_, handshakeErr := config.(ServerConfigCompat).ServerHandshake(context.Background(), serverConn)
		serverDone <- handshakeErr
	}()

	client := stdTLS.Client(clientConn, &stdTLS.Config{ServerName: "localhost", InsecureSkipVerify: true}) //nolint:gosec
	if err = client.Handshake(); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if err = <-fallbackDone; err != nil {
		t.Fatal(err)
	}
	if err = <-serverDone; !errors.Is(err, errFallbackCompleted) {
		t.Fatalf("expected fallback completion, got %v", err)
	}
}
