//go:build with_utls

package tls

import (
	"cmp"
	"context"
	"net"
	"time"

	tf "github.com/sagernet/sing-box/common/tlsfragment"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	aTLS "github.com/sagernet/sing/common/tls"

	utls "github.com/metacubex/utls"
)

var _ ConfigCompat = (*JLSClientConfig)(nil)

type JLSClientConfig struct {
	ctx     context.Context
	uClient *UTLSClientConfig
}

func NewJLSClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions) (Config, error) {
	return newJLSClient(ctx, logger, serverAddress, options, false)
}

func newJLSClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions, allowEmptyServerName bool) (Config, error) {
	if options.Reality != nil && options.Reality.Enabled {
		return nil, E.New("JLS is conflict with Reality")
	}
	if options.ECH != nil && options.ECH.Enabled {
		return nil, E.New("JLS is conflict with ECH")
	}
	if options.UTLS == nil {
		options.UTLS = &option.OutboundUTLSOptions{Enabled: true}
	}
	options.UTLS.Fingerprint = cmp.Or(options.UTLS.Fingerprint, "go")
	uClient, err := newUTLSClient(ctx, logger, serverAddress, options, allowEmptyServerName)
	if err != nil {
		return nil, err
	}
	uClientConfig := uClient.(*UTLSClientConfig)
	uClientConfig.config.JLSConfig = &utls.JLSConfig{
		Enable: true,
		User: utls.JLSUser{
			Username: options.JLS.IV,
			Password: options.JLS.Password,
		},
	}
	config := Config(&JLSClientConfig{
		ctx:     ctx,
		uClient: uClientConfig,
	})
	if options.KernelRx || options.KernelTx {
		if !C.IsLinux {
			return nil, E.New("kTLS is only supported on Linux")
		}
		config = &KTLSClientConfig{Config: config, logger: logger, kernelTx: options.KernelTx, kernelRx: options.KernelRx}
	}
	return config, nil
}

func (c *JLSClientConfig) ServerName() string {
	return c.uClient.ServerName()
}

func (c *JLSClientConfig) SetServerName(serverName string) {
	c.uClient.SetServerName(serverName)
}

func (c *JLSClientConfig) NextProtos() []string {
	return c.uClient.NextProtos()
}

func (c *JLSClientConfig) SetNextProtos(nextProto []string) {
	c.uClient.SetNextProtos(nextProto)
}

func (c *JLSClientConfig) HandshakeTimeout() time.Duration {
	return c.uClient.HandshakeTimeout()
}

func (c *JLSClientConfig) SetHandshakeTimeout(timeout time.Duration) {
	c.uClient.SetHandshakeTimeout(timeout)
}

func (c *JLSClientConfig) STDConfig() (*STDConfig, error) {
	return nil, E.New("unsupported usage for JLS")
}

func (c *JLSClientConfig) Client(conn net.Conn) (Conn, error) {
	return ClientHandshake(context.Background(), conn, c)
}

func (c *JLSClientConfig) ClientHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	if c.uClient.fragment || c.uClient.recordFragment {
		conn = tf.NewConn(conn, c.ctx, c.uClient.fragment, c.uClient.recordFragment, c.uClient.fragmentFallbackDelay)
	}
	conn, err := applyTLSSpoof(conn, c.uClient.spoof, c.uClient.spoofMethod)
	if err != nil {
		return nil, err
	}
	uConfig := c.uClient.config.Clone()
	uConn := utls.UClient(conn, uConfig, c.uClient.id)
	err = uConn.BuildHandshakeState()
	if err != nil {
		return nil, err
	}
	if len(uConfig.NextProtos) > 0 {
		for _, extension := range uConn.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = uConfig.NextProtos
				err := uConn.BuildHandshakeState()
				if err != nil {
					return nil, err
				}
				break
			}
		}
	}
	err = uConn.HandshakeContext(ctx)
	if err != nil {
		return nil, err
	}
	if uConn.ConnectionState().JLS.Status != utls.JLSAuthenticated {
		_ = uConn.Close()
		return nil, E.New("JLS authentication failed")
	}
	return &utlsConnWrapper{uConn}, nil
}

func (c *JLSClientConfig) Clone() Config {
	uClient := c.uClient.Clone().(*UTLSClientConfig)
	jlsConfig := *uClient.config.JLSConfig
	uClient.config.JLSConfig = &jlsConfig
	return &JLSClientConfig{ctx: c.ctx, uClient: uClient}
}
