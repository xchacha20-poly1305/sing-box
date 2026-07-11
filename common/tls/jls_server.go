//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"maps"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"

	utls "github.com/metacubex/utls"
)

var (
	errFallbackCompleted = E.New("jls: connection relayed to fallback")
)

var _ ServerConfigCompat = (*JLSServerConfig)(nil)

type JLSServerConfig struct {
	ctx                 context.Context
	config              *utls.Config
	handshakeTimeout    time.Duration
	rejectUnknownSNI    bool
	serverNames         map[string]bool
	fallbackDialer      N.Dialer
	fallbackDestination M.Socksaddr
	logger              log.ContextLogger
}

func NewJLSServer(ctx context.Context, logger log.ContextLogger, options option.InboundTLSOptions) (ServerConfig, error) {
	if options.ServerName != "" && len(options.ServerNames) > 0 {
		return nil, E.New("server_name and server_names cannot be configured at the same time")
	}
	if options.CertificateProvider != nil {
		return nil, E.New("certificate_provider is unavailable in JLS")
	}
	//nolint:staticcheck
	if options.ACME != nil && len(options.ACME.Domain) > 0 {
		return nil, E.New("acme is unavailable in JLS")
	}
	if options.ECH != nil && options.ECH.Enabled {
		return nil, E.New("JLS is conflict with ECH")
	}
	if options.Insecure {
		return nil, E.New("insecure is unavailable in JLS server")
	}
	if options.ClientAuthentication != 0 || len(options.ClientCertificate) > 0 || len(options.ClientCertificatePath) > 0 || len(options.ClientCertificatePublicKeySHA256) > 0 {
		return nil, E.New("client authentication is unavailable in JLS")
	}
	if len(options.JLS.Users) == 0 {
		return nil, E.New("missing JLS users")
	}

	var tlsConfig utls.Config
	tlsConfig.Time = ntp.TimeFuncFromContext(ctx)
	tlsConfig.ServerName = options.ServerName
	tlsConfig.NextProtos = append(tlsConfig.NextProtos, options.ALPN...)
	tlsConfig.MinVersion = utls.VersionTLS13
	tlsConfig.MaxVersion = utls.VersionTLS13
	if options.MinVersion != "" {
		minVersion, err := ParseTLSVersion(options.MinVersion)
		if err != nil {
			return nil, E.Cause(err, "parse min_version")
		}
		if minVersion > utls.VersionTLS13 {
			return nil, E.New("JLS requires TLS 1.3")
		}
	}
	if options.MaxVersion != "" {
		maxVersion, err := ParseTLSVersion(options.MaxVersion)
		if err != nil {
			return nil, E.Cause(err, "parse max_version")
		}
		if maxVersion < utls.VersionTLS13 {
			return nil, E.New("JLS requires TLS 1.3")
		}
	}
	if options.CipherSuites != nil {
	find:
		for _, cipherSuite := range options.CipherSuites {
			for _, tlsCipherSuite := range tls.CipherSuites() {
				if cipherSuite == tlsCipherSuite.Name {
					tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, tlsCipherSuite.ID)
					continue find
				}
			}
			return nil, E.New("unknown cipher_suite: ", cipherSuite)
		}
	}
	for _, curveID := range options.CurvePreferences {
		tlsConfig.CurvePreferences = append(tlsConfig.CurvePreferences, utls.CurveID(curveID))
	}

	var certificate, key []byte
	if len(options.Certificate) > 0 {
		certificate = []byte(strings.Join(options.Certificate, "\n"))
	} else if options.CertificatePath != "" {
		content, err := os.ReadFile(options.CertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read certificate")
		}
		certificate = content
	}
	if len(options.Key) > 0 {
		key = []byte(strings.Join(options.Key, "\n"))
	} else if options.KeyPath != "" {
		content, err := os.ReadFile(options.KeyPath)
		if err != nil {
			return nil, E.Cause(err, "read key")
		}
		key = content
	}
	if certificate == nil {
		return nil, E.New("missing certificate")
	}
	if key == nil {
		return nil, E.New("missing key")
	}
	keyPair, err := utls.X509KeyPair(certificate, key)
	if err != nil {
		return nil, E.Cause(err, "parse x509 key pair")
	}
	tlsConfig.Certificates = []utls.Certificate{keyPair}

	tlsConfig.JLSConfig = &utls.JLSConfig{
		Enable: true,
		Users: common.Map(options.JLS.Users, func(it auth.User) utls.JLSUser {
			return (utls.JLSUser)(it)
		}),
	}
	if options.ServerName != "" {
		tlsConfig.JLSConfig.ServerName = options.ServerName
	}
	serverNames := make(map[string]bool)
	if options.ServerName != "" {
		serverNames[options.ServerName] = true
	}
	for _, name := range options.ServerNames {
		if name != "" {
			serverNames[name] = true
		}
	}
	var fallbackDialer N.Dialer
	fallback := options.JLS.Fallback.ServerOptions.Build()
	if fallback.IsValid() {
		fallbackDialer, err = dialer.New(ctx, options.JLS.Fallback.DialerOptions, options.JLS.Fallback.ServerIsDomain())
		if err != nil {
			return nil, E.Cause(err, "create JLS fallback dialer")
		}
	} else if options.JLS.Fallback.Server != "" || options.JLS.Fallback.ServerPort != 0 {
		return nil, E.New("invalid JLS fallback server")
	}
	handshakeTimeout := C.TCPTimeout
	if options.HandshakeTimeout > 0 {
		handshakeTimeout = options.HandshakeTimeout.Build()
	}
	var config ServerConfig = &JLSServerConfig{
		ctx:                 ctx,
		config:              &tlsConfig,
		handshakeTimeout:    handshakeTimeout,
		rejectUnknownSNI:    options.RejectUnknownSNI,
		serverNames:         serverNames,
		fallbackDialer:      fallbackDialer,
		fallbackDestination: fallback,
		logger:              logger,
	}
	if options.KernelTx || options.KernelRx {
		if !C.IsLinux {
			return nil, E.New("kTLS is only supported on Linux")
		}
		config = &KTlSServerConfig{ServerConfig: config, logger: logger, kernelTx: options.KernelTx, kernelRx: options.KernelRx}
	}
	return config, nil
}

func (c *JLSServerConfig) ServerName() string {
	return c.config.ServerName
}

func (c *JLSServerConfig) SetServerName(serverName string) {
	c.config.ServerName = serverName
	c.config.JLSConfig.ServerName = serverName
}

func (c *JLSServerConfig) NextProtos() []string {
	return c.config.NextProtos
}

func (c *JLSServerConfig) SetNextProtos(nextProtos []string) {
	c.config.NextProtos = nextProtos
}

func (c *JLSServerConfig) HandshakeTimeout() time.Duration {
	return c.handshakeTimeout
}

func (c *JLSServerConfig) SetHandshakeTimeout(timeout time.Duration) {
	c.handshakeTimeout = timeout
}

func (c *JLSServerConfig) STDConfig() (*tls.Config, error) {
	return nil, E.New("unsupported usage for JLS")
}

func (c *JLSServerConfig) Client(conn net.Conn) (Conn, error) {
	return ClientHandshake(context.Background(), conn, c)
}

func (c *JLSServerConfig) Start() error {
	return nil
}

func (c *JLSServerConfig) Close() error {
	return nil
}

func (c *JLSServerConfig) Server(conn net.Conn) (Conn, error) {
	return ServerHandshake(context.Background(), conn, c)
}

func (c *JLSServerConfig) ServerHandshake(ctx context.Context, conn net.Conn) (Conn, error) {
	recorder := &handshakeRecorderConn{Conn: conn, recording: true}
	tlsConn := utls.Server(recorder, c.config.Clone())
	err := tlsConn.HandshakeContext(ctx)
	if err != nil {
		// A partial or complete server flight may have been written before a later
		// client message or network error; forwarding would then mix two TLS handshakes.
		if c.fallbackDialer != nil && !recorder.wroteToClient() {
			return nil, c.fallbackConnection(ctx, conn, recorder.stopRecording(), err)
		}
		recorder.discard()
		return nil, err
	}
	recorder.discard()
	// Defensively reject a successful TLS handshake if custom configuration bypassed JLS authentication.
	if tlsConn.ConnectionState().JLS.Status != utls.JLSAuthenticated {
		return nil, utls.ErrJLSAuthFailed
	}
	if c.rejectUnknownSNI {
		sni := tlsConn.ConnectionState().ServerName
		if len(c.serverNames) > 0 {
			if sni == "" || !c.serverNames[sni] {
				_ = tlsConn.Close()
				return nil, E.New("unknown or missing server name")
			}
		} else if sni != "" {
			_ = tlsConn.Close()
			return nil, E.New("unknown server name: no server names configured")
		}
	}
	return &realityConnWrapper{Conn: tlsConn}, nil
}

func (c *JLSServerConfig) fallbackConnection(ctx context.Context, conn net.Conn, received []byte, handshakeErr error) error {
	fallbackConn, err := c.fallbackDialer.DialContext(ctx, N.NetworkTCP, c.fallbackDestination)
	if err != nil {
		return E.Cause(err, "dial JLS fallback after handshake failure: ", handshakeErr)
	}
	c.logger.DebugContext(ctx, "JLS handshake failed, relaying connection to ", c.fallbackDestination, ": ", handshakeErr)
	cachedConn := bufio.NewCachedConn(conn, buf.As(received))
	err = bufio.CopyConn(ctx, cachedConn, fallbackConn)
	if err != nil {
		c.logger.DebugContext(ctx, "JLS fallback relay closed: ", err)
	}
	return errFallbackCompleted
}

func (c *JLSServerConfig) Clone() Config {
	config := c.config.Clone()
	jlsConfig := *config.JLSConfig
	config.JLSConfig = &jlsConfig
	return &JLSServerConfig{
		ctx:                 c.ctx,
		config:              config,
		handshakeTimeout:    c.handshakeTimeout,
		rejectUnknownSNI:    c.rejectUnknownSNI,
		serverNames:         maps.Clone(c.serverNames),
		fallbackDialer:      c.fallbackDialer,
		fallbackDestination: c.fallbackDestination,
		logger:              c.logger,
	}
}

type handshakeRecorderConn struct {
	net.Conn
	buffer    bytes.Buffer
	recording bool
	wrote     bool
}

func (c *handshakeRecorderConn) Upstream() any {
	return c.Conn
}

func (c *handshakeRecorderConn) ReaderReplaceable() bool {
	return !c.recording
}

func (c *handshakeRecorderConn) WriterReplaceable() bool {
	return !c.recording
}

func (c *handshakeRecorderConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.recording && n > 0 {
		_, _ = c.buffer.Write(p[:n])
	}
	return n, err
}

func (c *handshakeRecorderConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if c.recording && n > 0 {
		c.wrote = true
	}
	return n, err
}

func (c *handshakeRecorderConn) stopRecording() []byte {
	c.recording = false
	data := c.buffer.Bytes()
	// Transfer ownership of the backing slice to the fallback path. Recording is
	// disabled before detaching, so the recorder cannot append to or reuse it.
	c.buffer = bytes.Buffer{}
	return data
}

func (c *handshakeRecorderConn) discard() {
	c.recording = false
	c.buffer = bytes.Buffer{}
}

func (c *handshakeRecorderConn) wroteToClient() bool {
	return c.wrote
}
