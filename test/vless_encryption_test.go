//go:build with_utls

package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

const (
	vlessTestHostname = "vless.test"
	vlessTestShortID  = "0123456789abcdef"
	vlessTestVision   = "xtls-rprx-vision"
)

type vlessEncryptionTarget struct {
	name, url  string
	tlsVersion uint16
}

type vlessEncryptionFixture struct {
	user                      string
	caPath, certPath, keyPath string
	tlsCertHash               string
	realityTarget             M.Socksaddr
	realityPrivateKey         string
	realityPublicKey          string
	roots                     *x509.CertPool
	payload                   []byte
	targets                   []vlessEncryptionTarget
	targetPorts               string
}

type vlessEncryptionCase struct {
	encryption, decryption string
	flow, security         string
	xrayClient             bool
}

func sha256hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestVLESSEncryptionXray(t *testing.T) {
	t.Log(ImageXRayCoreVLESS)
	runVLESSEncryptionMatrix(t, func(t *testing.T, f vlessEncryptionFixture, name string, c vlessEncryptionCase) {
		for _, direction := range []string{"sing-box-to-xray", "xray-to-sing-box"} {
			testCase := c
			testCase.xrayClient = direction == "xray-to-sing-box"
			t.Run(name+"/"+direction, func(t *testing.T) {
				t.Parallel()
				f.runXrayCase(t, testCase)
			})
		}
	})
}

func TestVLESSEncryptionSelf(t *testing.T) {
	runVLESSEncryptionMatrix(t, func(t *testing.T, f vlessEncryptionFixture, name string, c vlessEncryptionCase) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			socksAddress := f.startSelfProxies(t, c)
			for _, target := range f.targets {
				t.Run(target.name, func(t *testing.T) {
					require.NoError(t, f.checkTraffic(t, socksAddress, target))
				})
			}
		})
	})
}

func runVLESSEncryptionMatrix(t *testing.T, run func(*testing.T, vlessEncryptionFixture, string, vlessEncryptionCase)) {
	t.Helper()

	caPath, certPath, keyPath := createSelfSignedCertificate(t, vlessTestHostname)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	caPEM, err := os.ReadFile(caPath)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM))
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlkem768, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	realityKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	user, err := uuid.NewV4()
	require.NoError(t, err)

	// Separate connections negotiate the exact destination TLS version.
	payload := bytes.Repeat([]byte("VLESS encryption interoperability\n"), 4096)
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(len(payload))))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, _ = w.Write(body)
	})
	plain := httptest.NewServer(echo)
	t.Cleanup(plain.Close)
	tls12 := httptest.NewUnstartedServer(echo)
	tls12.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}
	tls12.StartTLS()
	t.Cleanup(tls12.Close)
	tls13 := httptest.NewUnstartedServer(echo)
	tls13.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	tls13.StartTLS()
	t.Cleanup(tls13.Close)
	realityTarget := httptest.NewUnstartedServer(http.NotFoundHandler())
	realityTarget.TLS = tls13.TLS.Clone()
	realityTarget.EnableHTTP2 = true
	realityTarget.StartTLS()
	t.Cleanup(realityTarget.Close)

	encode := base64.RawURLEncoding.EncodeToString
	fixture := vlessEncryptionFixture{
		user: user.String(), caPath: caPath, certPath: certPath, keyPath: keyPath,
		tlsCertHash:       sha256hex(cert.Certificate[0]),
		realityTarget:     M.ParseSocksaddr(realityTarget.Listener.Addr().String()),
		realityPrivateKey: encode(realityKey.Bytes()),
		realityPublicKey:  encode(realityKey.PublicKey().Bytes()),
		roots:             roots, payload: payload,
		targets: []vlessEncryptionTarget{
			{"plain", plain.URL, 0},
			{"tls12", tls12.URL, tls.VersionTLS12},
			{"tls13", tls13.URL, tls.VersionTLS13},
		},
		targetPorts: fmt.Sprintf("%d,%d,%d", plain.Listener.Addr().(*net.TCPAddr).Port,
			tls12.Listener.Addr().(*net.TCPAddr).Port, tls13.Listener.Addr().(*net.TCPAddr).Port),
	}
	for _, key := range []struct {
		name, private, public string
	}{
		{"x25519", encode(x25519.Bytes()), encode(x25519.PublicKey().Bytes())},
		{"mlkem768", encode(mlkem768.Bytes()), encode(mlkem768.EncapsulationKey().Bytes())},
	} {
		for _, xorMode := range []string{"native", "xorpub", "random"} {
			for _, padding := range []struct{ name, value string }{
				{"default-padding", ""},
				{"custom-padding", "100-80-120.100-1-2.100-50-100."},
			} {
				for _, flow := range []struct{ name, value string }{{"no-flow", ""}, {"vision", vlessTestVision}} {
					for _, security := range []string{"none", "tls", "reality"} {
						name := strings.Join([]string{key.name, xorMode, padding.name, flow.name, security}, "/")
						run(t, fixture, name, vlessEncryptionCase{
							encryption: "mlkem768x25519plus." + xorMode + ".0rtt." + padding.value + key.public,
							decryption: "mlkem768x25519plus." + xorMode + ".600s." + padding.value + key.private,
							flow:       flow.value,
							security:   security,
						})
					}
				}
			}
		}
	}
}

func (f vlessEncryptionFixture) startSelfProxies(t *testing.T, c vlessEncryptionCase) M.Socksaddr {
	t.Helper()
	for range 3 {
		clientListener, serverListener := reserveVLESSTestListener(t), reserveVLESSTestListener(t)
		socksAddress := M.SocksaddrFromNet(clientListener.Addr())
		vlessAddress := M.SocksaddrFromNet(serverListener.Addr())
		server, err := startVLESSTestBox(t, f.singBoxServerOptions(c, vlessAddress), serverListener)
		if errors.Is(err, syscall.EADDRINUSE) {
			require.NoError(t, clientListener.Close())
			continue
		}
		require.NoError(t, err)
		client, err := startVLESSTestBox(t, f.singBoxClientOptions(c, socksAddress, vlessAddress), clientListener)
		if err != nil {
			require.NoError(t, server.Close())
			if errors.Is(err, syscall.EADDRINUSE) {
				continue
			}
		}
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, errors.Join(client.Close(), server.Close()))
		})
		return socksAddress
	}
	t.Fatal("could not acquire sing-box listen ports after three attempts")
	return M.Socksaddr{}
}

func (f vlessEncryptionFixture) runXrayCase(t *testing.T, c vlessEncryptionCase) {
	dir := t.TempDir()
	singBoxLog := filepath.Join(dir, "sing-box.log")
	t.Cleanup(func() {
		if t.Failed() {
			if log, err := os.ReadFile(singBoxLog); err == nil {
				t.Logf("sing-box log:\n%s", log)
			}
		}
	})
	socksAddress, xrayLogs := f.startXrayProxies(t, c, filepath.Join(dir, "xray.json"), singBoxLog)

	// Xray v26.11.9 requires the X25519MLKEM768 share that sing-box removes.
	expectRealityRejection := !c.xrayClient && c.security == "reality"
	const failureMessage = "authentication failed or validation criteria not met"
	for _, target := range f.targets {
		t.Run(target.name, func(t *testing.T) {
			if !expectRealityRejection {
				require.NoError(t, f.checkTraffic(t, socksAddress, target))
				return
			}
			message := []byte(failureMessage)
			before, err := xrayLogs(t.Context())
			require.NoError(t, err)
			require.Error(t, f.checkTraffic(t, socksAddress, target))
			require.Eventually(t, func() bool {
				log, err := xrayLogs(t.Context())
				return err == nil && bytes.Count(log, message) > bytes.Count(before, message)
			}, 15*time.Second, 100*time.Millisecond, "missing rejection in Xray: %s", failureMessage)
			t.Logf("Observed rejection in Xray: %s", failureMessage)
		})
	}
}

func (f vlessEncryptionFixture) startXrayProxies(t *testing.T, c vlessEncryptionCase, xrayConfig, singBoxLog string) (M.Socksaddr, func(context.Context) ([]byte, error)) {
	t.Helper()
	for range 3 {
		socksListener, vlessListener := reserveVLESSTestListener(t), reserveVLESSTestListener(t)
		socksAddress := M.SocksaddrFromNet(socksListener.Addr())
		vlessAddress := M.SocksaddrFromNet(vlessListener.Addr())
		config, err := json.MarshalIndent(f.xrayOptions(c, socksAddress, vlessAddress), "", "  ")
		require.NoError(t, err)
		// The official image runs as a non-root user. The fixture directory
		// is private on the host, and the file is mounted read-only.
		require.NoError(t, os.WriteFile(xrayConfig, config, 0o644))
		binds := map[string]string{xrayConfig: "/xray-test.json:ro"}
		if c.security == "tls" && !c.xrayClient {
			binds[f.certPath] = "/xray-test-cert.pem:ro"
			binds[f.keyPath] = "/xray-test-key.pem:ro"
		}
		dockerClient, containerID, stopXray := createDockerContainer(t, DockerOptions{
			Image: ImageXRayCoreVLESS, Cmd: []string{"run", "-config", "/xray-test.json"}, Bind: binds,
		})
		xrayLogs := func(ctx context.Context) ([]byte, error) {
			return readDockerLogs(ctx, dockerClient, containerID)
		}
		t.Cleanup(func() {
			if t.Failed() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if log, err := xrayLogs(ctx); err == nil {
					t.Logf("Xray log:\n%s", log)
				}
			}
		})

		xrayListener, singBoxListener := vlessListener, socksListener
		if c.xrayClient {
			xrayListener, singBoxListener = socksListener, vlessListener
		}
		require.NoError(t, xrayListener.Close())
		if !startVLESSXray(t, dockerClient, containerID) {
			stopXray()
			_ = singBoxListener.Close()
			t.Log("Retrying after Xray's listen port was taken")
			continue
		}
		var options option.Options
		if c.xrayClient {
			options = f.singBoxServerOptions(c, vlessAddress)
		} else {
			options = f.singBoxClientOptions(c, socksAddress, vlessAddress)
		}
		options.Log = &option.LogOptions{Level: "debug", Output: singBoxLog}
		instance, err := startVLESSTestBox(t, options, singBoxListener)
		if errors.Is(err, syscall.EADDRINUSE) {
			stopXray()
			continue
		}
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, instance.Close()) })
		return socksAddress, xrayLogs
	}
	t.Fatal("could not acquire proxy listen ports after three attempts")
	return M.Socksaddr{}, nil
}

func startVLESSXray(t *testing.T, dockerClient *client.Client, containerID string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	require.NoError(t, dockerClient.ContainerStart(ctx, containerID, container.StartOptions{}))
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, err := dockerClient.ContainerInspect(ctx, containerID)
		require.NoError(t, err)
		output, err := readDockerLogs(ctx, dockerClient, containerID)
		require.NoError(t, err)
		if !state.State.Running {
			if bytes.Contains(output, []byte("address already in use")) {
				return false
			}
			t.Fatalf("Xray exited during startup (code %d): %s", state.State.ExitCode, output)
		}
		if bytes.Contains(output, []byte("] core: Xray ")) && bytes.Contains(output, []byte(" started\n")) {
			return true
		}
		select {
		case <-ctx.Done():
			t.Fatal("Xray did not finish starting")
		case <-ticker.C:
		}
	}
}

func reserveVLESSTestListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func startVLESSTestBox(t *testing.T, options option.Options, listener net.Listener) (*box.Box, error) {
	t.Helper()
	if options.Log == nil {
		options.Log = &option.LogOptions{Level: "warning"}
	}
	// Each instance registers its own services.
	instance, err := box.New(box.Options{Context: include.Context(t.Context()), Options: options})
	if err != nil {
		return nil, err
	}
	if err = listener.Close(); err != nil {
		return nil, errors.Join(err, instance.Close())
	}
	err = instance.Start()
	if errors.Is(err, syscall.EADDRINUSE) {
		t.Log("Retrying after sing-box's listen port was taken")
	}
	return instance, err
}

func (f vlessEncryptionFixture) singBoxServerOptions(c vlessEncryptionCase, vlessAddress M.Socksaddr) option.Options {
	vlessListen := option.ListenOptions{Listen: common.Ptr(badoption.Addr(vlessAddress.Addr)), ListenPort: vlessAddress.Port}
	var inboundTLS *option.InboundTLSOptions
	switch c.security {
	case "tls":
		inboundTLS = &option.InboundTLSOptions{
			Enabled:         true,
			MinVersion:      "1.3",
			CertificatePath: f.certPath,
			KeyPath:         f.keyPath,
		}
	case "reality":
		inboundTLS = &option.InboundTLSOptions{
			Enabled: true, ServerName: vlessTestHostname,
			Reality: &option.InboundRealityOptions{
				Enabled:    true,
				PrivateKey: f.realityPrivateKey,
				ShortID:    []string{vlessTestShortID},
				Handshake: option.InboundRealityHandshakeOptions{
					ServerOptions: option.ServerOptions{
						Server:     f.realityTarget.Addr.String(),
						ServerPort: f.realityTarget.Port,
					},
				},
			},
		}
	}
	return option.Options{
		Inbounds: []option.Inbound{{Type: C.TypeVLESS, Options: &option.VLESSInboundOptions{
			ListenOptions:              vlessListen,
			Decryption:                 c.decryption,
			Users:                      []option.VLESSUser{{UUID: f.user, Flow: c.flow}},
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: inboundTLS},
		}}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
	}
}

func (f vlessEncryptionFixture) singBoxClientOptions(c vlessEncryptionCase, socksAddress, vlessAddress M.Socksaddr) option.Options {
	vlessServer := option.ServerOptions{Server: vlessAddress.Addr.String(), ServerPort: vlessAddress.Port}
	var outboundTLS *option.OutboundTLSOptions
	switch c.security {
	case "tls":
		outboundTLS = &option.OutboundTLSOptions{
			Enabled:         true,
			ServerName:      vlessTestHostname,
			MinVersion:      "1.3",
			CertificatePath: f.caPath,
		}
	case "reality":
		outboundTLS = &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: vlessTestHostname,
			UTLS: &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: "chrome",
			},
			Reality: &option.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: f.realityPublicKey,
				ShortID:   vlessTestShortID,
			},
		}
	}
	return option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeMixed,
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(socksAddress.Addr)),
						ListenPort: socksAddress.Port},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeVLESS,
				Options: &option.VLESSOutboundOptions{
					ServerOptions:               vlessServer,
					UUID:                        f.user,
					Flow:                        c.flow,
					Encryption:                  c.encryption,
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: outboundTLS},
				},
			},
		},
	}
}

func (f vlessEncryptionFixture) xrayOptions(c vlessEncryptionCase, socksAddress, vlessAddress M.Socksaddr) any {
	stream := map[string]any{"security": c.security}
	switch c.security {
	case "tls":
		tlsSettings := map[string]any{"minVersion": "1.3"}
		if c.xrayClient {
			tlsSettings["serverName"] = vlessTestHostname
			tlsSettings["pinnedPeerCertSha256"] = f.tlsCertHash
		} else {
			tlsSettings["certificates"] = []any{
				map[string]string{
					"certificateFile": "/xray-test-cert.pem",
					"keyFile":         "/xray-test-key.pem",
				},
			}
		}
		stream["tlsSettings"] = tlsSettings
	case "reality":
		if c.xrayClient {
			stream["realitySettings"] = map[string]any{
				"serverName":  vlessTestHostname,
				"fingerprint": "chrome",
				"password":    f.realityPublicKey,
				"shortId":     vlessTestShortID,
			}
		} else {
			stream["realitySettings"] = map[string]any{
				"target":      f.realityTarget.String(),
				"serverNames": []string{vlessTestHostname},
				"privateKey":  f.realityPrivateKey,
				"shortIds":    []string{vlessTestShortID},
			}
		}
	}
	var inbound, outbound map[string]any
	if c.xrayClient {
		inbound = map[string]any{
			"protocol": "socks",
			"listen":   socksAddress.Addr.String(),
			"port":     socksAddress.Port,
		}
		outbound = map[string]any{
			"protocol":       "vless",
			"streamSettings": stream,
			"settings": map[string]any{
				"address":    vlessAddress.Addr.String(),
				"port":       vlessAddress.Port,
				"id":         f.user,
				"flow":       c.flow,
				"encryption": c.encryption,
			},
		}
	} else {
		inbound = map[string]any{
			"protocol":       "vless",
			"listen":         vlessAddress.Addr.String(),
			"port":           vlessAddress.Port,
			"streamSettings": stream,
			"settings": map[string]any{
				"decryption": c.decryption,
				"clients": []any{
					map[string]string{
						"id":   f.user,
						"flow": c.flow,
					},
				},
			},
		}
		// Xray's freedom outbound blocks private destinations by default.
		outbound = map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{
				"finalRules": []any{
					map[string]any{
						"action":  "allow",
						"network": "tcp",
						"ip":      []string{"127.0.0.1/32"},
						"port":    f.targetPorts,
					},
				},
			},
		}
	}
	return map[string]any{
		"log":      map[string]string{"loglevel": "debug"},
		"inbounds": []any{inbound}, "outbounds": []any{outbound},
	}
}

func (f vlessEncryptionFixture) checkTraffic(t *testing.T, socksAddress M.Socksaddr, target vlessEncryptionTarget) error {
	t.Helper()
	dialer := socks.NewClient(N.SystemDialer, socksAddress, socks.Version5, "", "")
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
		},
		TLSClientConfig: &tls.Config{
			ServerName: vlessTestHostname,
			RootCAs:    f.roots,
			MinVersion: target.tlsVersion,
			MaxVersion: target.tlsVersion,
		},
		DisableKeepAlives: true,
	}
	t.Cleanup(transport.CloseIdleConnections)
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target.url, bytes.NewReader(f.payload))
	require.NoError(t, err)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	if target.tlsVersion != 0 {
		require.NotNil(t, resp.TLS)
		require.Equal(t, target.tlsVersion, resp.TLS.Version)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(len(f.payload))+1))
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256(f.payload), sha256.Sum256(body))
	return nil
}
