package urltest

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/observable"
)

var _ adapter.URLTestHistoryStorage = (*HistoryStorage)(nil)

type HistoryStorage struct {
	access       sync.RWMutex
	delayHistory map[string]*adapter.URLTestHistory
	updateHook   *observable.Subscriber[struct{}]
}

func NewHistoryStorage() *HistoryStorage {
	return &HistoryStorage{
		delayHistory: make(map[string]*adapter.URLTestHistory),
	}
}

func (s *HistoryStorage) SetHook(hook *observable.Subscriber[struct{}]) {
	s.updateHook = hook
}

func (s *HistoryStorage) LoadURLTestHistory(tag string) *adapter.URLTestHistory {
	if s == nil {
		return nil
	}
	s.access.RLock()
	defer s.access.RUnlock()
	return s.delayHistory[tag]
}

func (s *HistoryStorage) DeleteURLTestHistory(tag string) {
	s.access.Lock()
	delete(s.delayHistory, tag)
	s.notifyUpdated()
	s.access.Unlock()
}

func (s *HistoryStorage) StoreURLTestHistory(tag string, history *adapter.URLTestHistory) {
	s.access.Lock()
	s.delayHistory[tag] = history
	s.notifyUpdated()
	s.access.Unlock()
}

func (s *HistoryStorage) notifyUpdated() {
	updateHook := s.updateHook
	if updateHook != nil {
		updateHook.Emit(struct{}{})
	}
}

func (s *HistoryStorage) Close() error {
	s.access.Lock()
	defer s.access.Unlock()
	s.updateHook = nil
	return nil
}

func URLTest(ctx context.Context, link string, detour N.Dialer) (t uint16, err error) {
	if link == "" {
		link = "https://www.gstatic.com/generate_204"
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return
	}
	hostname := linkURL.Hostname()
	var isH3 bool
	port := linkURL.Port()
	switch linkURL.Scheme {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		if port == "" {
			port = "443"
		}
	case "h3", "http3", "quic":
		if !C.WithQUIC {
			err = C.ErrQUICNotIncluded
			return
		}
		if port == "" {
			port = "443"
		}
		isH3 = true
		linkURL.Scheme = "https"
		link = linkURL.String()
	}

	start := time.Now()
	var network string
	if isH3 {
		network = N.NetworkUDP
	} else {
		network = N.NetworkTCP
	}
	instance, err := detour.DialContext(ctx, network, M.ParseSocksaddrHostPortStr(hostname, port))
	if err != nil {
		return
	}
	defer instance.Close()
	if N.NeedHandshakeForWrite(instance) {
		start = time.Now()
	}
	req, err := http.NewRequest(http.MethodHead, link, nil)
	if err != nil {
		return
	}
	tlsConfig := &tls.Config{
		Time:    ntp.TimeFuncFromContext(ctx),
		RootCAs: adapter.RootPoolFromContext(ctx),
	}
	var transport http.RoundTripper
	if isH3 {
		transport = http3Transport(instance, tlsConfig)
	} else {
		transport = httpTransport(instance, tlsConfig)
	}
	var timeout time.Duration
	if isH3 {
		timeout = C.ProtocolTimeouts[C.ProtocolQUIC]
	} else {
		timeout = C.TCPTimeout
	}
	client := http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: timeout,
	}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return
	}
	resp.Body.Close()
	t = uint16(time.Since(start) / time.Millisecond)
	return
}

func httpTransport(conn net.Conn, tlsConfig *tls.Config) http.RoundTripper {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return conn, nil
		},
		TLSClientConfig: tlsConfig,
	}
}
