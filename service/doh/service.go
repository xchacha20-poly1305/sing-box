package doh

import (
	"context"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/doh"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	"github.com/sagernet/sing/service"

	"golang.org/x/net/http2"
)

func RegisterService(registry *boxService.Registry) {
	boxService.Register[option.DoHServiceOptions](registry, C.TypeDoH, NewService)
}

type Service struct {
	boxService.Adapter
	logger    log.ContextLogger
	listener  *listener.Listener
	tlsConfig tls.ServerConfig
	handler   http.Handler
}

func NewService(ctx context.Context, logger log.ContextLogger, tag string, options option.DoHServiceOptions) (adapter.Service, error) {
	path, err := doh.ResolvePath(options.Path)
	if err != nil {
		return nil, err
	}
	users := make(map[string]struct{}, len(options.Users))
	for i, user := range options.Users {
		if user.Username == "" || strings.Contains(user.Username, ":") || user.Password == "" {
			return nil, E.New("invalid credentials in users[", i, "]")
		}
		if _, loaded := users[user.Username]; loaded {
			return nil, E.New("duplicate username in users[", i, "]")
		}
		users[user.Username] = struct{}{}
	}

	queryHandler := doh.NewHandler(service.FromContext[adapter.DNSRouter](ctx), path, tag, C.TypeDoH)
	s := &Service{
		Adapter: boxService.NewAdapter(C.TypeDoH, tag),
		logger:  logger,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Network: []string{N.NetworkTCP},
			Listen:  options.ListenOptions,
		}),
		handler: queryHandler,
	}
	if authenticator := auth.NewAuthenticator(options.Users); authenticator != nil {
		s.handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if !queryHandler.Matches(request) {
				http.NotFound(writer, request)
				return
			}
			user, password, loaded := request.BasicAuth()
			if !loaded || !authenticator.Verify(user, password) {
				writer.Header().Set("WWW-Authenticate", `Basic realm="DoH"`)
				http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			ctx := auth.ContextWithUser(request.Context(), user)
			queryHandler.ServeHTTP(writer, request.WithContext(ctx))
		})
	}
	if options.TLS != nil {
		s.tlsConfig, err = tls.NewServer(ctx, logger, *options.TLS)
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStarted {
		return nil
	}
	ctx := scope.Context()
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	protocols.SetHTTP2(true)
	if s.tlsConfig != nil {
		err := s.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "start TLS config")
		}
		scope.Add(s.tlsConfig.Close)
		if !slices.Contains(s.tlsConfig.NextProtos(), http2.NextProtoTLS) {
			s.tlsConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, s.tlsConfig.NextProtos()...))
		}
		if !slices.Contains(s.tlsConfig.NextProtos(), "http/1.1") {
			s.tlsConfig.SetNextProtos(append(s.tlsConfig.NextProtos(), "http/1.1"))
		}
	}
	server := &http.Server{
		Handler:           s.handler,
		Protocols:         protocols,
		ReadHeaderTimeout: C.TCPConnectTimeout,
		ReadTimeout:       C.DNSTimeout,
		WriteTimeout:      2 * C.DNSTimeout,
		IdleTimeout:       time.Minute,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}
	tcpListener, err := s.listener.ListenTCP()
	if err != nil {
		return err
	}
	scope.Add(s.listener.Close)
	if s.tlsConfig != nil {
		tcpListener = aTLS.NewListener(tcpListener, s.tlsConfig)
	}
	scope.Add(server.Close)
	go func() {
		err := server.Serve(tcpListener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
			s.logger.Error("serve error: ", err)
		}
	}()
	return nil
}
