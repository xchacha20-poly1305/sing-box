package http

import (
	std_bufio "bufio"
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/uritemplate"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	connectUDPProtocol = "connect-udp"
	// DefaultUDPPath is the default template of RFC 9298 Section 2.
	DefaultUDPPath = "/.well-known/masque/udp/{target_host}/{target_port}/"

	variableTargetHost = "target_host"
	variableTargetPort = "target_port"
)

var defaultUDPTemplate = common.Must1(ParseUDPTemplate(""))

// UDPTemplate is the path and query of the URI Template of a UDP proxying
// resource (RFC 9298 Section 2).
type UDPTemplate struct {
	template *uritemplate.Template
	matcher  *uritemplate.Matcher
}

func ParseUDPTemplate(path string) (*UDPTemplate, error) {
	if path == "" {
		path = DefaultUDPPath
	}
	template, err := uritemplate.ParseProxyPath(path)
	if err != nil {
		return nil, err
	}
	variables := template.VarNames()
	if !slices.Contains(variables, variableTargetHost) || !slices.Contains(variables, variableTargetPort) {
		return nil, E.New("URI template must contain the target_host and target_port variables: ", path)
	}
	matcher, err := uritemplate.NewMatcher(template)
	if err != nil {
		return nil, E.Cause(err, "compile path: ", path)
	}
	return &UDPTemplate{template: template, matcher: matcher}, nil
}

// Expand performs URI Template expansion for the target (RFC 9298 Section
// 3). Other variables are left undefined.
func (t *UDPTemplate) Expand(destination M.Socksaddr) (*url.URL, error) {
	expanded, err := t.template.Expand(uritemplate.Values{
		variableTargetHost: uritemplate.String(destination.AddrString()),
		variableTargetPort: uritemplate.String(strconv.Itoa(int(destination.Port))),
	})
	if err != nil {
		return nil, err
	}
	requestURL, err := url.ParseRequestURI(expanded)
	if err != nil {
		return nil, E.Cause(err, "parse expanded path")
	}
	return &url.URL{Path: requestURL.Path, RawPath: requestURL.RawPath, RawQuery: requestURL.RawQuery}, nil
}

// Match extracts the target from the URI of a UDP proxying request (RFC 9298
// Section 3.1). The boolean result reports whether the URI is an expansion of
// the template; the error reports a malformed request.
func (t *UDPTemplate) Match(requestURL *url.URL) (M.Socksaddr, bool, error) {
	values, matched, err := t.matcher.MatchURL(requestURL)
	if !matched || err != nil {
		return M.Socksaddr{}, matched, err
	}
	host, hostLoaded := values[variableTargetHost]
	port, portLoaded := values[variableTargetPort]
	if !hostLoaded || host == "" {
		return M.Socksaddr{}, true, E.New("missing target_host")
	}
	if !portLoaded || port == "" {
		return M.Socksaddr{}, true, E.New("missing target_port")
	}
	destination, err := parseUDPTarget(host, port)
	if err != nil {
		return M.Socksaddr{}, true, err
	}
	return destination, true, nil
}

// parseUDPTarget validates the decoded variables (RFC 9298 Section 3):
//
//	target_host = IPv6address / IPv4address / reg-name
//	target_port = port
func parseUDPTarget(host string, port string) (M.Socksaddr, error) {
	// port = *DIGIT, between 1 and 65535 inclusive
	if strings.Trim(port, "0123456789") != "" {
		return M.Socksaddr{}, E.New("invalid target_port: ", port)
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return M.Socksaddr{}, E.New("invalid target_port: ", port)
	}
	if strings.Contains(host, ":") {
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is6() {
			return M.Socksaddr{}, E.New("invalid target_host: ", host)
		}
		if address.Zone() != "" {
			return M.Socksaddr{}, E.New("zone identifiers are not supported: ", host)
		}
		return M.SocksaddrFrom(address, uint16(portNumber)), nil
	}
	address, err := netip.ParseAddr(host)
	if err == nil && address.Is4() {
		return M.SocksaddrFrom(address, uint16(portNumber)), nil
	}
	// A host that does not match IPv4address is a reg-name (RFC 3986
	// Section 3.2.2).
	if !uritemplate.IsRegName(host) {
		return M.Socksaddr{}, E.New("invalid target_host: ", host)
	}
	return M.Socksaddr{Fqdn: host, Port: uint16(portNumber)}, nil
}

func requestIsConnectUDP(request *http.Request) bool {
	return request.Method == http.MethodGet && requestIsUpgrade(request) && strings.EqualFold(request.Header.Get("Upgrade"), connectUDPProtocol)
}

func (c *serverConn) serveConnectUDP(ctx context.Context, request *http.Request, source M.Socksaddr) (requestResult, error) {
	if !request.ProtoAtLeast(1, 1) {
		return c.reject(request, requestKeepAlive(request), http.StatusBadRequest, nil, E.New("invalid connect-udp request: ", request.Proto))
	}
	destination, matched, err := c.server.udpTemplate.Match(request.URL)
	if !matched {
		return c.reject(request, requestKeepAlive(request), http.StatusNotFound, nil, E.New("unexpected connect-udp path: ", request.URL.Path))
	}
	if err != nil {
		return c.reject(request, requestKeepAlive(request), http.StatusBadRequest, nil, E.Cause(err, "invalid connect-udp request"))
	}
	_, err = c.conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n"))
	if err != nil {
		return requestClose, E.Cause(err, "write response")
	}
	c.handler.NewPacketConnectionEx(ctx, newCapsuleConn(c.reader.Reader, c.conn, destination), source, destination, c.onClose)
	return requestHandedOff, nil
}

func (h *httpHandler) serveConnectUDP(ctx context.Context, writer http.ResponseWriter, request *http.Request, source M.Socksaddr) {
	destination, matched, err := h.server.udpTemplate.Match(request.URL)
	if !matched {
		h.server.logger.ErrorContext(ctx, "process connection from ", source, ": unexpected connect-udp path: ", request.URL.Path)
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		h.server.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", source, ": invalid connect-udp request"))
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	writer.Header().Set("Capsule-Protocol", "?1")
	writer.WriteHeader(http.StatusOK)
	writer.(http.Flusher).Flush()
	if request.ProtoMajor == 3 && HTTP3StreamFunc != nil {
		stream, isDatagramStream := HTTP3StreamFunc(request.Context(), writer)
		if isDatagramStream {
			localAddr, _ := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
			conn := newHTTP3PacketConn(stream, destination, localAddr)
			h.handler.NewPacketConnectionEx(ctx, conn, source, destination, nil)
			conn.wait(request.Context())
			return
		}
	}
	conn := v2rayhttp.NewHTTP2Wrapper(&v2rayhttp.ServerHTTPConn{
		HTTP2Conn: v2rayhttp.NewHTTPConn(request.Body, writer),
		Flusher:   writer.(http.Flusher),
	})
	done := make(chan struct{})
	h.handler.NewPacketConnectionEx(ctx, newCapsuleConn(std_bufio.NewReader(conn), conn, destination), source, destination, N.OnceClose(func(it error) {
		close(done)
	}))
	<-done
	conn.CloseWrapper()
}
