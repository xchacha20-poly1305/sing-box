package masque

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/uritemplate"
	E "github.com/sagernet/sing/common/exceptions"
)

const DefaultPath = "/.well-known/masque/ip/{target}/{ipproto}/"

const (
	variableTarget  = "target"
	variableIPProto = "ipproto"
	wildcard        = "*"
)

// Template is the path and query of the URI Template of an IP proxying
// resource (RFC 9484 Section 3).
type Template struct {
	template *uritemplate.Template
	matcher  *uritemplate.Matcher
}

type Scope struct {
	Domain   string
	Prefix   netip.Prefix
	Protocol uint8
}

func ParseTemplate(path string) (*Template, error) {
	if path == "" {
		path = DefaultPath
	}
	template, err := uritemplate.ParseProxyPath(path)
	if err != nil {
		return nil, err
	}
	matcher, err := uritemplate.NewMatcher(template)
	if err != nil {
		return nil, E.Cause(err, "compile path: ", path)
	}
	return &Template{template: template, matcher: matcher}, nil
}

// Expand performs URI Template expansion for the request scope (RFC 9484
// Section 4). Unset scope fields are expanded as the wildcard "*"; other
// variables are left undefined.
func (t *Template) Expand(scope Scope) (string, error) {
	target := wildcard
	switch {
	case scope.Domain != "":
		target = scope.Domain
	case scope.Prefix.IsValid():
		if scope.Prefix.IsSingleIP() {
			target = scope.Prefix.Addr().String()
		} else {
			target = scope.Prefix.String()
		}
	}
	protocol := wildcard
	if scope.Protocol != 0 {
		protocol = strconv.Itoa(int(scope.Protocol))
	}
	return t.template.Expand(uritemplate.Values{
		variableTarget:  uritemplate.String(target),
		variableIPProto: uritemplate.String(protocol),
	})
}

// Match extracts the scope from the URI of an IP proxying request (RFC 9484
// Section 4.1). The boolean result reports whether the URI is an expansion of
// the template; the error reports a malformed request.
func (t *Template) Match(requestURL *url.URL) (Scope, bool, error) {
	values, matched, err := t.matcher.MatchURL(requestURL)
	if !matched || err != nil {
		return Scope{}, matched, err
	}
	var scope Scope
	if target, loaded := values[variableTarget]; loaded {
		err = scope.parseTarget(target)
		if err != nil {
			return Scope{}, true, err
		}
	}
	if protocol, loaded := values[variableIPProto]; loaded {
		err = scope.parseProtocol(protocol)
		if err != nil {
			return Scope{}, true, err
		}
	}
	return scope, true, nil
}

// parseTarget validates the decoded target variable (RFC 9484 Section 4.6):
//
//	target = IPv6prefix / IPv4prefix / reg-name / "*"
//	IPv6prefix = IPv6address ["%2F" 1*3DIGIT]
//	IPv4prefix = IPv4address ["%2F" 1*2DIGIT]
func (s *Scope) parseTarget(target string) error {
	switch target {
	case "":
		return E.New("empty target")
	case wildcard:
		return nil
	}
	address, prefixLength, hasPrefixLength := strings.Cut(target, "/")
	if strings.Contains(address, ":") {
		prefix, err := parsePrefix(address, prefixLength, hasPrefixLength, 3)
		if err != nil {
			return E.Cause(err, "invalid target: ", target)
		}
		if !prefix.Addr().Is6() {
			return E.New("invalid target: ", target)
		}
		s.Prefix = prefix
		return nil
	}
	prefix, err := parsePrefix(address, prefixLength, hasPrefixLength, 2)
	if err == nil && prefix.Addr().Is4() {
		s.Prefix = prefix
		return nil
	}
	if hasPrefixLength {
		return E.Cause(err, "invalid target: ", target)
	}
	// A host that does not match IPv4address is a reg-name (RFC 3986
	// Section 3.2.2).
	if !uritemplate.IsRegName(target) {
		return E.New("invalid target: ", target)
	}
	s.Domain = target
	return nil
}

func parsePrefix(address string, prefixLength string, hasPrefixLength bool, maxDigits int) (netip.Prefix, error) {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr.Zone() != "" {
		return netip.Prefix{}, E.New("zone identifiers are not supported")
	}
	bits := addr.BitLen()
	if hasPrefixLength {
		if prefixLength == "" || len(prefixLength) > maxDigits || strings.Trim(prefixLength, "0123456789") != "" {
			return netip.Prefix{}, E.New("invalid prefix length")
		}
		bits, _ = strconv.Atoi(prefixLength)
		if bits > addr.BitLen() {
			return netip.Prefix{}, E.New("prefix length out of range")
		}
	}
	prefix := netip.PrefixFrom(addr, bits)
	if prefix.Masked() != prefix {
		return netip.Prefix{}, E.New("prefix has host bits set")
	}
	return prefix, nil
}

// parseProtocol validates the decoded ipproto variable (RFC 9484 Section
// 4.6):
//
//	ipproto = 1*3DIGIT / "*"
func (s *Scope) parseProtocol(protocol string) error {
	switch protocol {
	case "":
		return E.New("empty ipproto")
	case wildcard:
		return nil
	}
	if len(protocol) > 3 || strings.Trim(protocol, "0123456789") != "" {
		return E.New("invalid ipproto: ", protocol)
	}
	protocolNumber, _ := strconv.Atoi(protocol)
	if protocolNumber > 255 {
		return E.New("invalid ipproto: ", protocol)
	}
	s.Protocol = uint8(protocolNumber)
	return nil
}
