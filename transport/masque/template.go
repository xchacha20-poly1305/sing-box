package masque

import (
	"net/netip"
	"net/url"
	"regexp"
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
	pattern  *regexp.Regexp
	groups   []matchGroup
}

type matchGroup struct {
	name     string
	operator uritemplate.Operator
	// first is set for the first varspec of a form-style expression.
	first bool
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
	for _, character := range []byte(path) {
		if character < 0x21 || character > 0x7E {
			return nil, E.New("path contains invalid characters: ", path)
		}
	}
	if !strings.HasPrefix(path, "/") {
		return nil, E.New("path must start with a slash: ", path)
	}
	template, err := uritemplate.Parse(path)
	if err != nil {
		return nil, E.Cause(err, "parse URI template: ", path)
	}
	if template.Level() > 3 {
		return nil, E.New("URI template must be level 3 or lower: ", path)
	}
	for _, part := range template.Parts() {
		if part.Expression == nil {
			if strings.Contains(part.Literal, "#") {
				return nil, E.New("path must not contain a fragment: ", path)
			}
			continue
		}
		switch part.Expression.Operator {
		case uritemplate.OperatorSimple, uritemplate.OperatorQuery, uritemplate.OperatorContinue:
		default:
			return nil, E.New("unsupported expression operator in path: ", path)
		}
	}
	t := &Template{template: template}
	err = t.compile()
	if err != nil {
		return nil, E.Cause(err, "compile path: ", path)
	}
	return t, nil
}

// Characters that may appear in an expanded value: pchar without the
// separators of simple and form-style expansions. Stricter than pchar so
// that expressions do not overlap; looser than the unreserved set so that
// clients sending "*" unencoded, as in the examples of RFC 9484, are
// accepted.
const valuePattern = `[A-Za-z0-9\-._~%!$'()*+;:@]*`

// compile builds a pattern matching the expansions of the template. Only
// string values are considered since RFC 9484 templates are level 3 or
// lower.
func (t *Template) compile() error {
	var pattern strings.Builder
	pattern.WriteString("^")
	for _, part := range t.template.Parts() {
		if part.Expression == nil {
			pattern.WriteString(regexp.QuoteMeta(part.Literal))
			continue
		}
		operator := part.Expression.Operator
		for i, varSpec := range part.Expression.VarSpecs {
			group := matchGroup{name: varSpec.Name, operator: operator, first: i == 0}
			t.groups = append(t.groups, group)
			switch {
			case operator == uritemplate.OperatorSimple && i == 0:
				pattern.WriteString("(" + valuePattern + ")")
			case operator == uritemplate.OperatorSimple:
				pattern.WriteString("(?:,(" + valuePattern + "))?")
			default:
				pattern.WriteString("(?:[?&]" + regexp.QuoteMeta(varSpec.Name) + "=(" + valuePattern + "))?")
			}
		}
	}
	pattern.WriteString("$")
	var err error
	t.pattern, err = regexp.Compile(pattern.String())
	return err
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
	requestURI := requestURL.EscapedPath()
	if requestURL.RawQuery != "" || requestURL.ForceQuery {
		requestURI += "?" + requestURL.RawQuery
	}
	match := t.pattern.FindStringSubmatchIndex(requestURI)
	if match == nil {
		return Scope{}, false, nil
	}
	values := make(map[string]string)
	var formStarted bool
	for i, group := range t.groups {
		start, end := match[2*i+2], match[2*i+3]
		if group.first {
			formStarted = false
		}
		if start == -1 {
			continue
		}
		if group.operator == uritemplate.OperatorQuery || group.operator == uritemplate.OperatorContinue {
			// The first defined variable of a form-style expression is
			// prefixed by the operator, subsequent ones by "&".
			expected := byte('&')
			if !formStarted {
				expected = byte(group.operator)
			}
			if requestURI[start-len(group.name)-2] != expected {
				return Scope{}, false, nil
			}
			formStarted = true
		}
		value, err := url.PathUnescape(requestURI[start:end])
		if err != nil {
			return Scope{}, true, E.Cause(err, "decode ", group.name)
		}
		if previous, loaded := values[group.name]; loaded && previous != value {
			return Scope{}, true, E.New("conflicting values for ", group.name)
		}
		values[group.name] = value
	}
	var scope Scope
	if target, loaded := values[variableTarget]; loaded {
		err := scope.parseTarget(target)
		if err != nil {
			return Scope{}, true, err
		}
	}
	if protocol, loaded := values[variableIPProto]; loaded {
		err := scope.parseProtocol(protocol)
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
	for _, character := range []byte(target) {
		if !isRegName(character) {
			return E.New("invalid target: ", target)
		}
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

// reg-name = *( unreserved / pct-encoded / sub-delims ), checked after
// percent-decoding so octets from pct-encoded triplets are accepted when they
// are not ASCII.
func isRegName(character byte) bool {
	switch {
	case character >= 0x80:
		return true
	case character >= 'A' && character <= 'Z', character >= 'a' && character <= 'z', character >= '0' && character <= '9':
		return true
	}
	return strings.IndexByte("-._~!$&'()*+,;=", character) != -1
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
