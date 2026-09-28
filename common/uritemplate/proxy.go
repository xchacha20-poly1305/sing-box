package uritemplate

import (
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// ParseProxyPath parses the path and query of the URI Template of a UDP
// proxying resource (RFC 9298 Section 2) or an IP proxying resource (RFC 9484
// Section 3), and validates the requirements the two share.
func ParseProxyPath(path string) (*Template, error) {
	for _, character := range []byte(path) {
		if character < 0x21 || character > 0x7E {
			return nil, E.New("path contains invalid characters: ", path)
		}
	}
	if !strings.HasPrefix(path, "/") {
		return nil, E.New("path must start with a slash: ", path)
	}
	template, err := Parse(path)
	if err != nil {
		return nil, E.Cause(err, "parse URI template: ", path)
	}
	if template.Level() > 3 {
		return nil, E.New("URI template must be level 3 or lower: ", path)
	}
	for _, part := range template.parts {
		if part.Expression == nil {
			if strings.Contains(part.Literal, "#") {
				return nil, E.New("path must not contain a fragment: ", path)
			}
			continue
		}
		switch part.Expression.Operator {
		case OperatorSimple, OperatorQuery, OperatorContinue:
		default:
			return nil, E.New("unsupported expression operator in path: ", path)
		}
	}
	return template, nil
}

// IsRegName reports whether a percent-decoded host is a reg-name (RFC 3986
// Section 3.2.2):
//
//	reg-name = *( unreserved / pct-encoded / sub-delims )
//
// Octets from pct-encoded triplets are accepted when they are not ASCII.
func IsRegName(host string) bool {
	for i := 0; i < len(host); i++ {
		character := host[i]
		if character >= 0x80 || isUnreserved(character) || strings.IndexByte("!$&'()*+,;=", character) != -1 {
			continue
		}
		return false
	}
	return true
}
