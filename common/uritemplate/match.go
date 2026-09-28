package uritemplate

import (
	"net/url"
	"regexp"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// Matcher extracts variables from URIs produced by expanding a template, as
// described in RFC 6570 Section 1.4. Only string values are considered, so
// templates must be level 3 or lower and only use simple string expansion,
// form-style query expansion and form-style query continuation.
type Matcher struct {
	pattern *regexp.Regexp
	groups  []matchGroup
}

type matchGroup struct {
	name     string
	operator Operator
	// first is set for the first varspec of an expression.
	first bool
}

// Characters that may appear in an expanded value: pchar without the
// separators of simple and form-style expansions. Stricter than pchar so
// that expressions do not overlap; looser than the unreserved set so that
// values sent without the percent-encoding required by RFC 6570, such as "*"
// in the examples of RFC 9484, are accepted.
const valuePattern = `[A-Za-z0-9\-._~%!$'()*+;:@]*`

func NewMatcher(template *Template) (*Matcher, error) {
	if template.Level() > 3 {
		return nil, E.New("template must be level 3 or lower")
	}
	matcher := &Matcher{}
	var pattern strings.Builder
	pattern.WriteString("^")
	for _, part := range template.parts {
		if part.Expression == nil {
			pattern.WriteString(regexp.QuoteMeta(part.Literal))
			continue
		}
		operator := part.Expression.Operator
		switch operator {
		case OperatorSimple, OperatorQuery, OperatorContinue:
		default:
			return nil, E.New("unsupported expression operator: ", string(rune(operator)))
		}
		for i, varSpec := range part.Expression.VarSpecs {
			matcher.groups = append(matcher.groups, matchGroup{name: varSpec.Name, operator: operator, first: i == 0})
			switch {
			case operator == OperatorSimple && i == 0:
				pattern.WriteString("(" + valuePattern + ")")
			case operator == OperatorSimple:
				pattern.WriteString("(?:,(" + valuePattern + "))?")
			default:
				pattern.WriteString("(?:[?&]" + regexp.QuoteMeta(varSpec.Name) + "=(" + valuePattern + "))?")
			}
		}
	}
	pattern.WriteString("$")
	var err error
	matcher.pattern, err = regexp.Compile(pattern.String())
	if err != nil {
		return nil, err
	}
	return matcher, nil
}

// MatchURL matches the path and query of a request URL. See Match.
func (m *Matcher) MatchURL(requestURL *url.URL) (map[string]string, bool, error) {
	requestURI := requestURL.EscapedPath()
	if requestURL.RawQuery != "" || requestURL.ForceQuery {
		requestURI += "?" + requestURL.RawQuery
	}
	return m.Match(requestURI)
}

// Match returns the percent-decoded values of the defined variables. The
// boolean result reports whether uri is an expansion of the template; the
// error reports a value that cannot be decoded, or a variable that appears
// more than once with different values.
func (m *Matcher) Match(uri string) (map[string]string, bool, error) {
	match := m.pattern.FindStringSubmatchIndex(uri)
	if match == nil {
		return nil, false, nil
	}
	values := make(map[string]string)
	var formStarted bool
	for i, group := range m.groups {
		start, end := match[2*i+2], match[2*i+3]
		if group.first {
			formStarted = false
		}
		if start == -1 {
			continue
		}
		if group.operator == OperatorQuery || group.operator == OperatorContinue {
			// The first defined variable of a form-style expression is
			// prefixed by the operator, subsequent ones by "&".
			expected := byte('&')
			if !formStarted {
				expected = byte(group.operator)
			}
			if uri[start-len(group.name)-2] != expected {
				return nil, false, nil
			}
			formStarted = true
		}
		value, err := url.PathUnescape(uri[start:end])
		if err != nil {
			return nil, true, E.Cause(err, "decode ", group.name)
		}
		if previous, loaded := values[group.name]; loaded && previous != value {
			return nil, true, E.New("conflicting values for ", group.name)
		}
		values[group.name] = value
	}
	return values, true, nil
}
