package uritemplate

import (
	"strings"
	"unicode/utf8"

	E "github.com/sagernet/sing/common/exceptions"
)

// Value is a variable value (RFC 6570 Section 2.3): String, List or
// AssociativeArray.
type Value interface {
	defined() bool
}

type String string

// List is undefined if it contains zero members.
type List []string

type Pair struct {
	Name  string
	Value string
}

// AssociativeArray is undefined if it contains zero members.
type AssociativeArray []Pair

func (String) defined() bool {
	return true
}

func (l List) defined() bool {
	return len(l) > 0
}

func (a AssociativeArray) defined() bool {
	return len(a) > 0
}

// Values maps variable names to their values. A missing or nil value is
// undefined.
type Values map[string]Value

// Expand performs template expansion as defined in RFC 6570 Section 3.
func (t *Template) Expand(values Values) (string, error) {
	var result strings.Builder
	for _, part := range t.parts {
		if part.Expression == nil {
			expandLiteral(&result, part.Literal)
			continue
		}
		err := part.Expression.expand(&result, values)
		if err != nil {
			return "", err
		}
	}
	return result.String(), nil
}

func (e *Expression) expand(result *strings.Builder, values Values) error {
	behavior := e.Operator.behavior()
	first := true
	for _, varSpec := range e.VarSpecs {
		value := values[varSpec.Name]
		if value == nil || !value.defined() {
			continue
		}
		if first {
			result.WriteString(behavior.first)
			first = false
		} else {
			result.WriteString(behavior.separator)
		}
		switch value := value.(type) {
		case String:
			if behavior.named {
				expandLiteral(result, varSpec.Name)
				if value == "" {
					result.WriteString(behavior.ifEmpty)
					continue
				}
				result.WriteByte('=')
			}
			content := string(value)
			if varSpec.MaxLength > 0 {
				content = prefix(content, varSpec.MaxLength, behavior.allowReserved)
			}
			encode(result, content, behavior.allowReserved)
		case List:
			if varSpec.MaxLength > 0 {
				return E.New("prefix modifier applied to composite value: ", varSpec.Name)
			}
			if !varSpec.Explode {
				if behavior.named {
					expandLiteral(result, varSpec.Name)
					result.WriteByte('=')
				}
				for i, member := range value {
					if i > 0 {
						result.WriteByte(',')
					}
					encode(result, member, behavior.allowReserved)
				}
				continue
			}
			for i, member := range value {
				if i > 0 {
					result.WriteString(behavior.separator)
				}
				if behavior.named {
					expandLiteral(result, varSpec.Name)
					if member == "" {
						result.WriteString(behavior.ifEmpty)
						continue
					}
					result.WriteByte('=')
				}
				encode(result, member, behavior.allowReserved)
			}
		case AssociativeArray:
			if varSpec.MaxLength > 0 {
				return E.New("prefix modifier applied to composite value: ", varSpec.Name)
			}
			if !varSpec.Explode {
				if behavior.named {
					expandLiteral(result, varSpec.Name)
					result.WriteByte('=')
				}
				for i, pair := range value {
					if i > 0 {
						result.WriteByte(',')
					}
					encode(result, pair.Name, behavior.allowReserved)
					result.WriteByte(',')
					encode(result, pair.Value, behavior.allowReserved)
				}
				continue
			}
			for i, pair := range value {
				if i > 0 {
					result.WriteString(behavior.separator)
				}
				// Both name and value strings are encoded in the same way as
				// simple string values (RFC 6570 Section 3.2.1).
				encode(result, pair.Name, behavior.allowReserved)
				if pair.Value == "" {
					result.WriteString(behavior.ifEmpty)
					continue
				}
				result.WriteByte('=')
				encode(result, pair.Value, behavior.allowReserved)
			}
		default:
			return E.New("unsupported value type for variable: ", varSpec.Name)
		}
	}
	return nil
}

// prefix returns the first maxLength characters of value, counting each
// Unicode code point, or each pct-encoded triplet when it is passed through,
// as one character (RFC 6570 Section 2.4.1).
func prefix(value string, maxLength int, allowReserved bool) string {
	var i int
	for count := 0; i < len(value) && count < maxLength; count++ {
		if allowReserved && isPercentEncoded(value[i:]) {
			i += 3
			continue
		}
		_, size := utf8.DecodeRuneInString(value[i:])
		i += size
	}
	return value[:i]
}

// expandLiteral copies characters allowed in a URI and pct-encodes the rest
// as UTF-8 octets (RFC 6570 Section 3.1).
func expandLiteral(result *strings.Builder, literal string) {
	for i := 0; i < len(literal); {
		if isPercentEncoded(literal[i:]) {
			result.WriteString(literal[i : i+3])
			i += 3
			continue
		}
		character := literal[i]
		if isUnreserved(character) || isReserved(character) {
			result.WriteByte(character)
		} else {
			writePercentEncoded(result, character)
		}
		i++
	}
}

// encode pct-encodes every octet of value outside the allowed set: U, or
// U+R when allowReserved is set (RFC 6570 Section 3.2.1).
func encode(result *strings.Builder, value string, allowReserved bool) {
	for i := 0; i < len(value); i++ {
		character := value[i]
		switch {
		case isUnreserved(character):
			result.WriteByte(character)
		case allowReserved && isReserved(character):
			result.WriteByte(character)
		case allowReserved && isPercentEncoded(value[i:]):
			result.WriteString(value[i : i+3])
			i += 2
		default:
			writePercentEncoded(result, character)
		}
	}
}

func writePercentEncoded(result *strings.Builder, character byte) {
	const hex = "0123456789ABCDEF"
	result.WriteByte('%')
	result.WriteByte(hex[character>>4])
	result.WriteByte(hex[character&0x0F])
}

// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
func isUnreserved(character byte) bool {
	return isAlpha(character) || isDigit(character) || character == '-' || character == '.' || character == '_' || character == '~'
}

// reserved = gen-delims / sub-delims
func isReserved(character byte) bool {
	return strings.IndexByte(":/?#[]@!$&'()*+,;=", character) != -1
}
