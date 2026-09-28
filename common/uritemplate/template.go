// Package uritemplate implements URI Templates as defined in RFC 6570.
//
// The parser accepts the full Level 4 syntax so that unsupported levels can be
// identified by callers (RFC 6570 Section 2).
package uritemplate

import (
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	E "github.com/sagernet/sing/common/exceptions"
)

// Operator is the expression type (RFC 6570 Section 2.2). The zero value is
// simple string expansion.
type Operator byte

const (
	OperatorSimple    Operator = 0
	OperatorReserved  Operator = '+'
	OperatorFragment  Operator = '#'
	OperatorLabel     Operator = '.'
	OperatorPath      Operator = '/'
	OperatorParameter Operator = ';'
	OperatorQuery     Operator = '?'
	OperatorContinue  Operator = '&'
)

type operatorBehavior struct {
	first         string
	separator     string
	named         bool
	ifEmpty       string
	allowReserved bool
}

// Value table from RFC 6570 Appendix A.
func (o Operator) behavior() operatorBehavior {
	switch o {
	case OperatorReserved:
		return operatorBehavior{"", ",", false, "", true}
	case OperatorFragment:
		return operatorBehavior{"#", ",", false, "", true}
	case OperatorLabel:
		return operatorBehavior{".", ".", false, "", false}
	case OperatorPath:
		return operatorBehavior{"/", "/", false, "", false}
	case OperatorParameter:
		return operatorBehavior{";", ";", true, "", false}
	case OperatorQuery:
		return operatorBehavior{"?", "&", true, "=", false}
	case OperatorContinue:
		return operatorBehavior{"&", "&", true, "=", false}
	default:
		return operatorBehavior{"", ",", false, "", false}
	}
}

// VarSpec is a variable specifier (RFC 6570 Section 2.3 and 2.4).
type VarSpec struct {
	Name string
	// MaxLength is the prefix modifier, zero if absent.
	MaxLength int
	Explode   bool
}

type Expression struct {
	Operator Operator
	VarSpecs []VarSpec
}

// Part is either a literal or an expression.
type Part struct {
	Literal    string
	Expression *Expression
}

type Template struct {
	raw   string
	parts []Part
}

func MustParse(template string) *Template {
	t, err := Parse(template)
	if err != nil {
		panic(err)
	}
	return t
}

func Parse(template string) (*Template, error) {
	t := &Template{raw: template}
	var literal strings.Builder
	for i := 0; i < len(template); {
		switch template[i] {
		case '{':
			closing := strings.IndexByte(template[i+1:], '}')
			if closing == -1 {
				return nil, E.New("unterminated expression at offset ", i)
			}
			expression, err := parseExpression(template[i+1 : i+1+closing])
			if err != nil {
				return nil, E.Cause(err, "invalid expression at offset ", i)
			}
			if literal.Len() > 0 {
				t.parts = append(t.parts, Part{Literal: literal.String()})
				literal.Reset()
			}
			t.parts = append(t.parts, Part{Expression: expression})
			i += closing + 2
		case '%':
			if !isPercentEncoded(template[i:]) {
				return nil, E.New("invalid percent-encoding at offset ", i)
			}
			literal.WriteString(template[i : i+3])
			i += 3
		default:
			r, size := utf8.DecodeRuneInString(template[i:])
			if r == utf8.RuneError && size <= 1 || !isLiteral(r) {
				return nil, E.New("invalid literal character at offset ", i)
			}
			literal.WriteString(template[i : i+size])
			i += size
		}
	}
	if literal.Len() > 0 {
		t.parts = append(t.parts, Part{Literal: literal.String()})
	}
	return t, nil
}

func parseExpression(body string) (*Expression, error) {
	if body == "" {
		return nil, E.New("empty expression")
	}
	expression := &Expression{}
	switch body[0] {
	case '+', '#', '.', '/', ';', '?', '&':
		expression.Operator = Operator(body[0])
		body = body[1:]
	case '=', ',', '!', '@', '|':
		return nil, E.New("reserved operator: ", body[:1])
	}
	for _, specification := range strings.Split(body, ",") {
		varSpec, err := parseVarSpec(specification)
		if err != nil {
			return nil, err
		}
		expression.VarSpecs = append(expression.VarSpecs, varSpec)
	}
	return expression, nil
}

func parseVarSpec(specification string) (VarSpec, error) {
	var varSpec VarSpec
	name := specification
	if strings.HasSuffix(specification, "*") {
		varSpec.Explode = true
		name = specification[:len(specification)-1]
	} else if index := strings.IndexByte(specification, ':'); index != -1 {
		name = specification[:index]
		// max-length = %x31-39 0*3DIGIT
		maxLength := specification[index+1:]
		if maxLength == "" || len(maxLength) > 4 || maxLength[0] < '1' || maxLength[0] > '9' || !isDigits(maxLength) {
			return VarSpec{}, E.New("invalid prefix modifier: ", specification)
		}
		varSpec.MaxLength, _ = strconv.Atoi(maxLength)
	}
	if !isVarName(name) {
		return VarSpec{}, E.New("invalid variable name: ", specification)
	}
	varSpec.Name = name
	return varSpec, nil
}

// varname = varchar *( ["."] varchar )
// varchar = ALPHA / DIGIT / "_" / pct-encoded
func isVarName(name string) bool {
	if name == "" {
		return false
	}
	previousDot := true
	for i := 0; i < len(name); {
		character := name[i]
		switch {
		case character == '.':
			if previousDot {
				return false
			}
			previousDot = true
			i++
			continue
		case character == '%':
			if !isPercentEncoded(name[i:]) {
				return false
			}
			i += 3
		case isAlpha(character) || isDigit(character) || character == '_':
			i++
		default:
			return false
		}
		previousDot = false
	}
	return !previousDot
}

// literals = %x21 / %x23-24 / %x26 / %x28-3B / %x3D / %x3F-5B
//
//	/  %x5D / %x5F / %x61-7A / %x7E / ucschar / iprivate
//	/  pct-encoded
func isLiteral(r rune) bool {
	switch {
	case r == 0x21, r >= 0x23 && r <= 0x24, r == 0x26, r >= 0x28 && r <= 0x3B, r == 0x3D,
		r >= 0x3F && r <= 0x5B, r == 0x5D, r == 0x5F, r >= 0x61 && r <= 0x7A, r == 0x7E:
		return true
	}
	return isUCSChar(r) || isIPrivate(r)
}

// ucschar from RFC 3987
func isUCSChar(r rune) bool {
	switch {
	case r >= 0xA0 && r <= 0xD7FF, r >= 0xF900 && r <= 0xFDCF, r >= 0xFDF0 && r <= 0xFFEF:
		return true
	case r >= 0x10000 && r <= 0xEFFFD:
		return r&0xFFFF <= 0xFFFD && (r < 0xE0000 || r >= 0xE1000)
	}
	return false
}

// iprivate from RFC 3987
func isIPrivate(r rune) bool {
	return r >= 0xE000 && r <= 0xF8FF || r >= 0xF0000 && r <= 0xFFFFD || r >= 0x100000 && r <= 0x10FFFD
}

func (t *Template) String() string {
	return t.raw
}

func (t *Template) Parts() []Part {
	return t.parts
}

// Level returns the lowest template level (RFC 6570 Section 1.2) that
// covers every expression in the template.
func (t *Template) Level() int {
	level := 1
	for _, part := range t.parts {
		if part.Expression == nil {
			continue
		}
		level = max(level, part.Expression.level())
	}
	return level
}

func (e *Expression) level() int {
	for _, varSpec := range e.VarSpecs {
		if varSpec.MaxLength > 0 || varSpec.Explode {
			return 4
		}
	}
	switch e.Operator {
	case OperatorLabel, OperatorPath, OperatorParameter, OperatorQuery, OperatorContinue:
		return 3
	}
	if len(e.VarSpecs) > 1 {
		return 3
	}
	if e.Operator != OperatorSimple {
		return 2
	}
	return 1
}

// VarNames returns the distinct variable names in order of appearance.
func (t *Template) VarNames() []string {
	var names []string
	for _, part := range t.parts {
		if part.Expression == nil {
			continue
		}
		for _, varSpec := range part.Expression.VarSpecs {
			if !slices.Contains(names, varSpec.Name) {
				names = append(names, varSpec.Name)
			}
		}
	}
	return names
}

func isAlpha(character byte) bool {
	return character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z'
}

func isDigit(character byte) bool {
	return character >= '0' && character <= '9'
}

func isDigits(value string) bool {
	for i := 0; i < len(value); i++ {
		if !isDigit(value[i]) {
			return false
		}
	}
	return true
}

func isHex(character byte) bool {
	return isDigit(character) || character >= 'A' && character <= 'F' || character >= 'a' && character <= 'f'
}

func isPercentEncoded(value string) bool {
	return len(value) >= 3 && value[0] == '%' && isHex(value[1]) && isHex(value[2])
}
