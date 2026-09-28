package uritemplate

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExpandLiteral(t *testing.T) {
	t.Parallel()
	template, err := Parse("/café/%2F{var}")
	require.NoError(t, err)
	expanded, err := template.Expand(Values{"var": String("é")})
	require.NoError(t, err)
	require.Equal(t, "/caf%C3%A9/%2F%C3%A9", expanded)
}

func TestExpandPrefixUnicode(t *testing.T) {
	t.Parallel()
	template := MustParse("{var:2}{+res:2}")
	expanded, err := template.Expand(Values{"var": String("ééé"), "res": String("%2F%2Fx")})
	require.NoError(t, err)
	require.Equal(t, "%C3%A9%C3%A9%2F%2F", expanded)
}

func TestExpandPrefixComposite(t *testing.T) {
	t.Parallel()
	values := Values{
		"list": List{"red", "green", "blue"},
		"keys": AssociativeArray{{"semi", ";"}, {"dot", "."}, {"comma", ","}},
	}
	_, err := MustParse("{list:1}").Expand(values)
	require.Error(t, err)
	_, err = MustParse("{keys:1}").Expand(values)
	require.Error(t, err)
}

func TestLevel(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		template string
		level    int
	}{
		// Section 1.2
		{"http://example.com/~{username}/", 1},
		{"http://example.com/dictionary/{term:1}/{term}", 4},
		{"http://example.com/search{?q,lang}", 3},
		{"http://www.example.com/foo{?query,number}", 3},
		{"{+path}/here", 2},
		{"X{#var}", 2},
		{"{x,y}", 3},
		{"{/list*}", 4},
		{"/static", 1},
	}
	for _, testCase := range testCases {
		template, err := Parse(testCase.template)
		require.NoError(t, err, testCase.template)
		require.Equal(t, testCase.level, template.Level(), testCase.template)
	}
}

func TestParseInvalid(t *testing.T) {
	t.Parallel()
	for _, template := range []string{
		"{",
		"}",
		"/a{b",
		"{}",
		"{=var}",
		"{,var}",
		"{!var}",
		"{@var}",
		"{|var}",
		"{var,}",
		"{.var.}",
		"{var..name}",
		"{.var}{va-r}",
		"{var:0}",
		"{var:10000}",
		"{var:3*}",
		"{var*:3}",
		"{var:}",
		"{*}",
		"{%2}",
		"/a b",
		"/a\"b",
		"/a%",
		"/a%zz",
		"/a<b>",
		"/a\\b",
		"/a^b",
		"/a`b",
		"/a|b",
		"/a\x7f",
		"{{var}}",
		"/\xff",
	} {
		_, err := Parse(template)
		require.Error(t, err, template)
	}
}

func TestParseValid(t *testing.T) {
	t.Parallel()
	// RFC 6570 Errata ID 6937
	_, err := Parse("/a'b")
	require.NoError(t, err)
	template, err := Parse("/{a.b_c}{%2Fd}{?e,f:9999}{/g*}")
	require.NoError(t, err)
	require.Equal(t, []string{"a.b_c", "%2Fd", "e", "f", "g"}, template.VarNames())
}
