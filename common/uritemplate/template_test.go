package uritemplate

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Variable assignments from RFC 6570 Section 3.2.
var rfcValues = Values{
	"count":      List{"one", "two", "three"},
	"dom":        List{"example", "com"},
	"dub":        String("me/too"),
	"hello":      String("Hello World!"),
	"half":       String("50%"),
	"var":        String("value"),
	"who":        String("fred"),
	"base":       String("http://example.com/home/"),
	"path":       String("/foo/bar"),
	"list":       List{"red", "green", "blue"},
	"keys":       AssociativeArray{{"semi", ";"}, {"dot", "."}, {"comma", ","}},
	"v":          String("6"),
	"x":          String("1024"),
	"y":          String("768"),
	"empty":      String(""),
	"empty_keys": AssociativeArray{},
	"undef":      nil,
}

func TestExpandRFC6570(t *testing.T) {
	t.Parallel()
	testCases := [][2]string{
		// Section 3.2.1
		{"{count}", "one,two,three"},
		{"{count*}", "one,two,three"},
		{"{/count}", "/one,two,three"},
		{"{/count*}", "/one/two/three"},
		{"{;count}", ";count=one,two,three"},
		{"{;count*}", ";count=one;count=two;count=three"},
		{"{?count}", "?count=one,two,three"},
		{"{?count*}", "?count=one&count=two&count=three"},
		{"{&count*}", "&count=one&count=two&count=three"},
		// Section 3.2.2
		{"{var}", "value"},
		{"{hello}", "Hello%20World%21"},
		{"{half}", "50%25"},
		{"O{empty}X", "OX"},
		{"O{undef}X", "OX"},
		{"{x,y}", "1024,768"},
		{"{x,hello,y}", "1024,Hello%20World%21,768"},
		{"?{x,empty}", "?1024,"},
		{"?{x,undef}", "?1024"},
		{"?{undef,y}", "?768"},
		{"{var:3}", "val"},
		{"{var:30}", "value"},
		{"{list}", "red,green,blue"},
		{"{list*}", "red,green,blue"},
		{"{keys}", "semi,%3B,dot,.,comma,%2C"},
		{"{keys*}", "semi=%3B,dot=.,comma=%2C"},
		// Section 3.2.3
		{"{+var}", "value"},
		{"{+hello}", "Hello%20World!"},
		{"{+half}", "50%25"},
		{"{base}index", "http%3A%2F%2Fexample.com%2Fhome%2Findex"},
		{"{+base}index", "http://example.com/home/index"},
		{"O{+empty}X", "OX"},
		{"O{+undef}X", "OX"},
		{"{+path}/here", "/foo/bar/here"},
		{"here?ref={+path}", "here?ref=/foo/bar"},
		{"up{+path}{var}/here", "up/foo/barvalue/here"},
		{"{+x,hello,y}", "1024,Hello%20World!,768"},
		{"{+path,x}/here", "/foo/bar,1024/here"},
		{"{+path:6}/here", "/foo/b/here"},
		{"{+list}", "red,green,blue"},
		{"{+list*}", "red,green,blue"},
		{"{+keys}", "semi,;,dot,.,comma,,"},
		{"{+keys*}", "semi=;,dot=.,comma=,"},
		// Section 3.2.4
		{"{#var}", "#value"},
		{"{#hello}", "#Hello%20World!"},
		{"{#half}", "#50%25"},
		{"foo{#empty}", "foo#"},
		{"foo{#undef}", "foo"},
		{"{#x,hello,y}", "#1024,Hello%20World!,768"},
		{"{#path,x}/here", "#/foo/bar,1024/here"},
		{"{#path:6}/here", "#/foo/b/here"},
		{"{#list}", "#red,green,blue"},
		{"{#list*}", "#red,green,blue"},
		{"{#keys}", "#semi,;,dot,.,comma,,"},
		{"{#keys*}", "#semi=;,dot=.,comma=,"},
		// Section 3.2.5
		{"{.who}", ".fred"},
		{"{.who,who}", ".fred.fred"},
		{"{.half,who}", ".50%25.fred"},
		{"www{.dom*}", "www.example.com"},
		{"X{.var}", "X.value"},
		{"X{.empty}", "X."},
		{"X{.undef}", "X"},
		{"X{.var:3}", "X.val"},
		{"X{.list}", "X.red,green,blue"},
		{"X{.list*}", "X.red.green.blue"},
		{"X{.keys}", "X.semi,%3B,dot,.,comma,%2C"},
		{"X{.keys*}", "X.semi=%3B.dot=..comma=%2C"},
		{"X{.empty_keys}", "X"},
		{"X{.empty_keys*}", "X"},
		// Section 3.2.6
		{"{/who}", "/fred"},
		{"{/who,who}", "/fred/fred"},
		{"{/half,who}", "/50%25/fred"},
		{"{/who,dub}", "/fred/me%2Ftoo"},
		{"{/var}", "/value"},
		{"{/var,empty}", "/value/"},
		{"{/var,undef}", "/value"},
		{"{/var,x}/here", "/value/1024/here"},
		{"{/var:1,var}", "/v/value"},
		{"{/list}", "/red,green,blue"},
		{"{/list*}", "/red/green/blue"},
		{"{/list*,path:4}", "/red/green/blue/%2Ffoo"},
		{"{/keys}", "/semi,%3B,dot,.,comma,%2C"},
		{"{/keys*}", "/semi=%3B/dot=./comma=%2C"},
		// Section 3.2.7
		{"{;who}", ";who=fred"},
		{"{;half}", ";half=50%25"},
		{"{;empty}", ";empty"},
		{"{;v,empty,who}", ";v=6;empty;who=fred"},
		{"{;v,bar,who}", ";v=6;who=fred"},
		{"{;x,y}", ";x=1024;y=768"},
		{"{;x,y,empty}", ";x=1024;y=768;empty"},
		{"{;x,y,undef}", ";x=1024;y=768"},
		{"{;hello:5}", ";hello=Hello"},
		{"{;list}", ";list=red,green,blue"},
		{"{;list*}", ";list=red;list=green;list=blue"},
		{"{;keys}", ";keys=semi,%3B,dot,.,comma,%2C"},
		{"{;keys*}", ";semi=%3B;dot=.;comma=%2C"},
		// Section 3.2.8
		{"{?who}", "?who=fred"},
		{"{?half}", "?half=50%25"},
		{"{?x,y}", "?x=1024&y=768"},
		{"{?x,y,empty}", "?x=1024&y=768&empty="},
		{"{?x,y,undef}", "?x=1024&y=768"},
		{"{?var:3}", "?var=val"},
		{"{?list}", "?list=red,green,blue"},
		{"{?list*}", "?list=red&list=green&list=blue"},
		{"{?keys}", "?keys=semi,%3B,dot,.,comma,%2C"},
		{"{?keys*}", "?semi=%3B&dot=.&comma=%2C"},
		// Section 3.2.9
		{"{&who}", "&who=fred"},
		{"{&half}", "&half=50%25"},
		{"?fixed=yes{&x}", "?fixed=yes&x=1024"},
		{"{&x,y,empty}", "&x=1024&y=768&empty="},
		{"{&x,y,undef}", "&x=1024&y=768"},
		{"{&var:3}", "&var=val"},
		{"{&list}", "&list=red,green,blue"},
		{"{&list*}", "&list=red&list=green&list=blue"},
		{"{&keys}", "&keys=semi,%3B,dot,.,comma,%2C"},
		{"{&keys*}", "&semi=%3B&dot=.&comma=%2C"},
	}
	for _, testCase := range testCases {
		template, err := Parse(testCase[0])
		require.NoError(t, err, testCase[0])
		expanded, err := template.Expand(rfcValues)
		require.NoError(t, err, testCase[0])
		require.Equal(t, testCase[1], expanded, testCase[0])
	}
}

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
	_, err := MustParse("{list:1}").Expand(rfcValues)
	require.Error(t, err)
	_, err = MustParse("{keys:1}").Expand(rfcValues)
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
		"/a'b",
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
	template, err := Parse("/{a.b_c}{%2Fd}{?e,f:9999}{/g*}")
	require.NoError(t, err)
	require.Equal(t, []string{"a.b_c", "%2Fd", "e", "f", "g"}, template.VarNames())
}
