package masque

import (
	"net/netip"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseTemplate(t *testing.T) {
	t.Parallel()
	// RFC 9484 Figure 1
	for _, path := range []string{
		"",
		"/.well-known/masque/ip/{target}/{ipproto}/",
		"/masque/ip?t={target}&i={ipproto}",
		"/masque/ip{?target,ipproto}",
		"/?user=bob",
		"/masque/ip?user=bob{&target,ipproto}",
		"/{user}/ip/{target}/{ipproto}/",
	} {
		_, err := ParseTemplate(path)
		require.NoError(t, err, path)
	}
	for _, path := range []string{
		"masque/ip/{target}",
		"https://example.org/.well-known/masque/ip/{target}/{ipproto}/",
		"/masque/ip/{target} ",
		"/masque/ip/é",
		// Level 4
		"/masque/ip/{target:3}",
		"/masque/ip{?target*}",
		// Forbidden operators
		"/masque/ip/{+target}",
		"/masque/ip{#target}",
		"/masque/ip{.target}",
		"/masque/ip{/target}",
		"/masque/ip{;target}",
		// Fragment
		"/masque/ip#{target}",
		// Invalid template
		"/masque/ip/{target",
		"/masque/ip/{}",
		"/masque/ip/{=target}",
	} {
		_, err := ParseTemplate(path)
		require.Error(t, err, path)
	}
}

func TestTemplateExpand(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		path     string
		scope    Scope
		expanded string
	}{
		{"", Scope{}, "/.well-known/masque/ip/%2A/%2A/"},
		{"/masque/ip?t={target}&i={ipproto}", Scope{}, "/masque/ip?t=%2A&i=%2A"},
		{"/masque/ip{?target,ipproto}", Scope{}, "/masque/ip?target=%2A&ipproto=%2A"},
		{"/masque/ip?user=bob{&target,ipproto}", Scope{}, "/masque/ip?user=bob&target=%2A&ipproto=%2A"},
		{"/?user=bob", Scope{}, "/?user=bob"},
		{"/{user}/ip/{target}/", Scope{}, "//ip/%2A/"},
		// RFC 9484 Section 4.6
		{"", Scope{Prefix: netip.MustParsePrefix("2001:db8::42/128")}, "/.well-known/masque/ip/2001%3Adb8%3A%3A42/%2A/"},
		{"", Scope{Prefix: netip.MustParsePrefix("2001:db8::/32"), Protocol: 17}, "/.well-known/masque/ip/2001%3Adb8%3A%3A%2F32/17/"},
		{"", Scope{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Protocol: 6}, "/.well-known/masque/ip/192.0.2.0%2F24/6/"},
		{"/masque/ip{?target,ipproto}", Scope{Domain: "example.com"}, "/masque/ip?target=example.com&ipproto=%2A"},
	}
	for _, testCase := range testCases {
		template, err := ParseTemplate(testCase.path)
		require.NoError(t, err, testCase.path)
		expanded, err := template.Expand(testCase.scope)
		require.NoError(t, err, testCase.path)
		require.Equal(t, testCase.expanded, expanded, testCase.path)
		requestURL, err := url.ParseRequestURI(expanded)
		require.NoError(t, err, expanded)
		scope, matched, err := template.Match(requestURL)
		require.True(t, matched, expanded)
		require.NoError(t, err, expanded)
		require.Equal(t, testCase.scope, scope, expanded)
	}
}

func TestTemplateMatch(t *testing.T) {
	t.Parallel()
	type result struct {
		scope   Scope
		matched bool
		err     bool
	}
	testCases := []struct {
		path    string
		request string
		result  result
	}{
		// RFC 9484 Figures 2 and 4
		{"", "/.well-known/masque/ip/*/*/", result{matched: true}},
		{"", "/.well-known/masque/ip/%2a/%2A/", result{matched: true}},
		{"", "/.well-known/masque/ip/2001%3Adb8%3A%3A42/*/", result{Scope{Prefix: netip.MustParsePrefix("2001:db8::42/128")}, true, false}},
		{"", "/.well-known/masque/ip/2001:db8::42/*/", result{Scope{Prefix: netip.MustParsePrefix("2001:db8::42/128")}, true, false}},
		{"", "/.well-known/masque/ip/2001%3Adb8%3A%3A%2F32/17/", result{Scope{Prefix: netip.MustParsePrefix("2001:db8::/32"), Protocol: 17}, true, false}},
		{"", "/.well-known/masque/ip/192.0.2.0%2F24/6/", result{Scope{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Protocol: 6}, true, false}},
		{"", "/.well-known/masque/ip/example.com/*/", result{Scope{Domain: "example.com"}, true, false}},
		{"", "/.well-known/masque/ip/1.2.3.256/*/", result{Scope{Domain: "1.2.3.256"}, true, false}},
		{"", "/.well-known/masque/ip/*/*/?query", result{}},
		{"", "/.well-known/masque/ip/*/", result{}},
		{"", "/.well-known/masque/ip/*/*", result{}},
		{"", "/.well-known/masque/udp/*/*/", result{}},
		// Malformed variables
		{"", "/.well-known/masque/ip//*/", result{matched: true, err: true}},
		{"", "/.well-known/masque/ip/*//", result{matched: true, err: true}},
		{"", "/.well-known/masque/ip/192.0.2.1%2F24/*/", result{matched: true, err: true}},
		{"", "/.well-known/masque/ip/192.0.2.0%2F33/*/", result{matched: true, err: true}},
		{"", "/.well-known/masque/ip/192.0.2.0%2F024/*/", result{matched: true, err: true}},
		{"", "/.well-known/masque/ip/2001%3Adb8%3A%3A%2F129/*/", result{matched: true, err: true}},
		{"", "/.well-known/masque/ip/2001%3Adb8%3A%3A%2F0032/*/", result{matched: true, err: true}},
		{"", "/.well-known/masque/ip/fe80%3A%3A1%25eth0/*/", result{matched: true, err: true}},
		{"", "/.well-known/masque/ip/example.com%2F24/*/", result{matched: true, err: true}},
		{"", "/.well-known/masque/ip/exa%40mple.com/*/", result{matched: true, err: true}},
		{"", "/.well-known/masque/ip/*/256/", result{matched: true, err: true}},
		{"", "/.well-known/masque/ip/*/0017/", result{matched: true, err: true}},
		{"", "/.well-known/masque/ip/*/%2B1/", result{matched: true, err: true}},
		{"", "/.well-known/masque/ip/%zz/*/", result{matched: true, err: true}},
		// Form-style query expansion
		{"/masque/ip{?target,ipproto}", "/masque/ip", result{matched: true}},
		{"/masque/ip{?target,ipproto}", "/masque/ip?target=*&ipproto=*", result{matched: true}},
		{"/masque/ip{?target,ipproto}", "/masque/ip?ipproto=17", result{Scope{Protocol: 17}, true, false}},
		{"/masque/ip{?target,ipproto}", "/masque/ip?target=192.0.2.0%2F24", result{Scope{Prefix: netip.MustParsePrefix("192.0.2.0/24")}, true, false}},
		{"/masque/ip{?target,ipproto}", "/masque/ip?target=", result{matched: true, err: true}},
		{"/masque/ip{?target,ipproto}", "/masque/ip&target=*", result{}},
		{"/masque/ip{?target,ipproto}", "/masque/ip?target=*?ipproto=*", result{}},
		{"/masque/ip{?target,ipproto}", "/masque/ip?ipproto=*&target=*", result{}},
		{"/masque/ip{?target,ipproto}", "/masque/ip?target=*&other=1", result{}},
		{"/masque/ip?user=bob{&target,ipproto}", "/masque/ip?user=bob&ipproto=6", result{Scope{Protocol: 6}, true, false}},
		{"/masque/ip?user=bob{&target,ipproto}", "/masque/ip?user=bob", result{matched: true}},
		{"/masque/ip?user=bob{&target,ipproto}", "/masque/ip?user=alice", result{}},
		// Literal query
		{"/masque/ip?t={target}&i={ipproto}", "/masque/ip?t=example.com&i=*", result{Scope{Domain: "example.com"}, true, false}},
		{"/masque/ip?t={target}&i={ipproto}", "/masque/ip?i=*&t=*", result{}},
		{"/?user=bob", "/?user=bob", result{matched: true}},
		{"/?user=bob", "/", result{}},
		// Other variables
		{"/{user}/ip/{target}/", "/bob/ip/*/", result{matched: true}},
		{"/{target}/{target}/", "/*/*/", result{matched: true}},
		{"/{target}/{target}/", "/*/example.com/", result{matched: true, err: true}},
		// Simple expression with multiple variables
		{"/ip/{target,ipproto}", "/ip/192.0.2.1,17", result{Scope{Prefix: netip.MustParsePrefix("192.0.2.1/32"), Protocol: 17}, true, false}},
	}
	for _, testCase := range testCases {
		template, err := ParseTemplate(testCase.path)
		require.NoError(t, err, testCase.path)
		requestURL, err := url.ParseRequestURI(testCase.request)
		if err != nil {
			requestURL = &url.URL{Path: testCase.request}
		}
		scope, matched, err := template.Match(requestURL)
		require.Equal(t, testCase.result.matched, matched, testCase.request)
		if testCase.result.err {
			require.Error(t, err, testCase.request)
			continue
		}
		require.NoError(t, err, testCase.request)
		require.Equal(t, testCase.result.scope, scope, testCase.request)
	}
}
