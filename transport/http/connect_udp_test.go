package http

import (
	"net/netip"
	"net/url"
	"testing"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func TestParseUDPTemplate(t *testing.T) {
	t.Parallel()
	// RFC 9298 Figure 1
	for _, path := range []string{
		"",
		"/.well-known/masque/udp/{target_host}/{target_port}/",
		"/masque?h={target_host}&p={target_port}",
		"/masque{?target_host,target_port}",
		"/masque{?target_host,target_port,user}",
		"/{user}/udp/{target_host}/{target_port}/",
	} {
		_, err := ParseUDPTemplate(path)
		require.NoError(t, err, path)
	}
	for _, path := range []string{
		"masque/udp/{target_host}/{target_port}/",
		"https://example.org/.well-known/masque/udp/{target_host}/{target_port}/",
		// Both variables are required
		"/masque/udp/{target_host}/",
		"/masque/udp/{target_port}/",
		"/masque",
		// Level 4
		"/masque/udp/{target_host:3}/{target_port}/",
		"/masque{?target_host*,target_port}",
		// Forbidden operators
		"/masque/udp/{+target_host}/{target_port}/",
		"/masque/udp{/target_host,target_port}",
		"/masque/udp{.target_host}{;target_port}",
		"/masque/udp/{target_host}/{target_port}{#x}",
		// Fragment
		"/masque/udp/{target_host}/{target_port}/#x",
		// Invalid characters
		"/masque/udp/{target_host}/{target_port}/ ",
		"/masque/udp/é/{target_host}/{target_port}/",
	} {
		_, err := ParseUDPTemplate(path)
		require.Error(t, err, path)
	}
}

func TestUDPTemplateExpand(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		path        string
		destination M.Socksaddr
		expanded    string
	}{
		{"", M.ParseSocksaddrHostPort("192.0.2.6", 443), "/.well-known/masque/udp/192.0.2.6/443/"},
		// RFC 9298 Section 3
		{"", M.ParseSocksaddrHostPort("2001:db8::42", 443), "/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/"},
		{"", M.ParseSocksaddrHostPort("example.com", 53), "/.well-known/masque/udp/example.com/53/"},
		{"/masque?h={target_host}&p={target_port}", M.ParseSocksaddrHostPort("2001:db8::42", 443), "/masque?h=2001%3Adb8%3A%3A42&p=443"},
		{"/masque{?target_host,target_port}", M.ParseSocksaddrHostPort("192.0.2.6", 443), "/masque?target_host=192.0.2.6&target_port=443"},
		{"/masque{?target_host,target_port,user}", M.ParseSocksaddrHostPort("192.0.2.6", 443), "/masque?target_host=192.0.2.6&target_port=443"},
	}
	for _, testCase := range testCases {
		template, err := ParseUDPTemplate(testCase.path)
		require.NoError(t, err, testCase.path)
		requestURL, err := template.Expand(testCase.destination)
		require.NoError(t, err, testCase.path)
		require.Equal(t, testCase.expanded, requestURL.RequestURI(), testCase.path)
		destination, matched, err := template.Match(requestURL)
		require.True(t, matched, testCase.expanded)
		require.NoError(t, err, testCase.expanded)
		require.Equal(t, testCase.destination, destination, testCase.expanded)
	}
}

func TestUDPTemplateMatch(t *testing.T) {
	t.Parallel()
	type result struct {
		destination M.Socksaddr
		matched     bool
		err         bool
	}
	testCases := []struct {
		path    string
		request string
		result  result
	}{
		// RFC 9298 Figures 3 and 5
		{"", "/.well-known/masque/udp/192.0.2.6/443/", result{M.SocksaddrFrom(netip.MustParseAddr("192.0.2.6"), 443), true, false}},
		{"", "/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/", result{M.SocksaddrFrom(netip.MustParseAddr("2001:db8::42"), 443), true, false}},
		{"", "/.well-known/masque/udp/2001:db8::42/443/", result{M.SocksaddrFrom(netip.MustParseAddr("2001:db8::42"), 443), true, false}},
		{"", "/.well-known/masque/udp/%3A%3Affff%3A192.0.2.6/443/", result{M.SocksaddrFrom(netip.MustParseAddr("::ffff:192.0.2.6"), 443), true, false}},
		{"", "/.well-known/masque/udp/example.com/53/", result{M.Socksaddr{Fqdn: "example.com", Port: 53}, true, false}},
		{"", "/.well-known/masque/udp/192.0.2.256/53/", result{M.Socksaddr{Fqdn: "192.0.2.256", Port: 53}, true, false}},
		{"", "/.well-known/masque/udp/example.com/053/", result{M.Socksaddr{Fqdn: "example.com", Port: 53}, true, false}},
		{"", "/.well-known/masque/udp/example.com/53", result{}},
		{"", "/.well-known/masque/udp/example.com/53/?x", result{}},
		{"", "/.well-known/masque/udp/example.com/", result{}},
		{"", "/.well-known/masque/ip/*/*/", result{}},
		// Malformed variables
		{"", "/.well-known/masque/udp//53/", result{matched: true, err: true}},
		{"", "/.well-known/masque/udp/example.com//", result{matched: true, err: true}},
		{"", "/.well-known/masque/udp/example.com/0/", result{matched: true, err: true}},
		{"", "/.well-known/masque/udp/example.com/65536/", result{matched: true, err: true}},
		{"", "/.well-known/masque/udp/example.com/%2B53/", result{matched: true, err: true}},
		{"", "/.well-known/masque/udp/fe80%3A%3A1%25eth0/53/", result{matched: true, err: true}},
		{"", "/.well-known/masque/udp/2001%3Adb8%3A%3A%2F32/53/", result{matched: true, err: true}},
		{"", "/.well-known/masque/udp/exa%40mple.com/53/", result{matched: true, err: true}},
		// Form-style query expansion
		{"/masque{?target_host,target_port}", "/masque?target_host=example.com&target_port=53", result{M.Socksaddr{Fqdn: "example.com", Port: 53}, true, false}},
		{"/masque{?target_host,target_port}", "/masque?target_port=53&target_host=example.com", result{}},
		{"/masque{?target_host,target_port}", "/masque?target_host=example.com", result{matched: true, err: true}},
		{"/masque{?target_host,target_port}", "/masque", result{matched: true, err: true}},
		// Literal query
		{"/masque?h={target_host}&p={target_port}", "/masque?h=2001%3Adb8%3A%3A42&p=443", result{M.SocksaddrFrom(netip.MustParseAddr("2001:db8::42"), 443), true, false}},
		{"/masque?h={target_host}&p={target_port}", "/masque?p=443&h=example.com", result{}},
	}
	for _, testCase := range testCases {
		template, err := ParseUDPTemplate(testCase.path)
		require.NoError(t, err, testCase.path)
		requestURL, err := url.ParseRequestURI(testCase.request)
		require.NoError(t, err, testCase.request)
		destination, matched, err := template.Match(requestURL)
		require.Equal(t, testCase.result.matched, matched, testCase.request)
		if testCase.result.err {
			require.Error(t, err, testCase.request)
			continue
		}
		require.NoError(t, err, testCase.request)
		require.Equal(t, testCase.result.destination, destination, testCase.request)
	}
}
