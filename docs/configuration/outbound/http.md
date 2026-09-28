`http` outbound is a HTTP CONNECT proxy client.

### Structure

```json
{
  "type": "http",
  "tag": "http-out",
  
  "server": "127.0.0.1",
  "server_port": 1080,
  "username": "sekai",
  "password": "admin",
  "path": "",
  "udp_path": "",
  "headers": {},
  "version": 0,
  "disable_version_fallback": false,
  "tls": {},

  ... // HTTP2 Fields / QUIC Fields
  ... // Dial Fields
}
```

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### username

Basic authorization username.

#### password

Basic authorization password.

#### path

Path of HTTP request.

#### udp_path

Path and query of the [RFC 6570](https://www.rfc-editor.org/rfc/rfc6570) URI template of the CONNECT-UDP resource ([RFC 9298](https://www.rfc-editor.org/rfc/rfc9298)).

`/.well-known/masque/udp/{target_host}/{target_port}/` is used by default.

The template must satisfy [RFC 9298 Section 2](https://www.rfc-editor.org/rfc/rfc9298#section-2): it must contain the `target_host` and `target_port` variables, start with `/`, contain only ASCII characters in the range `0x21`-`0x7E`, be a level 3 template or lower, and must not use the `+`, `#`, `.`, `/` or `;` operators. Simple string expansion (`{var}`), form-style query expansion (`{?var}`) and form-style query continuation (`{&var}`) are supported, for example `/masque{?target_host,target_port}` or `/masque?h={target_host}&p={target_port}`. Other variables are left undefined.

#### headers

Extra headers of HTTP request.

#### version

!!! question "Since sing-box 1.15.0"

HTTP version.

Available values: `1`, `2`, `3`.

`2` is used by default, or `1` if `path` or the `Host` header is set.

`path` and the `Host` header are only available for `1`.

When `3`, [HTTP2 Fields](#http2-fields) are replaced by [QUIC Fields](#quic-fields).

#### disable_version_fallback

!!! question "Since sing-box 1.15.0"

Disable automatic fallback to lower HTTP version.

#### tls

TLS configuration, see [TLS](/configuration/shared/tls/#outbound).

### HTTP2 Fields

!!! question "Since sing-box 1.15.0"

When `version` is `2` (default).

See [HTTP2 Fields](/configuration/shared/http2/) for details.

### QUIC Fields

!!! question "Since sing-box 1.15.0"

When `version` is `3`.

See [QUIC Fields](/configuration/shared/quic/) for details.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
