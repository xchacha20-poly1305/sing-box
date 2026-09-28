### Structure

```json
{
  "type": "http",
  "tag": "http-in",
  
  ... // Listen Fields
  
  "version": [],
  "users": [
    {
      "username": "admin",
      "password": "admin"
    }
  ],
  "tls": {},
  "set_system_proxy": false,
  "udp_path": "",

  ... // HTTP2 Fields / QUIC Fields
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### version

!!! question "Since sing-box 1.15.0"

List of HTTP versions to serve.

Available values: `1`, `2`, `3`.

`1` and `2` are used by default.

TLS is required for `3`.

#### tls

TLS configuration, see [TLS](/configuration/shared/tls/#inbound).

#### users

HTTP users.

No authentication required if empty.

#### set_system_proxy

!!! quote ""

    Only supported on Linux, Android, Windows, and macOS.

!!! warning ""

    To work on Android and Apple platforms without privileges, use tun.platform.http_proxy instead.

Automatically set system proxy configuration when start and clean up when stop.

#### udp_path

Path and query of the [RFC 6570](https://www.rfc-editor.org/rfc/rfc6570) URI template of the CONNECT-UDP resource ([RFC 9298](https://www.rfc-editor.org/rfc/rfc9298)).

`/.well-known/masque/udp/{target_host}/{target_port}/` is used by default.

The template must satisfy the same requirements as the `udp_path` of the [HTTP outbound](/configuration/outbound/http/#udp_path).

Requests are matched against the expansions of the template, and rejected with `404 Not Found` otherwise. The `target_host` and `target_port` variables are percent-decoded and validated as described in [RFC 9298 Section 3](https://www.rfc-editor.org/rfc/rfc9298#section-3); an invalid value is rejected with `400 Bad Request`. Other variables are ignored.

### HTTP2 Fields

!!! question "Since sing-box 1.15.0"

When `version` contains `2`.

See [HTTP2 Fields](/configuration/shared/http2/) for details.

### QUIC Fields

!!! question "Since sing-box 1.15.0"

When `version` contains `3`, [HTTP2 Fields](#http2-fields) are replaced by QUIC Fields.

See [QUIC Fields](/configuration/shared/quic/) for details.
