# MASQUE Client

!!! question "Since sing-box 1.15.0"

`masque-client` endpoint is an IP proxying over HTTP ([RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484), CONNECT-IP) client.

## Structure

```json
{
  "type": "masque-client",
  "tag": "masque-client",

  "server": "127.0.0.1",
  "server_port": 443,
  "username": "",
  "password": "",
  "path": "",
  "headers": {},
  "warp": false,
  "address": [],
  "version": 0,
  "disable_version_fallback": false,
  "tls": {},
  "advertise_routes": [],
  "system": false,
  "gso": false,
  "inner_domain_resolver": "", // or {}
  "name": "",
  "mtu": 1280,
  "on_demand": false,

  ... // HTTP2 Fields / QUIC Fields
  ... // UDP NAT Fields
  ... // Dial Fields
}
```

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item

## Fields

### server

==Required==

The server address.

### server_port

==Required==

The server port.

### username

Basic authorization username.

### password

Basic authorization password.

### path

Path and query of the [RFC 6570](https://www.rfc-editor.org/rfc/rfc6570) URI template of the IP proxying resource.

The template must satisfy [RFC 9484 Section 3](https://www.rfc-editor.org/rfc/rfc9484#section-3): it must start with `/`, contain only ASCII characters in the range `0x21`-`0x7E`, be a level 3 template or lower, and must not use the `+`, `#`, `.`, `/` or `;` operators. Simple string expansion (`{var}`), form-style query expansion (`{?var}`) and form-style query continuation (`{&var}`) are supported, for example `/masque/ip{?target,ipproto}` or `/masque/ip?t={target}&i={ipproto}`.

The `target` and `ipproto` variables are expanded as the wildcard `*`, which is percent-encoded to `%2A`. Other variables are left undefined.

`/.well-known/masque/ip/{target}/{ipproto}/` is used by default.

### headers

Extra headers of HTTP request.

### warp

Use Cloudflare WARP's modified CONNECT-IP.

The tunnel protocol is `cf-connect-ip`. The path defaults to `/` and the request authority defaults to `cloudflareaccess.com`, unless `path` or a `Host` header is set. Address and route capsules are not exchanged. Set `address` to the IPv4 and IPv6 addresses assigned to the device. IP packets are sent as soon as the HTTP tunnel is established.

HTTP/3 also sends the draft setting `SETTINGS_H3_DATAGRAM` (`0x276`) and uses 20-byte QUIC connection IDs. Packets are carried in QUIC datagrams with context identifier 0. HTTP/2 sends `CONNECT` with `cf-connect-proto: cf-connect-ip` and `pq-enabled: false`, and carries packets in DATAGRAM capsules without a context identifier. HTTP/1 uses the same capsules. Cloudflare's endpoints speak HTTP/3 and HTTP/2.

WARP authenticates the device with a TLS client certificate. Set `tls.server_name` to `consumer-masque.cloudflareclient.com`. The endpoint certificate is not issued for that name: enable `tls.insecure` and pin the endpoint key with `tls.certificate_public_key_sha256`.

### address

Local addresses of the tunnel interface.

Required when `warp` is enabled.

### version

HTTP version.

Available values: `1`, `2`, `3`.

`3` is used by default.

When `2`, [QUIC Fields](#quic-fields) are replaced by [HTTP2 Fields](#http2-fields).

### disable_version_fallback

Disable automatic fallback to lower HTTP version.

### tls

TLS configuration, see [TLS](/configuration/shared/tls/#outbound).

Required for HTTP/3.

### advertise_routes

List of IP prefixes to advertise to the server.

The server will route traffic for these prefixes into this endpoint, where it is handled as inbound traffic.

### system

Use system interface.

Requires privilege and cannot conflict with existing system interfaces.

If disabled, sing-box uses the internal network stack.

### gso

!!! quote ""

    Only supported on Linux.

Attempt to enable generic segmentation offload for the system interface.

Enabled by default when `system` is `true`. Set to `false` to disable.

This option has no effect when `system` is `false`.

### inner_domain_resolver

Set the DNS resolver used for destination domain names when this endpoint is selected as an outbound. Applies to TCP and UDP.

It is also used to resolve unresolved domain destinations when this endpoint is selected for L3 forwarding.

This option uses the same format as [domain_resolver](/configuration/shared/dial/#domain_resolver).

When unset, existing DNS routing rules and the default DNS apply. IP destinations do not require domain resolution.

This option does not affect MASQUE server address resolution, which continues to use `domain_resolver` from the dial fields.

### name

Custom interface name for system interface.

An automatically generated `masque` interface name is used by default.

### mtu

Tunnel MTU.

`1280` will be used by default.

### on_demand

Allow the endpoint to be disconnected when necessary.

## HTTP2 Fields

When `version` is `2`.

See [HTTP2 Fields](/configuration/shared/http2/) for details.

## QUIC Fields

When `version` is `3` (default).

See [QUIC Fields](/configuration/shared/quic/) for details.

## UDP NAT Fields

See [UDP NAT Fields](/configuration/shared/udp-nat/) for details.

## Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
