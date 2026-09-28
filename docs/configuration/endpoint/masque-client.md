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
  // "h3_congestion_control": "bbr",
  "disable_version_fallback": false,
  "tls": {},
  "advertise_routes": [],
  // "tcp_congestion_control": "bbr",
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

### h3_congestion_control

Selects the local sender congestion controller for HTTP/3 connections. Applies only to HTTP/3.

Available values: `new_reno`, `cubic`, `bbr`, `none`.

Omitting the field preserves the existing defaults: NewReno on the client and BBR on the server. BBR uses the Standard profile; profile and bandwidth parameters are not exposed. The setting affects only local sending, so the two peers may select different algorithms.

When configured, `version` must be `3` or omitted; `0` resolves to the default version `3`. Builds without QUIC support reject this setting.

This field does not change version fallback. Client fallback remains controlled by `disable_version_fallback`; the setting has no effect after fallback to HTTP/1 or HTTP/2.

`none` bypasses the outer congestion window and pacing only for QUIC DATAGRAM packets carrying IP traffic. Control streams, the handshake, and reliable capsules retain normal congestion control. Capsule fallback remains available when DATAGRAM is unsupported. Exempt packets retain ACK/loss tracking, path MTU and resource limits, and use Not-ECT.

Before using `none`, ensure tunneled traffic has appropriate congestion control or that the deployment provides suitable traffic management. UDP or KCP alone does not establish this. Lower latency is not guaranteed. Configure both peers to exempt both sending directions.

### tls

TLS configuration, see [TLS](/configuration/shared/tls/#outbound).

Required for HTTP/3.

### advertise_routes

List of IP prefixes to advertise to the server.

The server will route traffic for these prefixes into this endpoint, where it is handled as inbound traffic.

### tcp_congestion_control

Selects the congestion controller for the local sender in this endpoint's internal Go TCP stack.

Available values: `reno`, `cubic`, `bbr`. Omitting the field preserves the default, CUBIC. Empty values and `none` are not supported.

Only affects TCP connections terminated or initiated by this endpoint's internal Go TCP stack. It does not affect kernel TCP, TCP forwarded at L3, UDP, or inner QUIC. Peers may select different algorithms; for example, configure this field on the server to control TCP download data sent by its internal stack to the client.

Allowed with either `system: false` or `system: true`, but only applies to connections handled by the internal Go TCP stack. Enabling the system interface does not make this setting affect kernel TCP.

Applies to HTTP/1, HTTP/2, and HTTP/3, including after version fallback. Does not require a build with QUIC support. This field is independent of `h3_congestion_control`, which controls outer HTTP/3 congestion, and can be combined with its `none` value.

Changing algorithms does not guarantee higher throughput; test on the actual network path.

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
