# EasyConnect Client

==Client only==

Sangfor EasyConnect VPN client.

The protocol is IPv4 only. Authentication uses username and password over HTTPS; tunneled traffic uses a camouflage TLS handshake rather than a real TLS stack.

## Structure

```json
{
  "type": "easyconnect",
  "tag": "ec-client",

  "system": false,
  "name": "",

  ... // UDP NAT Fields

  "server": "vpn.example.com",
  "username": "",
  "password": "",
  "device": "",
  "language": "",
  "mtu": 0,
  "queue_length": 0,
  "keep_alive_interval": "",
  "keep_alive_timeout": "",
  "keep_alive_sequence_disguise_disabled": false,
  "data_channel_timeout": "",
  "data_channel_keep_alive_interval": "",
  "data_channel_keep_alive_destination": "",
  "data_channel_keep_alive_timeout": "",
  "reconnect_timeout": "",
  "resource_routes_disabled": false,
  "resource_filter_disabled": false,
  "tls": {
    "insecure": false,
    "server_name": "",
    "system_trust_disabled": false,
    "certificate_authority": [],
    "certificate_authority_path": ""
  },
  "on_demand": false,

  ... // Dial Fields
}
```

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item.

## Fields

### system

Use a system interface.

Requires privilege and cannot conflict with existing system interfaces.

If disabled, sing-box uses the internal network stack.

### name

Custom interface name for the system interface.

An automatically generated `ec` interface name is used by default.

### server

==Required==

EasyConnect VPN server HTTPS URL.

The `https://` scheme is added if omitted. URL user information, queries, and fragments are not supported.

### username

==Required==

Username used for EasyConnect authentication.

### password

==Required==

Password used for EasyConnect authentication.

### device

==Required==

Device identifier reported to the VPN server.

The gateway may reject the request if this field is empty. The operating system name in lowercase (`linux`, `darwin`, `windows`, `android`, ...) is the original implementation's default behavior.

### language

Language tag reported during authentication.

`en_US` is used by default.

### mtu

Tunnel MTU.

The value advertised by the VPN server is used when empty, then `1400`. Values below `576` are raised to `576`.

### queue_length

Maximum number of data packets buffered in each direction.

`32` is used by default.

### keep_alive_interval

Keepalive interval on the tunnel keepalive channel.

`1s` is used by default.

### keep_alive_timeout

Keepalive timeout on the tunnel keepalive channel.

`30s` is used by default.

### keep_alive_sequence_disguise_disabled

Number keepalive messages with the seconds since this client was created.

By default the counter is disguised: it starts at a random point below an hour when the tunnel opens.

### data_channel_timeout

Maximum time one write on the tunnel upload channel may take.

`30s` is used by default. The gateway watches the tunnel through the keepalive channel, which is a connection of its own, so a path that stopped forwarding the data connections is reported by nothing else; without this timeout the write holds until the kernel gives up retransmitting.

### data_channel_keep_alive_interval

Send an ICMP echo request through the tunnel once the upload channel has been idle for this long.

Disabled by default. The data connections carry nothing while the tunnel is idle, so a NAT or firewall on the path can drop their state and leave the tunnel broken until the gateway ends the session. The probes keep that state alive; the original implementation does not send them.

### data_channel_keep_alive_destination

Destination of the probes.

The first DNS server published by the VPN server is used by default. The address must be covered by the published resource list, otherwise the endpoint refuses to connect.

### data_channel_keep_alive_timeout

Drop the tunnel when nothing arrives on the receive channel for this long while probes are being sent.

Disabled by default, and requires `data_channel_keep_alive_interval`. Only enable it when the probe destination answers ICMP echo requests.

### reconnect_timeout

Maximum time spent reconnecting after a tunnel failure.

`5m` is used by default. Authentication failures, TLS trust errors, and unsupported protocol features are terminal and do not reconnect.

### resource_routes_disabled

Do not fetch the published resource list.

The tunnel then only has the assigned address prefix. The gateway still drops traffic it did not publish, so leaving the resource filter enabled without the resource list will drop most outbound packets.

### resource_filter_disabled

Do not drop outbound datagrams that the published resource list does not cover.

The gateway treats such a datagram as a violation and drops the tunnel after a few of them.

### tls.insecure

Disable TLS certificate verification for HTTPS authentication.

### tls.server_name

Server name used for TLS authentication.

The hostname from `server` is used by default.

### tls.system_trust_disabled

Do not use the system certificate pool.

Use with `tls.certificate_authority` or `tls.certificate_authority_path` to trust only the supplied authorities.

### tls.certificate_authority

PEM certificate authorities used to verify the VPN server.

Conflict with `tls.certificate_authority_path`.

### tls.certificate_authority_path

PEM certificate authority path used to verify the VPN server.

Conflict with `tls.certificate_authority`.

### on_demand

Allow the endpoint to be disconnected when necessary.

## UDP NAT Fields

See [UDP NAT Fields](/configuration/shared/udp-nat/) for details.

## Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.

## DNS

Pushed DNS settings are not installed into the operating system. Configure an [EasyConnect DNS server](/configuration/dns/server/easyconnect/) to use them through sing-box.

## Routing

Use [`preferred_by`](/configuration/route/rule/#preferred_by) to send traffic covered by the published resource list through this endpoint. Traffic outside that list is dropped by the resource filter and can cause the gateway to close the tunnel.
