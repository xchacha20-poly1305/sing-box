---
name: sing-box-api
description: "How to interact with a running sing-box instance through the `sing-box api` CLI. Use this skill whenever the user wants to query or control a sing-box service — checking status, listing connections, switching outbound groups, viewing logs, running network tests, managing Tailscale/OpenConnect/OpenVPN/USB-IP endpoints, or anything that would otherwise require curling the Clash-compatible REST API. The `sing-box api` commands are the correct, first-class interface; do NOT fall back to raw HTTP requests against the Clash API."
---

# sing-box API

sing-box exposes a gRPC-based API service. The CLI wraps it as `sing-box api <subcommand>`, giving you a typed, tab-completable interface that replaces the legacy pattern of curling `http://127.0.0.1:9090` (Clash RESTful API).

## Connection

Every `sing-box api` call needs the API service URL:

```
sing-box api --url 127.0.0.1:9090 <subcommand>
```

Or set the environment variable once:

```
export BOX_API_URL=127.0.0.1:9090
```

If the API has a secret configured:

```
sing-box api --url 127.0.0.1:9090 --secret <secret> <subcommand>
# or
export BOX_API_SECRET=<secret>
```

`--url` and `--secret` are persistent flags — they apply to every subcommand.

## Command Reference

### Service info

| Command | Description |
|---|---|
| `sing-box api status` | Print service status (state, uptime, memory, goroutines, connections, traffic rates) |
| `sing-box api version` | Print the remote service version |
| `sing-box api logs` | Print the service log buffer |
| `sing-box api logs -f` | Follow logs (like `tail -f`), until Ctrl-C |
| `sing-box api logs --level warn` | Filter by minimum log level |
| `sing-box api logs --search "keyword"` | Filter log lines by text (case-insensitive) |

### Outbounds and groups

| Command | Description |
|---|---|
| `sing-box api outbounds` | List all outbounds with type and URL-test delay |
| `sing-box api group list` | List outbound groups with their selected outbound |
| `sing-box api group show <group>` | Show group details and all member outbounds |
| `sing-box api group select <group> <outbound>` | Select an outbound in a group (selector type) |
| `sing-box api group urltest <group>` | Trigger a URL test on a group; results appear in `outbounds` shortly after |

### Clash mode

| Command | Description |
|---|---|
| `sing-box api mode` | Print the current clash mode |
| `sing-box api mode list` | List available clash modes |
| `sing-box api mode set <mode>` | Set the clash mode (unvalidated — unknown modes succeed silently) |

### Connections

| Command | Description |
|---|---|
| `sing-box api connection list` | List open connections (columns: id, network, destination, inbound, outbound, total) |
| `sing-box api connection list --columns id,destination,rate` | Customize displayed columns |
| `sing-box api connection show <id>` | Print full details for one connection |
| `sing-box api connection close <id>` | Close a connection by UUID |
| `sing-box api connection close --all` | Close all connections |

Available column names: `id`, `network`, `source`, `destination`, `inbound`, `outbound`, `chain`, `rule`, `protocol`, `user`, `process`, `created`, `rate`, `total`.

### Network tests

| Command | Description |
|---|---|
| `sing-box api stun` | Run a STUN test (external address, latency, NAT type) |
| `sing-box api stun --outbound <tag>` | Run STUN through a specific outbound |
| `sing-box api networkquality` | Run an Apple-style network quality test (capacity, RPM) |
| `sing-box api networkquality --serial` | Run download and upload sequentially |
| `sing-box api networkquality -o <tag>` | Test through a specific outbound |

### Tailscale

All Tailscale subcommands operate on Tailscale endpoints configured in the sing-box config. When there is only one endpoint, `--endpoint` is optional.

| Command | Description |
|---|---|
| `sing-box api tailscale status` | Print Tailscale endpoint status |
| `sing-box api tailscale peer list` | List Tailscale peers |
| `sing-box api tailscale peer show <peer>` | Show peer details |
| `sing-box api tailscale ping <peer>` | Ping a Tailscale peer |
| `sing-box api tailscale ssh [user@]<peer>` | SSH to a Tailscale peer |
| `sing-box api tailscale exit-node list` | List available exit nodes |
| `sing-box api tailscale exit-node set <peer>` | Set exit node |
| `sing-box api tailscale exit-node clear` | Clear exit node |
| `sing-box api tailscale certificate list` | List Tailscale HTTPS certificates |
| `sing-box api tailscale certificate export <domain>` | Export a Tailscale certificate |
| `sing-box api tailscale taildrop targets` | List Taildrop send targets |
| `sing-box api tailscale taildrop send <peer> <file>...` | Send files via Taildrop |
| `sing-box api tailscale taildrop list` | List received Taildrop files |
| `sing-box api tailscale taildrop get <name> [output]` | Download a received file |
| `sing-box api tailscale taildrop delete <name>...` | Delete received files |
| `sing-box api tailscale logout` | Log out of Tailscale |

### OpenConnect

| Command | Description |
|---|---|
| `sing-box api openconnect status` | Print OpenConnect endpoint status |
| `sing-box api openconnect auth` | Authenticate an OpenConnect endpoint |
| `sing-box api openconnect cancel` | Cancel pending authentication |

### OpenVPN

| Command | Description |
|---|---|
| `sing-box api openvpn status` | Print OpenVPN endpoint status |
| `sing-box api openvpn auth` | Authenticate an OpenVPN endpoint |
| `sing-box api openvpn cancel` | Cancel pending authentication |

### USB/IP

| Command | Description |
|---|---|
| `sing-box api usbip device list` | List local USB devices |
| `sing-box api usbip device show <device>` | Show USB device details (by bus id, vid:pid, or vid:pid:serial) |
| `sing-box api usbip share <device>...` | Share USB devices through a usbip-server (runs until interrupted) |
| `sing-box api usbip share --all` | Share all local USB devices, including newly plugged ones |
| `sing-box api usbip status` | Print USB/IP sharing status |

## Why not curl the Clash API?

The `sing-box api` commands communicate over gRPC with the running service. Compared to curling the legacy Clash REST API:

- Typed and structured — no JSON parsing with `jq`
- Tab completion for all subcommands and flags
- Streaming support (logs, status, connection rates) built in
- Access to sing-box-specific features not exposed by the Clash API (Tailscale, OpenConnect, OpenVPN, USB/IP, network quality tests, STUN)
- Consistent error reporting with gRPC status codes
