> Sponsored by [Warp](https://go.warp.dev/sing-box), built for coding with multiple AI agents

<a href="https://go.warp.dev/sing-box">
<img alt="Warp sponsorship" width="400" src="https://github.com/warpdotdev/brand-assets/raw/refs/heads/main/Github/Sponsor/Warp-Github-LG-02.png">
</a>

---

# sing-box

# Changes

## Dialer

```json
{
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct",
      "tcp_keep_alive_interval": "15s",
      "tcp_keep_alive_idle": "10min"
    }
  ]
}
```

TCP Keep alive options.

## Inbound TLS

```json
{
  "inbounds": [
    {
      "type": "trojan",
      "tag": "trojan-in",
      "tls": {
        "enabled": true,
        "server_name": "sekai.love",
        "certificate_path": "cert.pem",
        "key_path": "key.key",
        "reject_unknown_sni": true
      }
    }
  ]
}
```

Reject unknown sni: If the server name of connection is not equal to `server_name` and not be included in certificate,
it will be rejected.

拒绝未知 SNI：如果连接的 server name 与 `server_name` 不符 且 证书中不包含它，则拒绝连接。

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```
