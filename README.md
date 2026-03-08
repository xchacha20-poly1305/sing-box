# sing-box

The universal proxy platform.

[![Packaging status](https://repology.org/badge/vertical-allrepos/sing-box.svg)](https://repology.org/project/sing-box/versions)

## Documentation

https://sing-box.sagernet.org

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
    },
    {
      "type": "anytls",
      "tag": "anytls-in",
      "tls": {
        "enabled": true,
        "server_names": [
          "sagernet.sekai.love",
          "sekai.love"
        ],
        "certificate_path": "cert.pem",
        "key_path": "key.key",
        "reject_unknown_sni": true
      }
    }
  ]
}
```

Reject unknown SNI: If the server name of connection does not match `server_name` or any domain in `server_names`,
and is not included in the certificate, it will be rejected.

拒绝未知 SNI：如果连接的 server name 与 `server_name` 或者 `server_names` 中包含的域名 不符 且 证书中不包含它，则拒绝连接。

## Dialer

```json
{
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct",
      "tcp_keep_alive": "5m",
      "tcp_keep_alive_interval": "75s",
      "tcp_keep_alive_count": 0,
      "disable_tcp_keep_alive": false
    }
  ]
}
```

TCP Keep alive options.

## URLTest Fallback 支持

按照**可用性**和**顺序**选择出站

可用：指 URL 测试存在有效结果

配置示例：
```
{
    "tag": "fallback",
    "type": "urltest",
    "outbounds": [
        "A",
        "B",
        "C"
    ],
    "fallback": {
        "enabled": true, // 开启 fallback
        "max_delay": "200ms" // 可选配置
        // 若某节点可用，但是延迟超过 max_delay，则认为该节点不可用，淘汰忽略该节点，继续匹配选择下一个节点
        // 但若所有节点均不可用，但是存在被 max_delay 规则淘汰的节点，则选择延迟最低的被淘汰节点
    }
}
```
以上配置为例子：
1. 当 A, B, C 都可用时，优选选择 A。当 A 不可用时，优选选择 B。当 A, B 都不可用时，选择 C，若 C 也不可用，则返回第一个出站：A
2. (配置了 max_delay) 当 A, C 都不可用，B 延迟超过 200ms 时（在第一轮选择时淘汰，被认为是不可用节点），则选择 B

For extended features

- Providers: [中文](./docs/configuration/provider/index.zh.md), [English](./docs/configuration/provider/index.md)

## HTTP

```json5
{
  "outbounds": [
     {
       "type": "http",
        "tag": "http-out",
        "udp_over_tcp": {} // or true
     }
  ]
}
```

* `udp_over_tcp`: UDP over TCP field.

## URLTest

Can use http3 (URL scheme: `quic` `http3` `h3`).

## DNS

### TCP

```json
{
  "dns": {
    "servers": [
      {
        "type": "tcp",
        "tag": "cloudlfare-tcp",
        "server": "1.1.1.1",
        "server_port": "53",
        "reuse": true
      }
    ]
  }
}
```

- `reuse`: Reuse TCP connection.

## Speedtest

A speedtest protocol invited by Hysteria 2.

Client:

```shell
sing-box -c config.json tools speedtest --outbound "proxy"
```

Server:

Supported: AnyTLS, HTTP, Hysteria2, mixed, shadowsocks, socks, trojan, TUIC, Juicity, VLESS, VMess.

```json
{
  "inbounds": [
    {
      "type": "anytls",
      "speedtest": "allow"
    }
  ]
}
```

## Juicity

Powered by [dyhkwong/sing-juicity](https://github.com/dyhkwong/sing-juicity).

_Note: Not support pin sha256_

```json5
{
  "inbounds": [
    {
      "type": "juicity",
      "tag": "juicity-in",
      "listen": "::",
      "listen_port": 443,
      "users": [
        {
          "name": "dyhkwong",
          "uuid": "1e50e0d5-54a6-515b-a2f3-316d50b5ef7c",
          "password": "sing-juicity"
        }
      ],
      "auth_timeout": "3s",
      "tls": {
        "enabled": true
      }
    }
  ],
  "outbounds": [
    {
      "type": "juicity",
      "tag": "juicity-out",
      "server": "example.com",
      "server_port": 443,
      "uuid": "1e50e0d5-54a6-515b-a2f3-316d50b5ef7c",
      "password": "sing-juicity",
      "tls": {
        "enabled": true
      }
    }
  ]
}
```

## VLESS

Add encryption and decryption. 

```shell
sing-box generate vless-enc

sing-box generate vless-enc -m # ML-KEM-768
```

```json5
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "decryption": "mlkem768x25519plus.native.600s.qEjiFe8d_WUw8LGe8VH8GnEPLxiHNqT1honkCkSXE2M"
    }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "vless-out",
      "encryption": "mlkem768x25519plus.native.0rtt.JytWZyE79E7RlfntZG4DZb3o5czP37tBo9icrKgGEDk"
    }
  ]
}
```

You can set environment `SING_VMESS_ENCRYPTION_DISABLE_AES` = `1` to disable AES.

## Rule

```json5
{
  "route": {
    "rules": {
      "time_range": [
        "12:00:00-14:00:00",
        "22:00:00-07:00:00", // Can cross a day.
      ],
      "time_zone": "Asia/Shanghai"
    }
  }
}
```

- `time_range` Listable. This function can restrict your kids' internet access.
- `time_zone` Time zone for `time_range`. List see <https://en.wikipedia.org/wiki/List_of_tz_database_time_zones#List>. If empty, the behavior is nearly undefined.(Usually uses local or UTC)

For extended features

- Providers: [中文](./docs/configuration/provider/index.zh.md), [English](./docs/configuration/provider/index.md)

## gRPC

### multimode

**Requirement: `with_grpc`**

```json
{
  "outbound": [
    {
      "tag": "vless_grpc",
      "type": "vless",
      "transport": {
        "type": "grpc",
        "multi_mode": true
      }
    }
  ]
}
```

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