`http` 出站是一个 HTTP CONNECT 代理客户端

### 结构

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
  // "h3_congestion_control": "bbr",
  "disable_version_fallback": false,
  "udp_fast_open": false,
  "tls": {},

  ... // HTTP2 字段 / QUIC 字段
  ... // 拨号字段
}
```

### 字段

#### server

==必填==

服务器地址。

#### server_port

==必填==

服务器端口。

#### username

Basic 认证用户名。

#### password

Basic 认证密码。

#### path

HTTP 请求路径。

#### udp_path

CONNECT-UDP（[RFC 9298](https://www.rfc-editor.org/rfc/rfc9298)）资源的 [RFC 6570](https://www.rfc-editor.org/rfc/rfc6570) URI 模板的路径与查询部分。

默认使用 `/.well-known/masque/udp/{target_host}/{target_port}/`。

模板需满足 [RFC 9298 第 2 节](https://www.rfc-editor.org/rfc/rfc9298#section-2) 的要求：包含 `target_host` 和 `target_port` 变量，以 `/` 开头，只包含 `0x21`-`0x7E` 范围内的 ASCII 字符，模板等级不高于 3，且不使用 `+`、`#`、`.`、`/`、`;` 运算符。支持简单字符串展开（`{var}`）、表单式查询展开（`{?var}`）和表单式查询续接（`{&var}`），例如 `/masque{?target_host,target_port}` 或 `/masque?h={target_host}&p={target_port}`。其他变量视为未定义。

#### headers

HTTP 请求的额外标头。

#### version

!!! question "自 sing-box 1.15.0 起"

HTTP 版本。

可用值：`1`、`2`、`3`。

默认使用 `2`；设置了 `path` 或 `Host` 头时默认使用 `1`。

`path` 和 `Host` 头仅在 `1` 时可用。

当为 `3` 时，[HTTP2 字段](#http2-字段) 替换为 [QUIC 字段](#quic-字段)。

#### disable_version_fallback

!!! question "自 sing-box 1.15.0 起"

禁用自动回退到更低的 HTTP 版本。

#### h3_congestion_control

HTTP/3 连接的本端发送拥塞控制算法。仅在 HTTP/3 生效。

支持 `new_reno`、`cubic`、`bbr`。HTTP 代理不支持 `none`，配置后将拒绝启动。

省略时保留现有行为：客户端使用 NewReno，服务端使用 BBR。BBR 使用 Standard profile，不提供 profile 或带宽参数。配置仅影响本端发送，两端可以使用不同算法。

配置本字段时，必须显式设置 `version: 3`。不包含 QUIC 支持的构建拒绝此配置。

本字段不改变版本回退策略。客户端是否允许回退仍由 `disable_version_fallback` 控制；回退到 HTTP/1 或 HTTP/2 后，本字段不生效。

#### udp_fast_open

通过 `connect-udp` 发送 UDP 数据包时，不等待代理返回响应。默认关闭。

请求发出后隧道即可使用，响应在首次读取时检查。请求被拒绝（例如 `407`、`405`）时，将作为连接错误而不是拨号错误报告。版本回退不受影响。

HTTP/3 下客户端仍会等待服务端的 SETTINGS，以确定能否使用 QUIC datagram。如果服务端不为尚未接受的请求流缓存 datagram，提前发送的 QUIC datagram 可能被丢弃。

仅影响 `connect-udp`；TCP `CONNECT` 始终等待响应。

#### tls

TLS 配置, 参阅 [TLS](/zh/configuration/shared/tls/#出站)。

### HTTP2 字段

!!! question "自 sing-box 1.15.0 起"

当 `version` 为 `2`（默认）时。

参阅 [HTTP2 字段](/zh/configuration/shared/http2/) 了解详情。

### QUIC 字段

!!! question "自 sing-box 1.15.0 起"

当 `version` 为 `3` 时。

参阅 [QUIC 字段](/zh/configuration/shared/quic/) 了解详情。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
