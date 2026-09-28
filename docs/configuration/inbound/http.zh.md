### 结构

```json
{
  "type": "http",
  "tag": "http-in",

  ... // 监听字段

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

  ... // HTTP2 字段 / QUIC 字段
}
```

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### version

!!! question "自 sing-box 1.15.0 起"

提供的 HTTP 版本列表。

可用值：`1`、`2`、`3`。

默认为 `1` 和 `2`。

`3` 需要 TLS。

#### tls

TLS 配置, 参阅 [TLS](/zh/configuration/shared/tls/#入站)。

#### users

HTTP 用户

如果为空则不需要验证。

#### set_system_proxy

!!! quote ""

    仅支持 Linux、Android、Windows 和 macOS。

!!! warning ""

    要在无特权的 Android 和 iOS 上工作，请改用 tun.platform.http_proxy。

启动时自动设置系统代理，停止时自动清理。

#### udp_path

CONNECT-UDP（[RFC 9298](https://www.rfc-editor.org/rfc/rfc9298)）资源的 [RFC 6570](https://www.rfc-editor.org/rfc/rfc6570) URI 模板的路径与查询部分。

默认使用 `/.well-known/masque/udp/{target_host}/{target_port}/`。

模板需满足与 [HTTP 出站](/zh/configuration/outbound/http/#udp_path) 的 `udp_path` 相同的要求。

请求按模板的展开结果进行匹配，不匹配时以 `404 Not Found` 拒绝。`target_host` 和 `target_port` 变量经百分号解码后按 [RFC 9298 第 3 节](https://www.rfc-editor.org/rfc/rfc9298#section-3) 校验，无效的值以 `400 Bad Request` 拒绝。其他变量会被忽略。

### HTTP2 字段

!!! question "自 sing-box 1.15.0 起"

当 `version` 包含 `2` 时。

参阅 [HTTP2 字段](/zh/configuration/shared/http2/)。

### QUIC 字段

!!! question "自 sing-box 1.15.0 起"

当 `version` 包含 `3` 时，[HTTP2 字段](#http2-字段) 被 QUIC 字段替代。

参阅 [QUIC 字段](/zh/configuration/shared/quic/)。
