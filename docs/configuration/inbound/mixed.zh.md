`mixed` 入站是一个 socks4, socks4a, socks5 和 http 服务器.

### 结构

```json
{
  "type": "mixed",
  "tag": "mixed-in",

  ... // 监听字段

  "users": [
    {
      "username": "admin",
      "password": "admin"
    }
  ],
  "set_system_proxy": false,
  "udp_path": ""
}
```

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### users

SOCKS 和 HTTP 用户

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
