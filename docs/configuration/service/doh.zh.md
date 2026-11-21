---
icon: material/new-box
---

# DNS over HTTP(S)

DoH 服务通过内部 DNS 路由器处理查询。GET 请求使用无填充的 base64url `dns` 查询参数，
POST 请求发送二进制 DNS 消息，并设置 `Content-Type: application/dns-message`。

### 结构

```json
{
  "type": "doh",
  "tag": "doh-in",
  "listen": "127.0.0.1",
  "listen_port": 8443,
  "path": "/dns-query",
  "users": [
    {
      "username": "alice",
      "password": "alice-password"
    },
    {
      "username": "bob",
      "password": "bob-password"
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "cert.pem",
    "key_path": "key.pem"
  }
}
```

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### path

服务精确匹配的 URL 路径。默认使用 `/dns-query`。请使用规范的绝对路径。
根路径、尾随斜杠、空路径段、`.` 或 `..`、百分号转义、查询串、片段和路由通配符均无效。

#### users

允许使用 HTTP Basic 认证的用户。每项须设置唯一的非空用户名和非空密码。
用户名不能包含冒号。列表为空时允许匿名查询。

DNS 规则可以用 `inbound` 匹配服务标签，用 `auth_user` 匹配已认证的用户名。

#### tls

在监听地址上启用 HTTPS。参阅 [TLS](/zh/configuration/shared/tls/)。
关闭 TLS 时，查询和 Basic 认证头均通过明文 HTTP 传输。
