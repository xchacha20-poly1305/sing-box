---
icon: material/new-box
---

# EasyConnect

### 结构

```json
{
  "dns": {
    "servers": [
      {
        "type": "easyconnect",
        "tag": "",

        "endpoint": "ec-client",
        "accept_default_resolvers": false,
        "accept_search_domain": false
      }
    ]
  }
}
```

### 字段

#### endpoint

==必填==

[EasyConnect 端点](/zh/configuration/endpoint/easyconnect) 的标签。

DNS 查询会通过该端点发送到 VPN 服务器发布的解析器。资源列表中的域名用作搜索域后缀。匹配时优先使用最具体的后缀。

推送的 DNS 设置不会安装到操作系统中。

#### accept_default_resolvers

对未匹配资源列表域后缀的查询使用发布的解析器。

禁用时，未匹配查询返回 `NXDOMAIN`。

#### accept_search_domain

启用且存在发布的搜索域时，单标签查询（例如 `intranet`）会依次附加各个搜索域进行重试，直到其中一个解析成功。

如果所有搜索域扩展均返回 `NXDOMAIN`，原始未限定名称将按普通默认解析器行为处理。

### 示例

```json
{
  "dns": {
    "servers": [
      {
        "type": "local",
        "tag": "local"
      },
      {
        "type": "easyconnect",
        "tag": "ec",
        "endpoint": "ec-client"
      }
    ],
    "rules": [
      {
        "preferred_by": "ec",
        "action": "route",
        "server": "ec"
      }
    ],
    "final": "local"
  }
}
```
