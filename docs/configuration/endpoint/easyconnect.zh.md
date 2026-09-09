# EasyConnect 客户端

==仅客户端==

深信服 EasyConnect VPN 客户端。

该协议仅支持 IPv4。认证通过 HTTPS 使用用户名和密码；隧道流量使用伪装 TLS 握手，而不是真实的 TLS 协议栈。

## 结构

```json
{
  "type": "easyconnect",
  "tag": "ec-client",

  "system": false,
  "name": "",

  ... // UDP NAT 字段

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

  ... // 拨号字段
}
```

!!! note ""

    当内容只有一项时，可以忽略 JSON 数组 [] 标签。

## 字段

### system

使用系统网卡。

需要权限，且不能与现有系统网卡冲突。

如果禁用，sing-box 使用内部网络栈。

### name

系统网卡的自定义名称。

默认使用自动生成的 `ec` 网卡名。

### server

==必填==

EasyConnect VPN 服务器 HTTPS URL。

如果省略，会添加 `https://` 协议。不支持 URL 用户信息、查询参数和片段。

### username

==必填==

用于 EasyConnect 认证的用户名。

### password

==必填==

用于 EasyConnect 认证的密码。

### device

==必填==

向 VPN 服务器报告的设备标识。

如果为空，网关可能会拒绝请求。原始实现的默认行为是使用小写操作系统名称（`linux`、`darwin`、`windows`、`android` 等）。

### language

认证时报告的语言标签。

默认使用 `en_US`。

### mtu

隧道 MTU。

为空时使用 VPN 服务器通告的值，再否则为 `1400`。低于 `576` 的值会被提升到 `576`。

### queue_length

每个方向缓冲的数据包最大数量。

默认使用 `32`。

### keep_alive_interval

隧道保活通道的保活间隔。

默认使用 `1s`。

### keep_alive_timeout

隧道保活通道的保活超时。

默认使用 `30s`。

### keep_alive_sequence_disguise_disabled

使用自该客户端创建以来的秒数对保活消息编号。

默认会伪装计数器：隧道打开时从一个低于一小时的随机点开始。

### data_channel_timeout

隧道上传通道单次写入的最长耗时。

默认使用 `30s`。网关通过保活通道观察隧道，而保活通道是一条独立的连接，因此路径停止转发数据连接时没有其他地方会报告；没有此超时，写入将一直阻塞到内核放弃重传为止。

### data_channel_keep_alive_interval

在上传通道空闲达到该时长后，通过隧道发送一个 ICMP 回显请求。

默认禁用。隧道空闲时数据连接不传输任何内容，路径上的 NAT 或防火墙可能清除其状态，使隧道在网关结束会话前一直处于静默损坏状态。探测包可以保持该状态；原始实现不发送它们。

### data_channel_keep_alive_destination

探测包的目标地址。

默认使用 VPN 服务器发布的第一个 DNS 服务器。该地址必须被已发布的资源列表覆盖，否则该端点将拒绝连接。

### data_channel_keep_alive_timeout

发送探测包期间，接收通道静默达到该时长后断开隧道。

默认禁用，且需要 `data_channel_keep_alive_interval`。仅在探测目标会响应 ICMP 回显请求时启用。

### reconnect_timeout

隧道失败后用于重连的最长时间。

默认使用 `5m`。认证失败、TLS 信任错误以及不支持的协议特性是终态错误，不会重连。

### resource_routes_disabled

不获取已发布的资源列表。

此时隧道仅包含分配的地址前缀。网关仍会丢弃未发布的流量，因此在没有资源列表时保持资源过滤启用会丢弃大多数出站数据包。

### resource_filter_disabled

不丢弃资源列表未覆盖的出站数据报。

网关会将此类数据报视为违规，并在少量此类流量后断开隧道。

### tls.insecure

禁用 HTTPS 认证的 TLS 证书验证。

### tls.server_name

TLS 认证使用的服务器名称。

默认使用 `server` 中的主机名。

### tls.system_trust_disabled

不使用系统证书池。

与 `tls.certificate_authority` 或 `tls.certificate_authority_path` 一起使用，以仅信任提供的证书颁发机构。

### tls.certificate_authority

用于验证 VPN 服务器的 PEM 证书颁发机构。

与 `tls.certificate_authority_path` 冲突。

### tls.certificate_authority_path

用于验证 VPN 服务器的 PEM 证书颁发机构路径。

与 `tls.certificate_authority` 冲突。

### on_demand

允许该 endpoint 在需要时断开连接。

## UDP NAT 字段

参阅 [UDP NAT 字段](/zh/configuration/shared/udp-nat/)。

## 拨号字段

参阅[拨号字段](/zh/configuration/shared/dial/)了解详情。

## DNS

推送的 DNS 设置不会安装到操作系统中。配置 [EasyConnect DNS 服务器](/zh/configuration/dns/server/easyconnect/) 以通过 sing-box 使用这些设置。

## 路由

使用 [`preferred_by`](/zh/configuration/route/rule/#preferred_by) 将资源列表覆盖的流量发送到该端点。资源列表之外的流量会被资源过滤器丢弃，并可能导致网关断开隧道。
