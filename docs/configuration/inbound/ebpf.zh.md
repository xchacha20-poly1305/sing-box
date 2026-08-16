---
icon: material/new-box
---

!!! question "自 sing-box 1.14.0 起"

eBPF 入站透明拦截本机或下游网络的 TCP/UDP 流量。`local` 数据路径使用
cgroup socket-address 程序拦截本机 socket，`shared` 数据路径使用 TC
拦截热点、路由器或其他下游接口的转发流量。

该入站只在使用 `with_ebpf` 构建标签的 Android 和 Linux 版本中可用。
运行时不需要 cgo，但需要 root 或等效的 BPF、cgroup 和网络管理权限。

!!! warning "Linux 6.6 LPM trie 兼容性"

    Linux 6.6.0 至 6.6.46 在更新 BPF LPM trie 时可能因 UBSAN 触发内核
    panic。默认 `shared_network` 的本机地址策略使用精确匹配 HASH map，
    不受影响。本机 UID/包名筛选、`bypass_rule_set` 和 shared 来源 CIDR
    筛选会写入 LPM trie，需要 Linux 6.6.47，或包含上游修复
    `896880ff30866f386ebed14ab81ce1ad3710cfc4` 的厂商内核。对于已知未修复
    的内核，sing-box 会拒绝这些策略，而不是冒险触发内核崩溃。

### 结构

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",
  "mode": "local",
  "network": ["tcp", "udp"],
  "udp_timeout": "5m",
  "dns_mode": "hijack",
  "bypass_private_address": true,
  "bypass_rule_set": ["geoip-cn"],
  "local": {
    "cgroup_path": "",
    "ipv6_mode": "auto",
    "include_uid": [],
    "include_uid_range": [],
    "exclude_uid": [],
    "exclude_uid_range": [],
    "include_android_user": [],
    "include_package": [],
    "exclude_package": [],
    "state_capacity": 0
  },
  "shared": {
    "interface": [],
    "ipv6_mode": "always",
    "include_source_cidr": [],
    "exclude_source_cidr": [],
    "include_mac_address": [],
    "exclude_mac_address": [],
    "state_capacity": 0,
    "advanced": {
      "tc_priority": 1
    }
  }
}
```

eBPF 入站不使用[监听字段](/zh/configuration/shared/listen/)。内部监听端口和
重定向地址前缀由 sing-box 自动分配并检查冲突。

### mode

| 值 | 数据路径 |
|----|----------|
| `local` | 仅拦截本机 cgroup 流量。 |
| `shared` | 仅拦截所选下游接口的转发流量。 |
| `hybrid` | 同时启用两条数据路径，并共享绕过策略。 |

默认值为 `local`。`local` 字段只能用于 `local` 或 `hybrid`，`shared` 字段
只能用于 `shared` 或 `hybrid`。

### network

启用的网络协议，可选值为 `tcp` 和 `udp`，默认同时启用。

### udp_timeout

UDP 会话超时，默认值为 `5m`。

### dns_mode

控制目标端口 53 与绕过策略的顺序：

| 值 | 行为 |
|----|------|
| `hijack` | 在私网和规则集绕过前拦截 DNS。 |
| `respect_bypass` | 先执行私网和规则集绕过，再决定是否拦截 DNS。 |
| `off` | 不拦截目标端口 53。 |

默认值为 `hijack`。UID、协议、自身防回环、DHCP 和 shared 客户端筛选仍然
先于 DNS 策略执行。此选项只捕获 TCP/UDP 53 端口，不等同于路由规则中的
`hijack-dns` 动作。shared 模式启用 DNS 拦截时必须启用 UDP。

### bypass_private_address

是否在进入 sing-box 路由前绕过内建私网、运营商级 NAT 和链路本地目的地址。
默认值为 `true`，同时作用于两条数据路径。设置为 `false` 不会关闭协议、
自身防回环、DHCP、无效地址、回环地址和多播地址等安全绕过。在
`dns_mode: "hijack"` 下，目标端口 53 会先于目的地址绕过处理。

### bypass_rule_set

目的 IP CIDR 需要绕过 eBPF 入站的规则集。只提取 CIDR；域名、端口、进程和
其他条件不会在内核中求值。规则集更新时会刷新 map，已有流在过期前保持原决定。

### local

#### local.cgroup_path

要拦截的 cgroup v2 绝对路径。留空时自动使用 cgroup v2 根目录。
同一个 cgroup 路径同时只能由一个 eBPF 入站管理。

#### local.ipv6_mode

| 值 | 行为 |
|----|------|
| `auto` | 仅在存在可用原生 IPv6 路由时拦截新 IPv6 流。 |
| `always` | 始终启用原生 IPv6 拦截。 |
| `off` | 不拦截原生 IPv6。 |

默认值为 `auto`。IPv4-mapped IPv6 socket 仍按 IPv4 处理。该选项不影响
shared 数据路径的 IPv6；shared 使用独立的 `shared.ipv6_mode`。

#### local.include_uid

需要拦截的 UID。配置任意 include UID、范围或包名后，其他 UID 默认绕过。

#### local.include_uid_range

需要拦截的 UID 范围，格式为 `start:end`。

#### local.exclude_uid

需要绕过的 UID；exclude 优先于 include。

#### local.exclude_uid_range

需要绕过的 UID 范围，格式为 `start:end`。

#### local.include_android_user

需要拦截的 Android 用户 ID，仅支持 Android。

#### local.include_package

需要拦截的 Android 包名。包名在启动时转换为 UID。

#### local.exclude_package

需要绕过的 Android 包名。共享同一 UID 的包无法由 eBPF 区分。

包名策略只保证直接由目标 UID 创建的 socket。系统 DNS resolver、
`DownloadManager`、isolated process、SDK sandbox 等代应用创建的流量可能使用
其他 UID。启动日志会输出最终 include/exclude UID ranges，用于确认实际策略。

#### local.state_capacity

本机重定向、UDP flow 和 socket-cookie 回退状态的容量。`0` 使用实现默认值
（当前为 65536）；允许范围为 `0` 到 `1048576`。增大会占用更多锁定内核内存。

### shared

shared 模式不会创建热点、DHCP、NAT、IPv6 RA 或 IP 转发，这些仍由系统负责。

#### shared.interface

==shared 或 hybrid 模式必填==

客户端报文进入 TC ingress 的下游接口。接口可在启动后出现或消失，sing-box
会自动挂载和卸载。不要选择 `lo`、上游接口或仅支持三层报文的接口。热点与
Wi-Fi 上游共用接口名时，应使用源 CIDR 或 MAC 筛选客户端流量。

#### shared.ipv6_mode

| 值 | 行为 |
|----|------|
| `always` | 始终拦截所选下游接口的 IPv6 流量。 |
| `off` | 不拦截 shared 数据路径的 IPv6 流量。 |

默认值为 `always`，保持旧版本行为。`off` 不会阻断 IPv6；系统能够转发 IPv6
时，这些流量会绕过 sing-box。shared 不使用本机原生 IPv6 路由探测，因为无法
从主机默认 IPv6 路由准确推断下游 IPv6 和代理出口是否可用。

#### shared.include_source_cidr

允许进入代理路径的客户端源 CIDR。非空时，未匹配流量绕过。

#### shared.exclude_source_cidr

需要绕过的客户端源 CIDR，优先于 include。

#### shared.include_mac_address

允许进入代理路径的 48-bit 客户端源 MAC。

#### shared.exclude_mac_address

需要绕过的客户端源 MAC，优先于 include。

#### shared.state_capacity

shared proxy、bypass 和分片状态容量。`0` 使用实现默认值（当前为 65536）；
允许范围为 `0` 到 `1048576`。

#### shared.advanced.tc_priority

TC filter 优先级，有效范围为 1 到 65535，默认值为 `1`。仅在与现有 OpenWrt、
Android tethering 或其他 TC 程序协调时修改。无论优先级是否相同，一个接口只能
由一个 eBPF 入站管理。

### 内核兼容性

shared 模式和仅启用 TCP 的 local 模式最低兼容目标为 Linux 4.19。local UDP
还需要上游 Linux 5.2 加入的 cgroup UDP4/UDP6 recvmsg hook，因此默认同时启用
TCP/UDP 的 local 或 hybrid 配置需要 Linux 5.2，或包含相应回移的厂商内核。
Android 的主要验证目标仍为 GKI 5.10 及以上。

生成的程序只使用 BPF v1 指令集，不包含 verifier 可见的反向跳转，并且每个
程序不超过 Linux 4.19 的 4096 条指令上限。实现不依赖内核 BTF、CO-RE、TCX、
bounded-loop verifier、BPF timer、dynptr 或 kfunc。local 需要 cgroup v2 和所选
协议对应的 socket-address hook；shared 需要 `sched_cls`、`clsact`、报文写入及
校验和 helper。厂商内核可能单独回移、禁用或修改某项能力，因此实际能力探测
比版本号更可靠。

请以 root 使用与配置一致的模式和协议运行无侵入的纯 Go 探测器：

```sh
sing-box tools ebpf status --mode local --network tcp,udp
sing-box tools ebpf status --mode shared-network --interface br-lan
```

该命令直接使用 `cilium/ebpf`，不依赖 shell、`bpftool` 或 `tc`。它只创建并立即
关闭临时探测对象，不会挂载程序，也不会修改 cgroup、qdisc、路由、sysctl 或
流量状态。
