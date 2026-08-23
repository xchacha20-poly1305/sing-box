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
  "tcp_splice": false,
  "bypass_rule_set": ["geoip-cn"],
  "local": {
    "dns_mode": "hijack",
    "cgroup_path": "",
    "ipv6_mode": "auto",
    "bypass_private_address": true,
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
    "dns_mode": "hijack",
    "interface": [],
    "ipv6_mode": "always",
    "bypass_private_address": true,
    "include_source_cidr": [],
    "exclude_source_cidr": [],
    "include_mac_address": [],
    "exclude_mac_address": [],
    "state_capacity": 0,
    "advanced": {
      "tc_priority": 1,
      "data_plane": "auto",
      "routing_mark": 0,
      "routing_table": 0
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
| `hybrid` | 同时启用两条数据路径；共享规则集绕过，私网绕过则分别配置。 |

默认值为 `local`。`local` 字段只能用于 `local` 或 `hybrid`，`shared` 字段
只能用于 `shared` 或 `hybrid`。

### network

启用的网络协议，可选值为 `tcp` 和 `udp`，默认同时启用。

### udp_timeout

UDP 会话超时，默认值为 `5m`。


### bypass_rule_set

目的 IP CIDR 需要绕过 eBPF 入站的规则集。只提取 CIDR；域名、端口、进程和
其他条件不会在内核中求值。规则集更新时会刷新 map，已有流在过期前保持原决定。

配置 FakeIP DNS 服务器时，其 IPv4/IPv6 分配范围会在私网和规则集绕过之前强制
进入代理。这也保证 `local.ipv6_mode` 为 `auto` 且本机暂时没有可用原生 IPv6
路由时，FakeIP IPv6 仍可被拦截。UID、包名、shared 来源、协议、自身防回环和
本机真实地址的精确匹配仍然优先。FakeIP 与规则集 CIDR 重叠会在启动时告警；
若它与未指定地址、回环、多播或内部重定向范围冲突，启动会直接拒绝该配置。

### tcp_splice

为符合条件的 TCP 连接启用实验性内核流转发，默认值为 `false`。

仅处理进入当前 eBPF 入站、并由内建 `direct` 出站建立的连接，且两端必须都能安全
还原为裸 TCP socket。UDP、代理出站、多路复用或加密传输、TLS 分片、TLS 伪装，
以及存在不安全缓存状态的连接仍使用原有 Go copy。内核不支持 SOCKHASH 或
`SK_SKB` 时也会自动回退，不会阻止 eBPF 入站启动。上游 power report recorder
处于活动状态时，该连接也会回退，以保留完整的用户态归因和字节统计。

该功能可减少长连接 DIRECT TCP 流量的用户态 CPU 和数据复制，但不同厂商内核的
socket 激活与半关闭行为仍需实机验证，因此保持实验状态。完全由内核搬运的字节
不会实时经过用户态统计包装器；sing-box 会在 splice 连接关闭时把累计的上传和
下载字节补入连接与全局流量统计，因此活跃连接的显示值会暂时偏低。

### local

#### local.dns_mode

控制 local 数据路径对目标端口 53 的拦截顺序：

| 值 | 行为 |
|----|------|
| `hijack` | 在 local UID/包名和目的地址绕过策略之前拦截。 |
| `respect_policy` | 执行完整 local 策略，仅拦截最终仍应进入代理路径的流量。 |
| `off` | 在 local 用户策略之前直接放行目标端口 53。 |

默认值为 `hijack`。此时 UID/包名筛选、本机精确地址、私网绕过和
`bypass_rule_set` 均不能绕过 53 端口；`respect_policy` 则正常遵守这些策略。
自身与内部重定向防回环、协议选择、DHCP 安全放行、报文有效性以及
`local.ipv6_mode: "off"` 在所有模式下仍是优先级更高的正确性门控。只处理
`network` 已启用协议的 TCP/UDP 53，因此可使用仅 TCP 或仅 UDP 的配置。
该选项不能识别 DoH/DoT，也不等同于路由规则中的 `hijack-dns` 动作。

#### local.cgroup_path

要拦截的 cgroup v2 绝对路径。留空时自动使用 cgroup v2 根目录。
每个 sing-box 进程只支持一个 `local` 或 `hybrid` eBPF 入站。该入站会为
sing-box 自身创建的 socket 注册进程级保护，因此即使使用不同的 cgroup 路径，
也不能再启动另一个 local 后端。

#### local.ipv6_mode

| 值 | 行为 |
|----|------|
| `auto` | 仅在存在可用原生 IPv6 路由时拦截新 IPv6 流。 |
| `always` | 始终启用原生 IPv6 拦截。 |
| `off` | 不拦截原生 IPv6。 |

默认值为 `auto`。IPv4-mapped IPv6 socket 仍按 IPv4 处理。该选项不影响
shared 数据路径的 IPv6；shared 使用独立的 `shared.ipv6_mode`。
普通原生 IPv6 仍遵循路由可用性探测；配置的 FakeIP IPv6 不受该门控影响，
避免 DNS 已合成 FakeIP 地址却被 eBPF 绕过而形成不可达路径。

#### local.bypass_private_address

是否在 local 数据路径绕过内建私网、运营商级 NAT 和链路本地目的地址，默认值
为 `true`。设置为 `false` 不会关闭普通非 DNS 流量对未指定地址、回环、多播和
本机真实地址精确匹配等安全绕过。如 `local.dns_mode` 所述，`hijack` 会在所有
目的地址绕过之前处理 53 端口。

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

本机重定向、UDP 缓存和 socket-cookie 回退状态的容量。`0` 使用实现默认值：
重定向及 socket-cookie map 为 32768，connected UDP peer 与 UDP flow 缓存为
16384，已关闭 socket 的 UDP 恢复 map 为 8192。支持 socket-release 清理的内核
会启用独立 UDP flow 缓存；旧内核的 `lru_fallback` 路径只使用 peer 状态，未使用
的 flow map 缩减为 1。显式配置的值会应用于重定向、peer、启用的 flow 缓存和
socket-cookie map；恢复 map 取配置值与 8192 中的较小值。允许范围为 `0` 到
`1048576`。
增大会占用更多锁定内核内存。

### shared

shared 模式不会创建热点、DHCP、NAT、IPv6 RA 或 IP 转发，这些仍由系统负责。

#### shared.dns_mode

控制 shared 数据路径对目标端口 53 的拦截顺序：

| 值 | 行为 |
|----|------|
| `hijack` | 在 shared 客户端和目的地址绕过策略之前拦截。 |
| `respect_policy` | 执行完整 shared 策略，仅拦截最终仍应进入代理路径的流量。 |
| `off` | 在 shared 用户策略之前直接放行目标端口 53。 |

默认值为 `hijack`。此时来源 CIDR/MAC 筛选、本机精确地址、私网绕过和
`bypass_rule_set` 均不能绕过 53 端口；`respect_policy` 则正常遵守这些策略。
协议选择、DHCP 安全放行、报文有效性以及 `shared.ipv6_mode: "off"` 在所有
模式下仍是优先级更高的正确性门控。只处理 `network` 已启用协议的 TCP/UDP
53；仅启用 TCP 时，shared DNS 拦截不再强制要求 UDP。该选项不能识别
DoH/DoT，也不等同于路由规则中的 `hijack-dns` 动作。

#### shared.interface

==shared 或 hybrid 模式必填==

客户端报文进入 TC ingress 的下游接口。接口可在启动后出现或消失，sing-box
会自动挂载和卸载。shared eBPF 程序和 map 只在首个已配置接口出现时加载；
接口暂时消失后仍保留 backend，避免重复执行 verifier 和 map 初始化。不要选择
`lo`、上游接口或仅支持三层报文的接口。热点与
Wi-Fi 上游共用接口名时，应使用源 CIDR 或 MAC 筛选客户端流量。

#### shared.ipv6_mode

| 值 | 行为 |
|----|------|
| `always` | 始终拦截所选下游接口的 IPv6 流量。 |
| `off` | 不拦截 shared 数据路径的 IPv6 流量。 |

默认值为 `always`，保持旧版本行为。`off` 不会阻断 IPv6；系统能够转发 IPv6
时，这些流量会绕过 sing-box。shared 不使用本机原生 IPv6 路由探测，因为无法
从主机默认 IPv6 路由准确推断下游 IPv6 和代理出口是否可用。

#### shared.bypass_private_address

是否在 shared 数据路径绕过内建私网、运营商级 NAT 和链路本地目的地址，默认值
为 `true`，与 `local.bypass_private_address` 相互独立。设置为 `false` 后，普通
非 DNS 流量仍会绕过 IPv4 未指定地址范围（`0.0.0.0/8`）、完整 IPv4 回环范围
（`127.0.0.0/8`）、IPv6 未指定地址和回环地址、IPv4/IPv6 多播目的地址以及本机
精确地址。如 `shared.dns_mode` 所述，`hijack` 会在所有目的地址绕过之前处理
53 端口。

#### shared.include_source_cidr

允许进入代理路径的客户端源 CIDR。非空时，未匹配流量绕过。

#### shared.exclude_source_cidr

需要绕过的客户端源 CIDR，优先于 include。

#### shared.include_mac_address

允许进入代理路径的 48-bit 客户端源 MAC。

#### shared.exclude_mac_address

需要绕过的客户端源 MAC，优先于 include。

#### shared.state_capacity

shared proxy、bypass 和分片状态容量。`0` 使用实现默认值：proxy 为 32768，
分片为 8192；配置 bypass rule-set 或来源策略时 bypass 为 16384，否则未使用的
bypass 缓存缩减为 1（包括显式设置容量时）。显式设置的值会应用于实际启用的
map。允许范围为 `0` 到 `1048576`。
当代理状态持续承压或 token 预留开始失败时，sing-box 会暂时缩短孤立流清理
周期以恢复容量，同时保留仍被活跃 TCP 或 UDP 会话引用的流。

#### shared.advanced.tc_priority

TC filter 优先级，有效范围为 1 到 65535，默认值为 `1`。仅在与现有 OpenWrt、
Android tethering 或其他 TC 程序协调时修改。无论优先级是否相同，一个接口只能
由一个 eBPF 入站管理。
使用默认优先级时，sing-box 会在内核支持时采用 TCX，否则自动回退到 clsact。
非默认优先级会固定使用 clsact，以确保配置的排序语义仍然有效。

#### shared.advanced.data_plane

shared TCP 和实验性 UDP 拦截数据面。默认值 `auto` 会优先尝试 TC socket assignment；如果
内核拒绝所需的程序、map 或 helper，则自动回退到兼容的包改写路径。
`socket_assign` 强制要求 TCP 使用现代路径，不允许整体回退；`rewrite` 始终使用
目标 token 和 TC egress 源地址恢复。

socket assignment 保留原始五元组，将 ingress 包直接分配给透明 listener，
回包走正常内核协议栈。仅显式选择 `socket_assign` 时才尝试实验性的 UDP
assignment，并会单独探测；若内核不提供
`bpf_sk_lookup_udp` 或 verifier 拒绝 UDP classifier，TCP assignment 仍然保留，
仅 UDP 回退 rewrite。默认 `auto` 模式下 UDP 仍使用 rewrite。Linux 4.19
继续由 rewrite fallback 支持。

#### shared.advanced.routing_mark

socket assignment 使用的数据包 mark。`0` 使用进程专属默认值
`0x53420001`；rewrite 数据面忽略此项。

#### shared.advanced.routing_table

将带 mark 的 assignment 数据包路由到 loopback 的策略路由表。`0` 使用表
`2026`。sing-box 随 eBPF 入站安装并清理所需 rule 和 local route；如果专用
优先级或路由表已存在不兼容状态，则拒绝覆盖。

### 内核兼容性

shared 模式和仅启用 TCP 的 local 模式最低兼容目标为 Linux 4.19。local UDP
还需要上游 Linux 5.2 加入的 cgroup UDP4/UDP6 recvmsg hook，因此默认同时启用
TCP/UDP 的 local 或 hybrid 配置需要 Linux 5.2，或包含相应回移的厂商内核。
Android 的主要验证目标仍为 GKI 5.10 及以上。

生成的程序使用 BPF ISA v1，不要求 BTF 或 CO-RE。sing-box 会直接探测所需的
map、program、helper 和挂载能力，而不是只根据内核版本选择路径；新内核挂载与
batch 操作不可用时会自动回退。启动日志会以
`udp_state_cleanup=socket_release` 或 `udp_state_cleanup=lru_fallback` 报告最终
采用的 local UDP 清理路径，并以 `data_plane=socket_assign` 或
`data_plane=rewrite` 报告 shared 数据面。显式启用实验性 UDP assignment 时，
runtime status 还会输出是否启用、独立回退原因和成功/失败计数。`tcp_splice`
状态会输出 attachment 模式、激活与回退、redirect/peer miss，以及已在连接关闭时
结算的上传和下载字节。

即使能力探测成功，本页开头的 Linux 6.6 LPM trie 警告仍然适用。

### 诊断

请以 root 使用与配置一致的模式和协议运行无侵入的纯 Go 探测器：

```sh
sing-box tools ebpf status --mode local --network tcp,udp
sing-box tools ebpf status --mode shared-network --interface br-lan
sing-box tools ebpf status --mode all --interface br-lan --json
```

该命令只创建并立即关闭临时探测对象，不会挂载程序，也不会修改 cgroup、qdisc、
路由、sysctl 或流量状态。使用 `--json` 可生成适合附加到问题报告的结果。

启用 Debug 日志后，sing-box 会记录 map/program ID、挂载健康状态、UDP 清理模式
和汇总失败计数。临时使用 `ebpf_debug` tag 构建时，还会在内核支持的情况下记录
map 占用、维护任务耗时、Go runtime 和内核 BPF 运行统计。采集材料时请参阅
[eBPF 排障指南](/zh/manual/misc/ebpf-troubleshooting/)；`ebpf_debug` 不适合日常
release 构建。
