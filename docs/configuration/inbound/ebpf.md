---
icon: material/new-box
---

!!! question "Since sing-box 1.14.0"

The eBPF inbound transparently intercepts local or downstream TCP and UDP
traffic. The `local` data path uses cgroup socket-address programs. The
`shared` data path uses TC to intercept forwarded traffic from hotspot, router,
or other downstream interfaces.

It is available on Android and Linux builds compiled with `with_ebpf`. The
runtime does not require cgo, but requires root or equivalent BPF, cgroup, and
network administration privileges.

!!! warning "Linux 6.6 LPM trie compatibility"

    Linux 6.6.0 through 6.6.46 can panic under UBSAN while updating a BPF LPM
    trie. The default `shared_network` host-address policy uses exact-match
    hash maps and is unaffected. Local UID/package filters, `bypass_rule_set`,
    and shared source CIDR filters populate LPM tries and require Linux 6.6.47
    or a vendor kernel containing upstream fix
    `896880ff30866f386ebed14ab81ce1ad3710cfc4`. sing-box rejects those policies
    on a known-unfixed kernel instead of risking a kernel panic.

### Structure

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

The eBPF inbound does not use [listen fields](/configuration/shared/listen/).
sing-box allocates internal listener ports and non-conflicting redirect prefixes.

### mode

| Value | Data path |
|-------|-----------|
| `local` | Intercept local cgroup traffic only. |
| `shared` | Intercept forwarded traffic on selected downstream interfaces only. |
| `hybrid` | Enable both data paths and share bypass policy. |

Default is `local`. `local` fields require local or hybrid mode; `shared`
fields require shared or hybrid mode.

### network

Enabled protocols, `tcp` and/or `udp`. Both are enabled by default.

### udp_timeout

UDP session timeout. Default is `5m`.

### dns_mode

Controls how destination port 53 interacts with bypass policy:

| Value | Behavior |
|-------|----------|
| `hijack` | Intercept DNS before private-address and rule-set bypass checks. |
| `respect_bypass` | Apply bypass checks before deciding whether to intercept DNS. |
| `off` | Do not intercept destination port 53. |

Default is `hijack`. UID, protocol, self-loop, DHCP, and shared client filters
still run before this policy. This captures TCP/UDP port 53 and is not the same
as the `hijack-dns` routing action. UDP must be enabled when shared DNS
interception is active.

### bypass_private_address

Bypass built-in private, carrier-grade NAT, and link-local destinations before
sing-box routing. Default is `true` and applies to both data paths. Setting it
to `false` does not disable protocol, self-loop, DHCP, invalid-address,
loopback, or multicast safety bypasses. In `dns_mode: "hijack"`, destination
port 53 is handled before destination-address bypasses.

### bypass_rule_set

Rule sets whose destination IP CIDRs bypass this inbound. Only CIDRs are
extracted; domains, ports, processes, and other conditions are not evaluated in
the kernel. Map contents are refreshed after rule-set updates. Existing flows
keep their decision until they expire.

### local

#### local.cgroup_path

Absolute cgroup v2 path to intercept. Empty uses the detected cgroup v2 root.
Only one eBPF inbound can own a cgroup path at a time.

#### local.ipv6_mode

| Value | Behavior |
|-------|----------|
| `auto` | Intercept new native IPv6 flows only while a usable IPv6 route exists. |
| `always` | Always enable native IPv6 interception. |
| `off` | Do not intercept native IPv6. |

Default is `auto`. IPv4-mapped IPv6 sockets are still handled as IPv4. This
field does not control shared-path IPv6; use `shared.ipv6_mode` separately.

#### local.include_uid

UIDs to intercept. Once any include UID, range, or package is configured,
other UIDs bypass by default.

#### local.include_uid_range

UID ranges to intercept, in `start:end` format.

#### local.exclude_uid

UIDs to bypass. Exclude takes precedence over include.

#### local.exclude_uid_range

UID ranges to bypass, in `start:end` format.

#### local.include_android_user

Android user IDs to intercept. Android only.

#### local.include_package

Android package names to intercept. Names are resolved to UIDs at startup.

#### local.exclude_package

Android package names to bypass. Packages sharing a UID cannot be distinguished.

Package policy only covers sockets directly created by the resolved UID.
System DNS, `DownloadManager`, isolated processes, SDK sandboxes, and similar
delegated traffic may use another UID. Startup logs show the final include and
exclude UID ranges written to the kernel.

#### local.state_capacity

Capacity for local redirect, UDP flow, and socket-cookie fallback state. `0`
uses the implementation default (currently 65536). Valid range is 0 through
1048576. Larger values consume more locked kernel memory.

### shared

Shared mode does not create a hotspot, DHCP, NAT, IPv6 RA, or IP forwarding.
Those remain the responsibility of Android, Linux, or OpenWrt.

#### shared.interface

==Required in shared or hybrid mode==

Downstream interfaces where client packets enter TC ingress. Interfaces may
appear or disappear after startup; sing-box attaches and detaches automatically.
Do not select `lo`, an upstream interface, or a layer-3-only interface. When a
hotspot and Wi-Fi upstream share an interface name, restrict clients with
source CIDR or MAC policy.

#### shared.ipv6_mode

| Value | Behavior |
|-------|----------|
| `always` | Always intercept IPv6 traffic on selected downstream interfaces. |
| `off` | Do not intercept shared-path IPv6 traffic. |

Default is `always`, which preserves the behavior of earlier versions. `off`
does not block IPv6: when the system can forward IPv6, that traffic bypasses
sing-box. Shared mode does not use local native-route probing because downstream
IPv6 availability and proxy reachability cannot be inferred from the host's
default IPv6 route.

#### shared.include_source_cidr

Client source CIDRs allowed into the proxy path. Non-matching traffic bypasses
when the list is non-empty.

#### shared.exclude_source_cidr

Client source CIDRs to bypass. Exclude takes precedence over include.

#### shared.include_mac_address

48-bit client source MAC addresses allowed into the proxy path.

#### shared.exclude_mac_address

Client source MAC addresses to bypass. Exclude takes precedence over include.

#### shared.state_capacity

Capacity for shared proxy, bypass, and fragment state. `0` uses the
implementation default (currently 65536). Valid range is 0 through 1048576.

#### shared.advanced.tc_priority

TC filter priority in the range 1 through 65535. Default is `1`. Change it only
to coordinate with OpenWrt, Android tethering, or existing TC programs. An
interface can be managed by only one eBPF inbound, regardless of priority.

### Kernel compatibility

Linux 4.19 is the minimum compatibility target for shared mode and TCP-only
local mode. Local UDP also requires the cgroup UDP4/UDP6 recvmsg hooks added by
upstream Linux 5.2, so the default TCP+UDP local or hybrid configuration needs
Linux 5.2 or a vendor backport. Android GKI 5.10+ remains the primary Android
validation target.

The generated programs use the BPF v1 instruction set, contain no verifier
backward jumps, and stay within the Linux 4.19 limit of 4096 instructions per
program. They do not require kernel BTF, CO-RE, TCX, bounded-loop verification,
BPF timers, dynptrs, or kfuncs. Local mode requires cgroup v2 and the selected
socket-address hooks. Shared mode requires `sched_cls`, `clsact`, writable-packet
and checksum helpers. Vendor kernels may backport, disable, or alter individual
features, so direct capability probes are more reliable than the release string.

Run the non-disruptive pure-Go probe as root with the same mode and protocols:

```sh
sing-box tools ebpf status --mode local --network tcp,udp
sing-box tools ebpf status --mode shared-network --interface br-lan
```

The command uses `cilium/ebpf` directly and does not require a shell, `bpftool`,
or `tc`. It creates and closes transient probe objects but never attaches a
program or changes cgroups, qdiscs, routes, sysctls, or traffic.
