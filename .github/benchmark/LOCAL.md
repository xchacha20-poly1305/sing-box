# Local transparent inbound benchmarking

This guide covers repeatable local runs outside GitHub Actions. Standard Linux
can use the automated namespace topology. Rooted Android uses the same traffic
generator but requires a physical remote endpoint and device-specific routing.

## Standard Linux

### Requirements

Use a disposable test host or VM with root access, cgroup v2, and a kernel that
supports the selected inbound. Install Go, `iproute2`, `iptables`/`ip6tables`,
`nftables`, `jq`, `curl`, `ethtool`, `iputils-ping`, `procps`, and `util-linux`.
The automated script creates only names prefixed with `sb-bench-` and a cgroup
prefixed with `sing-box-benchmark-`, then removes them on exit.

Build the release binary, diagnostic binary, and traffic generator. CGO and an
Android NDK are not required for this Linux harness:

```sh
mkdir -p build/inbound-benchmark
CGO_ENABLED=0 go build -trimpath -tags with_ebpf,with_gvisor \
  -o build/inbound-benchmark/sing-box ./cmd/sing-box
CGO_ENABLED=0 go build -trimpath -tags with_ebpf,with_gvisor,ebpf_debug \
  -o build/inbound-benchmark/sing-box-ebpf-debug ./cmd/sing-box
CGO_ENABLED=0 go build -trimpath \
  -o build/inbound-benchmark/interception-bench \
  ./cmd/internal/interception_bench
```

Run a short functional smoke test first:

```sh
sudo .github/benchmark/run-inbound-benchmark.sh \
  --sing-box "$PWD/build/inbound-benchmark/sing-box" \
  --debug-sing-box "$PWD/build/inbound-benchmark/sing-box-ebpf-debug" \
  --benchmark "$PWD/build/inbound-benchmark/interception-bench" \
  --output "$PWD/build/inbound-benchmark/smoke-ipv4" \
  --family ipv4 \
  --duration 200ms \
  --warmup 50ms \
  --repetitions 1 \
  --concurrency 2 \
  --profile-seconds 0
```

Repeat with a new output directory and `--family ipv6`. A normal comparison
should use longer sampling and at least five randomized repetitions:

```sh
sudo .github/benchmark/run-inbound-benchmark.sh \
  --sing-box "$PWD/build/inbound-benchmark/sing-box" \
  --debug-sing-box "$PWD/build/inbound-benchmark/sing-box-ebpf-debug" \
  --benchmark "$PWD/build/inbound-benchmark/interception-bench" \
  --output "$PWD/build/inbound-benchmark/results-ipv4" \
  --family ipv4 \
  --duration 30s \
  --warmup 5s \
  --repetitions 5 \
  --concurrency 16 \
  --tcp-payload-size 32768 \
  --udp-payload-size 1200 \
  --profile-seconds 15
python3 .github/benchmark/summarize.py \
  build/inbound-benchmark/results-ipv4
```

Limit an A/B run with `--variants` and `--scenarios`, for example:

```sh
--variants direct,ebpf-local,tun-mixed,tun-mixed-auto-redirect \
--scenarios tcp-short,udp-pps,udp-churn
```

Use `--ebpf-policy-prefixes 4096` in a separate run to measure a large
non-matching bypass policy. Never compare that result against an eBPF run with
zero prefixes without labeling the policy difference.

After an interrupted run, verify that no test resources remain:

```sh
ip netns list | grep '^sb-bench-' || true
find /sys/fs/cgroup -maxdepth 1 -type d \
  -name 'sing-box-benchmark-*' -print
```

### Measurement hygiene

Prefer a bare-metal host with a fixed performance governor and stable cooling.
Stop unrelated workloads, keep offloads unchanged across variants, and retain
the complete output directory. Monitor temperature and frequency separately;
discard a run that throttles. Do not run two benchmark jobs concurrently.

For short-connection pressure, increase `--concurrency` and select `tcp-short`.
For UDP state pressure, select `udp-churn` and test several concurrency levels.
For datagram behavior, run separate 64, 512, 1200, and 1400 byte experiments.
A 10-30 minute soak is useful for lifecycle stability, but should not be merged
with short steady-state throughput samples.

## Rooted Android

Android results must be collected on a physical device. Do not compare their
absolute values directly with the namespace topology: Android GKI, tethering,
thermal controls, UID policy, and network drivers are different.

### Build and deploy

Build sing-box for arm64 using the normal project command. For example:

```sh
TAGS=with_gvisor,with_quic,with_dhcp,with_utls,with_clash_api,with_ebpf,ebpf_debug,badlinkname,tfogo_checklinkname0 \
CGO_ENABLED=1 \
CC="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang" \
GOARCH=arm64 GOOS=android make build
```

The traffic generator itself is pure Go:

```sh
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -trimpath \
  -o build/interception-bench-android-arm64 \
  ./cmd/internal/interception_bench
adb push build/interception-bench-android-arm64 /data/local/tmp/interception-bench
adb shell chmod 0755 /data/local/tmp/interception-bench
```

Run the generator server on a wired Linux host or another quiet device reachable
through the tested network:

```sh
./interception-bench -mode server -listen :5201
```

Confirm direct connectivity from `adb shell` before enabling interception:

```sh
/data/local/tmp/interception-bench -mode client \
  -target SERVER_IP:5201 -scenario all -duration 30s -warmup 5s \
  -concurrency 16 -tcp-payload-size 32768 -udp-payload-size 1200
```

An `adb shell` client normally runs as UID 2000. Verify with `id -u`, and use the
observed UID in the local eBPF policy. Package-name tests are inappropriate for
this generator because the shell directly creates the sockets.

### Comparable inbound configurations

Use the same direct outbound, destination, payloads, log level, and client UID in
every run. Disable DNS hijack, sniffing, unrelated routing rules, and bypass rule
sets for the baseline comparison.

For local eBPF, configure the actual cgroup v2 path used by the shell process and
include UID 2000:

```json
{
  "type": "ebpf",
  "tag": "benchmark-in",
  "mode": "local",
  "network": ["tcp", "udp"],
  "local": {
    "dns_mode": "off",
    "cgroup_path": "/sys/fs/cgroup",
    "include_uid": [2000],
    "ipv6_mode": "auto",
    "bypass_private_address": false
  }
}
```

For TUN, keep `stack: mixed` and `auto_route: true`. Run exactly two variants by
changing only `auto_redirect`:

```json
{
  "type": "tun",
  "tag": "benchmark-in",
  "interface_name": "sb-benchmark",
  "address": ["172.19.0.1/30", "fd89:19::1/126"],
  "stack": "mixed",
  "auto_route": true,
  "auto_redirect": false,
  "include_uid": [2000],
  "route_address": ["SERVER_IP/32"]
}
```

Use `/128` for an IPv6 server. Repeat with `auto_redirect: true`; do not change
the stack or route scope between those runs.

Redirect is TCP-only. TProxy and Redirect firewall rules must match only UID
2000, the server address, protocol, and port, and must exclude sing-box itself.
Android ROMs differ in their netfilter chains and policy routing, so record the
exact `iptables-save`/`ip6tables-save` and `ip rule` output rather than applying
an unreviewed generic device-wide rule set. Remove the exact rules immediately
after each run.

Shared eBPF cannot be measured by traffic originating in `adb shell` on the same
device. Enable a dedicated hotspot/downstream interface and run the client on a
second device connected through it. Record the actual downstream interface and
use only that interface in `shared.interface`.

### Android evidence to retain

For every run, keep:

- sing-box commit, build tags, config, complete debug log, and raw JSON;
- `uname -a`, relevant `getprop` output, device model, and Android security patch;
- `id`, cgroup path, interface addresses, routes, rules, and firewall state;
- `/proc/PID/status`, thermal and battery state before and after the run;
- eBPF startup/shutdown runtime status and pprof captures from
  `experimental.debug.listen` when diagnostics are enabled.

Run normal throughput with a non-`ebpf_debug` binary. Use the debug build only
for a separate reproduction or diagnostic phase; its map scans, Go metrics, and
kernel BPF runtime statistics intentionally add observation overhead.
