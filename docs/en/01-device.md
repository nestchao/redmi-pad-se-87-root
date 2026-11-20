# 01 · Device Baseline and Environment

[中文](../01-device.md) · **English**

## Hardware

| Item | Value |
|---|---|
| Model | Redmi Pad SE 8.7 |
| Codename | `flare` (`ro.product.device`) |
| Part number | `24075RP89G` |
| SoC | MediaTek **MT8786V/N** |
| Display | 8.7" |
| Bootloader | **locked**, `ro.boot.verifiedbootstate=green` |
| Serial (used in this write-up) | `b82625497d98` |

## System

| Item | Value |
|---|---|
| ROM | HyperOS `OS3.0.303.0.WHXMIXM` |
| Android | 16 |
| Build | `BP2A.250605.031.A3` |
| Security patch | `2026-09-01` |
| `ro.build.version.sdk` | 36 |

## Kernel

```
6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
```

Breaking it down:

| Segment | Meaning |
|---|---|
| `6.6.118` | Linux LTS version |
| `android15-8` | Google GKI branch (**KMI = android15-6.6**) |
| `gc4127a25dcf3` | git short hash |
| `ab15863337` | Android build number |
| `-4k` | 4 KB pages |

**This exact kernel string is the key that matches the Shark profile.**

## Starting privilege

```console
$ adb shell id
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),
1011(adb),1015(sdcard_rw),1028(sdcard_r),1078(ext_data_rw),1079(ext_obb_rw),
3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),
3011(uhid),3012(readtracefs) context=u:r:shell:s0
```

**Two important groups:**

- `3011(uhid)` → can open `/dev/uhid`
- `3012(readtracefs)` → can read files under `/sys/kernel/tracing` (**the foundation of the entire exploit**)

## SELinux

```
$ adb shell getenforce
Enforcing
```

### Measured policy details

**tracefs permissions** (`ls -l /sys/kernel/tracing/`):

```
drwxr-xr-x 6 root readtracefs       /sys/kernel/tracing
-rw-rw-rw- 1 root readtracefs       buffer_size_kb
-rw-rw-rw- 1 root readtracefs       buffer_percent
-rw-r----- 1 root readtracefs       current_tracer
-rw-rw-rw- 1 root readtracefs       trace
-rw-rw-rw- 1 root readtracefs       tracing_on
-rw-rw-rw- 1 root readtracefs       trace_clock
--w--w--w- 1 root readtracefs       trace_marker
-rw-r----- 1 root readtracefs       trace_options
-rwxrwxrwx 1 root readtracefs       kprobe_events      # 0777!
-rwxrwxrwx 1 root readtracefs       uprobe_events      # 0777!
-rw-rw-rw- 1 root readtracefs       synthetic_events
-r--r----- 1 root readtracefs       per_cpu/cpu0/trace_pipe_raw
```

**Conclusions:**

- `tracing_on` / `trace` / `buffer_size_kb` are all world-writable (0666)
- `events/*/enable` is 0666, so any tracepoint can be enabled
- `per_cpu/cpuN/trace_pipe_raw` is 0640 and **shell is in the `readtracefs` group, so it is readable** ← the core channel for the exploit
- `events/*/id` and `format` are 0640 and readable (so event IDs can be discovered)

**However:** whether `kprobe_events` (0777) is actually writable under Enforcing depends on
the SELinux policy; under Permissive it always is.

### Key sysctls

| Path | Value | Meaning |
|---|---|---|
| `/proc/sys/vm/unprivileged_userfaultfd` | `0` | userfaultfd disabled |
| `/proc/sys/kernel/unprivileged_bpf_disabled` | `0` | unprivileged BPF open (but SELinux blocks it under Enforcing) |
| `/proc/sys/kernel/io_uring_disabled` | `0` | io_uring open (same caveat) |
| `/proc/sys/kernel/kptr_restrict` | high | pointers in the text `trace` output are hashed |

**Important:** a high `kptr_restrict` only affects the *text* rendering of `trace`.
The **binary records in `trace_pipe_raw` contain real, unhashed pointers** — this is the
reason the exploit can obtain real addresses at all.

## Attack-surface reachability (measured)

Measured with [`tools/surf_probe.c`](../../tools/surf_probe.c) and
[`surf_probe2.c`](../../tools/surf_probe2.c):

| Entry point | Result |
|---|---|
| `epoll_create1` | ✅ |
| `socket(AF_NETLINK)` | ✅ |
| `open("/dev/binder")` | ✅ (`crw-rw-rw-` 0666) |
| `open("/dev/vhost-vsock")` | ✅ (0666) |
| `open("/dev/uhid")` | ✅ (group uhid) |
| `open("/dev/mali0")` | ✅ (0666) |
| `open("/dev/dri/card0")` | ✅ (0666) |
| `open("/dev/ashmem")` | ✅ (0666) |
| `keyctl(GET_KEYRING_ID)` | ✅ |
| `userfaultfd` | ❌ EPERM |
| `socket(AF_RDS)` | ❌ EACCES (Enforcing) |
| `socket(AF_VSOCK)` | ❌ EACCES (Enforcing) |
| `socket(AF_PACKET)` | ❌ EACCES (Enforcing) |
| `socket(AF_BLUETOOTH)` | ❌ EACCES (Enforcing) |
| `open("/dev/net/tun")` | ❌ EACCES (Enforcing) |

**Note:** the last five become available under **Permissive** — we measured
`io_uring_setup` and `bpf(MAP_CREATE)` returning OK in one Permissive probe run.

## Local threats ruled out

| CVE / mechanism | Status |
|---|---|
| CVE-2026-43499 (rtmutex) | Backported fix present |
| CVE-2026-46242 (Bad Epoll) | Patched |
| CVE-2024-31317 (Zygote injection) | Only affects SPL ≤ 2024-06-01; ours is 2026-09 |
| CVE-2026-49881 (TLPE) | Fixed in SPL 2026-09-01 — exactly our patch level |
| **CVE-2026-98260 (posix cpu timers)** | **Present** ← the one we used |

## Vendor services

```console
$ adb shell service list | grep -i mqsas
216     miui.mqsas.IMQSNative: [miui.mqsas.IMQSNative]
217     miui.mqsas.MQSService: [miui.mqsas.IMQSService]
```

The service exists but is **hardened on this ROM** (see
[03-dead-ends.md](03-dead-ends.md)).
