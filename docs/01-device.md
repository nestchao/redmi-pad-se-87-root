# 01 · 设备基线与环境

**中文** · [English](en/01-device.md)

## 硬件

| 项 | 值 |
|---|---|
| 机型 | Redmi Pad SE 8.7 |
| 代号 | `flare`（`ro.product.device` / `ro.boot.product.hardware.sku`）|
| 型号 | `24075RP89G` |
| SoC | MediaTek **MT8786V/N** |
| 屏幕 | 8.7 寸 |
| Bootloader | **locked**，`ro.boot.verifiedbootstate=green` |
| 序列号格式 | `b82625497d98`（本文所有命令用这个） |

## 系统

| 项 | 值 |
|---|---|
| ROM | HyperOS `OS3.0.303.0.WHXMIXM` |
| Android | 16 |
| Build | `BP2A.250605.031.A3` |
| 安全补丁 | `2026-09-01` |
| `ro.build.version.sdk` | 36 |

## 内核

```
6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
```

拆开看：

| 片段 | 含义 |
|---|---|
| `6.6.118` | Linux LTS 版本 |
| `android15-8` | Google GKI 分支（**KMI = android15-6.6**）|
| `gc4127a25dcf3` | git 短哈希 |
| `ab15863337` | Android 构建号 |
| `-4k` | 4 KB 页 |

**这个内核串是精确匹配 Shark profile 的关键标识。**

## 起始权限

```console
$ adb shell id
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),
1011(adb),1015(sdcard_rw),1028(sdcard_r),1078(ext_data_rw),1079(ext_obb_rw),
3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),
3011(uhid),3012(readtracefs) context=u:r:shell:s0
```

**两个关键组**：

- `3011(uhid)` → 可以打开 `/dev/uhid`
- `3012(readtracefs)` → 可以读 `/sys/kernel/tracing` 下的文件（**这是整个漏洞利用的基础**）

## SELinux

```
$ adb shell getenforce
Enforcing
```

### 实测的关键策略点

**tracefs 目录权限**（`ls -l /sys/kernel/tracing/`）：

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
-rwxrwxrwx 1 root readtracefs       kprobe_events      ← 0777！
-rwxrwxrwx 1 root readtracefs       uprobe_events      ← 0777！
-rw-rw-rw- 1 root readtracefs       synthetic_events
-r--r----- 1 root readtracefs       per_cpu/cpu0/trace_pipe_raw
```

**结论**：
- `tracing_on` / `trace` / `buffer_size_kb` 全可写（0666）
- `events/*/enable` 是 0666，可以启用任意 tracepoint
- `per_cpu/cpuN/trace_pipe_raw` 是 0640，**shell 在 readtracefs 组，可读** ← 漏洞利用的核心通道
- `events/*/id` / `format` 是 0640，可读（所以能发现事件 id）

**但**：`kprobe_events`（0777）在 Enforcing 下是否可写，取决于 SELinux 策略；
在 Permissive 下一定可以。

### 关键 sysctl

| 路径 | 值 | 含义 |
|---|---|---|
| `/proc/sys/vm/unprivileged_userfaultfd` | `0` | userfaultfd 被禁 |
| `/proc/sys/kernel/unprivileged_bpf_disabled` | `0` | 非特权 BPF 开放（但 Enforcing 下 SELinux 会拦）|
| `/proc/sys/kernel/io_uring_disabled` | `0` | io_uring 开放（同上）|
| `/proc/sys/kernel/kptr_restrict` | 高 | trace 文本里的指针会被 hash |

**重要**：`kptr_restrict` 高只影响 `trace` 文本输出，
`trace_pipe_raw` 的**二进制记录里是未 hash 的真实地址** —— 这是漏洞能拿到真指针的原因。

## 攻击面可达性（实测）

用 [tools/surf_probe.c](../tools/surf_probe.c) 和 [surf_probe2.c](../tools/surf_probe2.c) 实测：

| 入口 | 结果 |
|---|---|
| `epoll_create1` | ✅ |
| `socket(AF_NETLINK)` | ✅ |
| `open("/dev/binder")` | ✅（`crw-rw-rw-` 0666）|
| `open("/dev/vhost-vsock")` | ✅（0666）|
| `open("/dev/uhid")` | ✅（group uhid）|
| `open("/dev/mali0")` | ✅（0666）|
| `open("/dev/dri/card0")` | ✅（0666）|
| `open("/dev/ashmem")` | ✅（0666）|
| `keyctl(GET_KEYRING_ID)` | ✅ |
| `userfaultfd` | ❌ EPERM |
| `socket(AF_RDS)` | ❌ EACCES（Enforcing）|
| `socket(AF_VSOCK)` | ❌ EACCES（Enforcing）|
| `socket(AF_PACKET)` | ❌ EACCES（Enforcing）|
| `socket(AF_BLUETOOTH)` | ❌ EACCES（Enforcing）|
| `open("/dev/net/tun")` | ❌ EACCES（Enforcing）|

**注意**：后四项在 **Permissive** 下会变成可用（我们实测过 `io_uring_setup` 和 `bpf(MAP_CREATE)`
在 21:06 那次探测里返回 OK）。

## 被判死的本地威胁

| CVE / 机制 | 状态 |
|---|---|
| CVE-2026-43499（rtmutex） | 已 backport 修复 |
| CVE-2026-46242（Bad Epoll） | 已修复 |
| CVE-2024-31317（Zygote 注入）| 只对 2024-06-01 前 SPL，我们是 2026-09 |
| CVE-2026-49881（TLPE）| 修于 SPL 2026-09-01 —— 正好是这一版 |
| **CVE-2026-98260（posix cpu timers）** | **存在** ← 我们用的就是这个 |

## 厂商服务

```console
$ adb shell service list | grep -i mqsas
216     miui.mqsas.IMQSNative: [miui.mqsas.IMQSNative]
217     miui.mqsas.MQSService: [miui.mqsas.IMQSService]
```

服务存在，但**已被封堵**（详见 [03-dead-ends.md](03-dead-ends.md)）。
