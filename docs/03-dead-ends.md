# 03 · 所有死路与证据（避雷核心）

**中文** · [English](en/03-dead-ends.md)

> **这一章是为了让你不要重复我们踩过的坑。**
> 每一条都附了判据。如果你手上的设备也在这个范围内，直接跳过。

---

## 目录

- [A. 内核 CVE 类](#a-内核-cve-类)
  - [A1. CVE-2026-43499（GhostLock）](#a1-cve-2026-43499ghostlock)
  - [A2. CVE-2026-46242（Bad Epoll）](#a2-cve-2026-46242bad-epoll)
  - [A3. DirtyFrag / Dirty Pipe](#a3-dirtyfrag--dirty-pipe)
  - [A4. 其他 CVE](#a4-其他-cve)
- [B. 厂商服务类](#b-厂商服务类)
  - [B1. mqsas（重点，三处封堵）](#b1-mqsas重点三处封堵)
  - [B2. Magica](#b2-magica)
- [C. MTK 启动链类](#c-mtk-启动链类)
  - [C1. BROM / mtkclient / penumbra](#c1-brom--mtkclient--penumbra)
  - [C2. fenrir](#c2-fenrir)
  - [C3. lkpatcher](#c3-lkpatcher)
  - [C4. Kamakiri / Heapbait / Carbonara](#c4-kamakiri--heapbait--carbonara)
- [D. 不相干的 CVE](#d-不相干的-cve)
- [E. 仍然可能有戏的（我们没继续）](#e-仍然可能有戏的我们没继续)

---

# A. 内核 CVE 类

## A1. CVE-2026-43499（GhostLock）

**这是 2026 年最热的 Android 临时 root 漏洞，有至少 4 个公开实现：**

- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)（上游 Pixel）
- [BuSung-dev/Root-My-Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy)（三星）
- [yijiacloud/ghostlock-...-4.19-k40](https://github.com/yijiacloud/ghostlock-cve-2026-43499-4.19-k40)（高通 4.19）
- [Delta-Water/CVE-2026-43499-phq110-root](https://github.com/Delta-Water/CVE-2026-43499-phq110-root)（一加）

**漏洞**：`rtmutex` 的 `remove_waiter()` 用 `current` 而不是 `waiter->task`，
导致内核栈上的 `rt_mutex_waiter` 悬垂（CWE-416）。

**官方修复**：Linux 6.6.140，提交 `3bfdc63936dd`
（"rtmutex: Use waiter::task instead of current in remove_waiter()"）

**我们的内核是 6.6.118**，按版本号看**早于**修复。

### 判据：反汇编

```console
$ python tools/kcalls.py remove_waiter
=== remove_waiter @ 0xffffffc08106c758  跨度 0x278 ===
  （没有任何 mrs sp_el0）
```

清 `pi_blocked_on` 的那一句：

```asm
0xffffffc08106c7d4  bl   #0xffffffc08104786c   ; rb_erase(waiter->tree)
0xffffffc08106c7d8  str  x23, [x23]            ; RB_CLEAR_NODE
0xffffffc08106c7dc  str  xzr, [x20, #0x938]    ; 清 pi_blocked_on
                    ; x20 来自 [x23, #0x50] ← 从结构体读
```

**ARM64 上取 `current` 只有 `mrs x, sp_el0` 一条路。函数内 0 次出现 ⇒ 不读 current ⇒ 已修复。**

（函数跨度 0x278，两个 `mrs sp_el0` 在 `0xc9f8` / `0xca94`，
经计算属于**下一个函数** `rt_mutex_wait_proxy_lock`，不在 `remove_waiter` 范围内。）

### 结论

**小米在 6.6.118 里已经 backport 了 6.6.140 的修复。这条完全不通。**

> ⚠️ **教训**：不要按版本号判断。`ghostlock419` 的 README 自己写了
> "OEM kernel 可能提前回补等效修正，因此不能只依版本字串判定" —— 我们亲身体验了一次。

---

## A2. CVE-2026-46242（Bad Epoll）

**网上最诱人的一条**：epoll UAF，公开 PoC 成功率 **约 99%**，明确说影响 Android。

来源：[Bad Epoll 分析](https://labs.cosmicbytez.ca/news/2026-07-04-new-bad-epoll-linux-kernel-flaw-lets-unprivileged-users-gain-root-hits-android)

**官方修复**：Linux 6.6.144，上游 `a6dc643c6931`：

> **Pin @file via epi_fget() at the top of ep_remove()** and gate the critical
> section on the pin succeeding.

### 判据一：符号命名

6.6.144 有一系列重命名：

```
eventpoll: use hlist_is_singular_node() in __ep_remove()
eventpoll: split __ep_remove()
eventpoll: kill __ep_remove()
eventpoll: drop vestigial __ prefix from ep_remove_{file,epi}()
eventpoll: rename ep_remove_safe() back to ep_remove()
```

我们的符号表：

```
ep_remove              0xffffffc0804314f4   ✅
ep_remove_epi          0xffffffc0804308fc   ✅
ep_remove_safe         ❌ 不存在
__ep_remove            ❌ 不存在
```

**⇒ 命名是修复后的形态。**

### 判据二：反汇编 `ep_remove`

```asm
0x431568  ldr   x20, [x21, #0x30]     ; x20 = epi->ffd.file
0x43156c  ldr   x8,  [x20, #0x18]     ; file->f_count
0x431574  add   x9, x8, #1
0x4315a0  ldxr  x10, [x11]            ; ★ atomic_long_inc_not_zero = get_file_rcu()
0x4315ac  stlxr w12, x9, [x11]
0x4315bc  cbz   x20, 0x4316d4         ; ★ pin 失败就跳过临界区
0x4315c0  add   x22, x20, #0x10       ; &file->f_lock
0x4315c8  bl    _raw_spin_lock
0x4315d8  str   x9, [x8]              ; hlist_del_rcu 的 *pprev = next
0x4316d0  bl    fput                  ; ★ 释放 pin
```

**`epi_fget` 内联 + 门控 + `fput` 配对 —— 完全是修复后的形态。**

### 结论

**Bad Epoll 已修补。这条最诱人的路彻底不通。**

---

## A3. DirtyFrag / Dirty Pipe

| CVE | 说明 | 状态 |
|---|---|---|
| CVE-2022-0847（Dirty Pipe） | pipe buffer / page cache 写 | 早就修了 |
| CVE-2026-43284（DirtyFrag） | IPsec ESP 路径的 page cache 写 | **已修** |

`awesome-android-root` 的临时 root 指南只讲这两条 + GhostLock，
**三条在我们设备上全都不通**。

---

## A4. 其他 CVE

| CVE | 原因 |
|---|---|
| CVE-2024-31317 | Zygote 注入，只对 SPL ≤ 2024-06-01；我们是 2026-09-01 |
| CVE-2026-49881（TLPE）| Android 17 Telecom → system_server，**修于 SPL 2026-09-01** —— 我们的 SPL 正是这一天 |
| CVE-2026-2091 | io_uring fixed-file-table TOCTOU，修于 6.6.28，我们 6.6.118 |
| CVE-2025-21479（Adreno micronode）| 高通 GPU，我们是 Mali |
| CVE-2026-21385（Qualcomm Display）| 同上 |
| CVE-2026-31413（BPF verifier）| 影响 6.1 LTS，我们是 6.6 |
| CVE-2026-53365（VsockDrop）| 需要 `AF_VSOCK` socket，Enforcing 下 EACCES |
| CVE-2026-43494（PinTheft）| 需要 `AF_RDS` socket，Enforcing 下 EACCES |

---

# B. 厂商服务类

## B1. mqsas（重点，三处封堵）

**这是最有希望的一条，我们花了很大力气才确认它死了。**

### 背景

`miui.mqsas.IMQSNative` 是小米诊断服务。公开资料（六条独立来源）说它的
**方法 21** 会以 `uid=0` 执行任意脚本：

```bash
service call miui.mqsas.IMQSNative 21 \
    i32 1 s16 '/system/bin/sh' \
    i32 1 s16 '/data/local/tmp/script.sh' \
    s16 '/data/local/tmp/out.txt' i32 180
```

来源：
[XDA 高通小米免解BL](https://xdaforums.com/t/kernelsu-root-without-unlocked-bootloader-for-most-qualcomm-xiaomi-devices.4781779/)、
[XDA ROLLBACK METHOD](https://xdaforums.com/t/tool-unofficial-bootloader-unlock-rollback-method.4802695/)、
[mrdong916/mi_nobl_root](https://github.com/mrdong916/mi_nobl_root)、
[HyperUnlocked #34](https://github.com/ukriu/HyperUnlocked/issues/34)、
[PTT 小米17 免解BL](https://pttdigits.com/MobileComm/1fjGZB-Y)、
[linux.do](https://linux.do/t/topic/1707800/8?page=2)

### 封堵一：方法号 16–30 全部不存在

我们逐个探测方法号 1–30：

```console
$ for i in $(seq 1 30); do
    service call miui.mqsas.IMQSNative $i
  done
```

结果：

```
[1..15]   有响应（各种返回码）
[16..30]  全部 EBADMSG "Not a data message"      ← 方法不存在
```

**⇒ 我们这个 ROM 的 `IMQSNative` 只有 15 个方法，公开 exploit 需要用第 21 个。**

### 封堵二：真正的接口没有 exec 方法，而且 `runCommand` 有白名单

从 `miui-services.jar` 反编译，提取出接口真正的方法：

```
runCommand(String, String, int)                     ← 方法号 4
readFile(String)
captureLogByRunCommand(List, List, String, int)
attachSockFilter(String, String, int×5, byte[], int, String)
getStationInfo(String, String)
setCoreFilter(int, boolean)
flashDebugPolicy(int)
captureLog(...)   // 参数很长
```

`runCommand` 是方法号 **4**，但：

```console
$ adb shell service call miui.mqsas.IMQSNative 4 s16 'id' s16 '' i32 5
Result: Parcel( fffffff8 00000032 'runCommand:145: Command not allowed for shell user')

# 从 uid=0 的 root shell 调用：
Result: Parcel( fffffff8 00000023 'runCommand:152: Command not allowed')
```

**⇒ 有命令白名单。uid 0 能过用户检查，但过不了白名单。**

### 封堵三：后端守护进程根本没在跑

从 `miui-services.jar` 的字符串里挖到：

```
runCommand no mqsasd!
mqsasd not available!
CaptureLog no mqsasd!
```

而设备上：

```console
$ adb shell ps -A | grep mqsasd
（空）
```

**⇒ `mqsasd` 这个 native 守护进程根本没运行，整条路是死的。**

### 其他信息

- 服务由 **`com.miui.daemon`** 提供，运行身份 **`system` (uid 1000)**
- 即使能通过白名单，拿到的也是 uid 1000，**不是 root**

### 结论

**mqsas 在我们这个 ROM（HyperOS 3.0.303.0.WHXMIXM）上彻底封堵。别再试。**

---

## B2. Magica

[vvb2060/Magica](https://github.com/vvb2060/Magica)：
> **Privilege Escalation PoC when seccomp is disabled for Android 10 - Android 16.**

**原理（我们从 AOSP 源码确认了）**：

```cpp
static void ..._nativeInstallSeccompUidGidFilter(...) {
  if (!gIsSecurityEnforced) {
    ALOGI("seccomp disabled by setenforce 0");
    return;                    // ★ permissive 就不装 setuid 过滤器
  }
  ...
}
```

出处：[AOSP Zygote.cpp](https://android.googlesource.com/platform/frameworks/base/+/0bccbf7984e482b66dd4f4f6561b25c6a65af37f/core/jni/com_android_internal_os_Zygote.cpp)、
[提交 86f08a5190c8](https://android.googlesource.com/platform/frameworks/base/+/86f08a5190c8a36497ff3b9848ce3e6d0ba2e951%5e%21/core/java/android/os/ZygoteProcess.java)

**Android 17 用 SafeSetID LSM 才补上。我们是 Android 16 —— 理论上有效。**

### 为什么我们没用这条

需要 **app zygote 在 permissive 状态下被 fork**。而 permissive 期间只有很短的时间窗口，
且要重启 zygote / 清 USAP 池。我们当时选择了更直接的 Shark 路线，所以没有实测这条。

**⇒ 这条可能还有戏**，只是需要：
1. 先打成 Permissive
2. 在窗口内启动一个带 `useAppZygote` 的 App（Magica 本身）
3. 它的 `onBind` 会 `setresuid(0,0,0)`

详见 [12-pitfalls.md](12-pitfalls.md) 里关于 Permissive 窗口的说明。

---

# C. MTK 启动链类

**结论先行：整条线对我们完全不可用。** 原因只有一个 ——
**小米同时开了 BROM SLA + DAA，没有任何免费的 BROM 写入门路。**

---

## C1. BROM / mtkclient / penumbra

[penumbra](https://github.com/shomykohai/penumbra) 是 MTK 工具的权威文档。它的 FAQ 直说：

> **"No signer available" / DA SLA challenge**
> Your device needs additional auth to proceed. Without exploits, this means that
> most of the times you'll need paid auth. While penumbra includes some SLA keys,
> they are **not enough to cover all devices, especially Xiaomi**, OnePlus and some
> other OEMs. **THIS IS NOT A BUG!**

> **SLA on!** ... you'll need to get online auth from **paid tools**,
> or hope for future exploits.

> I get error 0x7017 / 0x7024 on my device when trying to upload DA1
> This means your device has **DAA** on! ... you can only load the official DA
> provided by your device manufacturer.

**⇒ 小米 MTK 设备同时开着 BROM SLA 和 DAA，免费工具完全走不通。**

商业工具（Infinity-Box CM2MT2 v3.00）的更新日志里确实列了
`Xiaomi Redmi-Pad-SE-8-flare` —— 但那是付费授权。

---

## C2. fenrir

[R0rt1z2/fenrir](https://github.com/R0rt1z2/fenrir)：bl2_ext 未验证 → EL3 代码执行。

**为什么不通**：

> This exploit abuses a flaw in the MediaTek boot chain. **When the bootloader is
> unlocked (seccfg)**, the Preloader skips verification of the `bl2_ext` partition

**⇒ 需要先解锁才能用。而且仓库已经归档废弃。**

（唯一有价值的副产品：README 提到有些设备**即使锁定也不校验 bl2_ext**，
检查方法是 dump `expdb` 看 `img_auth_required = 0`。这只有拿到 root 之后才能做，
是「root 后如何永久解锁」的事。）

---

## C3. lkpatcher

[R0rt1z2/lkpatcher](https://github.com/R0rt1z2/lkpatcher)：patch LK + 证书绕过。

README 原文：

> - To successfully boot patched images, **unlock seccfg using mtkclient**.
> - If your device doesn't boot after unlocking with mtkclient, it likely uses
>   **SBC** and is not supported.

**⇒ 需要 mtkclient（BROM）先解锁 seccfg —— 绕回 C1 的死路。**

另外 `patches.json` 里全是 **32 位 Thumb 指令模式**（`2de9f04f...`），
我们是 arm64 LK，未必对得上。

---

## C4. Kamakiri / Heapbait / Carbonara

| 漏洞 | 目标 | 状态 |
|---|---|---|
| **Kamakiri** | BROM `if_info[wIndex]` 无边界检查 + `SendCert` 残留 | 修复加了 `wIndex` 边界检查；2023+ 芯片几乎肯定有 |
| **Heapbait** | DA2 `fp_read_host_file` 堆溢出 | 修复于 2024-11 前后；我们固件 2026-07 → **已修** |
| **Carbonara** | DA1 `boot_to` 可写任意地址 → 覆盖 DA2 hash | 需要**签名 DA1**（DAA），否则 `0xc0070004 DA_HASH_MISMATCH` |

**Carbonara 是唯一理论上还有可能的**（"Devices released during or after 2024
aren't guaranteed to work, but there's been instances"），但需要签名 DA1，
而小米的 DA 是加密/需授权的。

---

# D. 不相干的 CVE

有人在需求里给过这 5 个 CVE 编号：

| CVE | 实际是什么 |
|---|---|
| CVE-2026-123007 | **nginx RCE（NGINX2Root）** |
| CVE-2026-123633 | **nginx HTTP/2 RCE** |
| CVE-2026-123634 | **nginx 内存破坏** |
| CVE-2026-121810 | **NGINX Plus** |
| CVE-2026-113425 | **nginx** |

**全部是 Web 服务器漏洞，和安卓内核提权毫无关系。**

来源：[CrowdStrike](https://www.crowdstrike.com/en-us/blog/crowdstrike-helps-protect-against-nginx2root-cve-2026-123007/)、
[NVD](https://nvd.nist.gov/vuln/detail/cve-2026-123634)、
[cve.org](https://www.cve.org/CVERecord?id=CVE-2026-113425&source=nginx2root.pl)

**另外 NFC 系列（11 条）也全废 —— 设备没有 NFC 硬件（无 `/dev/nfc*`）。**

---

# E. 仍然可能有戏的（我们没继续）

## binder 的两个 UAF（6.6.145 修）

**为什么觉得有戏**：

| 事实 | 证据 |
|---|---|
| 修复在 6.6.145，我们 6.6.118 | ChangeLog |
| 二进制显示**未修补** | `binder_free_transaction` 里**没有** `put_task_struct` / `__put_task_struct`，而这两个符号内核里都存在 |
| 入口是 **0666** | `crw-rw-rw- 1 root root 506, 1 /dev/binderfs/binder` |

**漏洞机制**（来自修复说明）：

```
binder_free_transaction():
  t->to_proc 在 t->lock 下读出来是安全的，但锁一放，目标进程就可能死掉，
  紧接着去拿 to_proc->inner_lock 就是 UAF。
  修复方式：pin 住 t->to_thread。
```

我们的 `binder_free_transaction` 反汇编（0xffffffc080cd0bd0，跨度 0x220）：

```asm
0xcd0be8  ldr  x21, [x0, #0x40]     ; x21 = t->to_proc
0xcd0c14  add  x20, x21, #0x228     ; ★ &to_proc->inner_lock（裸指针）
0xcd0c1c  bl   _raw_spin_lock       ; ★ UAF 就发生在这
0xcd0c20  ldr  w8, [x21, #0x6c]     ; to_proc->tmp_ref
0xcd0c28  str  w2, [x21, #0x6c]     ; ★ 写回 4 字节
0xcd0c3c  add  x0, x21, #0x78
0xcd0c4c  bl   __wake_up            ; ★ 把 to_proc+0x78 当 wait_queue_head
0xcd0c58  str  xzr, [x8, #0x30]     ; ★ 往 [x8+0x30] 写 0
```

**获取原语的思路**：`__wake_up(&to_proc->0x78)` 是任意地址解引用，
如果能回收那块 slab 并用可控内容填充，就能构造任意读写链。

**为什么没继续**：这是竞争型漏洞，工程量大（要写 binder 协议、设计回收、做堆喷），
而当时 Shark 那条线已经看到希望了。

**如果你要试，从这条开始** —— `binder_proc` 是 `kzalloc`，大约 0x2a8 字节，
落在 **kmalloc-1k**，比 98260 的「一页」好回收得多。

## CVE-2026-93189（Joyride，hidraw UAF）

- `hid_hw_stop()` 不等 input 停止 → failed probe 释放 `hidraw`，而 `hidraw_report_event()` 仍在写
- 入口 `/dev/uhid`，**我们的 shell 有 `3011(uhid)` 组**
- 我们只确认了 `hid_hw_stop` 前 0x120 字节里没有 `flush_work` / `cancel_work_sync` / `synchronize_rcu`，
  **没有深入分析**

**这条也还没排除。**

---

## 小结表

| 路线 | 判定 | 可靠度 |
|---|---|---|
| CVE-2026-43499 | ❌ 已修 | 反汇编确认 |
| CVE-2026-46242 Bad Epoll | ❌ 已修 | 符号 + 反汇编确认 |
| DirtyFrag / Dirty Pipe | ❌ 已修 | — |
| mqsas | ❌ 三重封堵 | 逐方法号探测 + 反编译 + 进程检查 |
| Magica | ⚠️ 理论可行，未实测 | AOSP 源码确认机制 |
| MTK BROM 全线 | ❌ SLA + DAA | penumbra 官方文档 |
| nginx 5 个 CVE | ❌ 无关 | — |
| NFC 11 条 | ❌ 无硬件 | — |
| **binder UAF** | ⚠️ **可能有戏** | 二进制显示未修补 |
| **Joyride（hidraw）** | ⚠️ **未深入** | 入口可达 |
| **CVE-2026-98260** | ✅ **成功了** | 见 [10-breakthrough.md](10-breakthrough.md) |
