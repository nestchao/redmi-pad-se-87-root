# 02 · 侦察方法论

**中文** · [English](en/02-methodology.md)

> 这个项目试了非常多路线。能系统地排除它们，靠的不是运气，而是下面这套方法。
> **如果你也在做类似研究，这套方法能帮你省掉大量时间。**

---

## 一、核心原则：用「我们自己的内核」当证据源

网上的文章、CVE 公告、别人的成功报告，**都不能直接用来判断你手上的设备**。

原因：

1. **OEM 会 backport 安全修复**。我们的内核是 `6.6.118`，而 CVE-2026-43499 官方修于 `6.6.140` ——
   按版本号看应该中招，但**实际已经修好了**（小米提前回补了）。
2. **同一个内核版本串，不同机器行为可能不同**。我们的 KASLR 对齐就和他们不一样（见 09 章）。
3. **厂商会阉割功能**。mqsas 服务在，但方法被砍掉了。

**所以：最终判据必须是设备本身的证据。**

---

## 二、方法 A：从内核镜像里验证「补丁在不在」

### 2.1 拿到 vmlinux

我们从设备固件里解出内核镜像，用 `vmlinux-to-elf` 转成带符号的 ELF：

```
recon/vmlinux.elf      ← 9.3 万个符号
链接基址 0xffffffc080000000
```

### 2.2 反汇编看「修复后的代码形状」

以 CVE-2026-43499 为例。修复的内容是：
`remove_waiter()` 从用 `current` 改成用 `waiter->task`。

ARM64 上取 `current` **唯一**的方式是读 `sp_el0`：

```asm
mrs x8, sp_el0
```

所以我们只要看 `remove_waiter` 里有没有这条指令：

```console
$ python tools/kcalls.py remove_waiter
=== remove_waiter @ 0xffffffc08106c758  跨度 0x278 ===
  ...（没有任何 mrs sp_el0）
```

**函数跨度 0x278 字节内 `mrs sp_el0` 出现 0 次 ⇒ 不用 `current` ⇒ 已修复。**

而且能看到清 `pi_blocked_on` 的那句：

```asm
0xffffffc08106c7dc  str xzr, [x20, #0x938]   ; 清 pi_blocked_on
                    ; x20 来自 [x23, #0x50]  ← 从结构体读，不是 current
```

**逐指令确认，不留疑点。**

### 2.3 用「符号命名」当旁证

CVE-2026-46242（Bad Epoll）的修复有一系列重命名提交：

```
eventpoll: rename ep_remove_safe() back to ep_remove()
eventpoll: kill __ep_remove()
eventpoll: drop vestigial __ prefix from ep_remove_{file,epi}()
```

于是符号表本身就是判据：

| 符号 | 修复前 | 修复后 |
|---|---|---|
| `ep_remove_safe` | ✅ 有 | ❌ 无 |
| `__ep_remove` | ✅ 有 | ❌ 无 |
| `ep_remove_epi` | ❌ 无 | ✅ 有 |

我们的内核：**有 `ep_remove` 和 `ep_remove_epi`，没有 `ep_remove_safe` / `__ep_remove`**
⇒ 命名是**修复后**的。

再进一步反汇编确认 `ep_remove` 里有 `epi_fget` 的内联：

```asm
0x431568  ldr   x20, [x21, #0x30]     ; epi->ffd.file
0x43156c  ldr   x8,  [x20, #0x18]     ; file->f_count
0x4315a0  ldxr  x10, [x11]            ; ★ get_file_rcu() 原子递增
0x4315ac  stlxr w12, x9, [x11]
0x4315bc  cbz   x20, 0x4316d4         ; ★ pin 失败跳过临界区
0x4316d0  bl    fput                  ; ★ 释放 pin
```

**pin + 临界区门控 + fput 配对 = 修复形态。**

---

## 三、方法 B：把补丁说明当「探针」

ChangeLog 里的提交说明往往直接写了修复的代码行为。把它翻译成二进制特征：

| 提交说明 | 二进制特征 |
|---|---|
| "Pin @file via epi_fget()" | `fget`/`get_file_rcu` 内联 + `fput` 配对 |
| "Use waiter::task instead of current" | 函数内无 `mrs sp_el0` |
| "defer free to RCU grace period" | 有 `call_rcu` / `kvfree_call_rcu` |
| "pin the target thread" | 有 `put_task_struct` / `__put_task_struct` 调用 |

**注意**：`get_task_struct` / `refcount_inc` 会被内联，**没有 `bl` 不能证明没有**。
所以只在不内联的调用（如 `put_task_struct`、`fput`、`call_rcu`）上做「缺失判定」才可靠。

---

## 四、方法 C：挖自己的内核 ChangeLog

我们下载了 `6.6.119` → `6.6.162` 共 **44 个 ChangeLog、11845 条提交**，全部解析：

```
全部提交        11845
安全关键词命中    2654      （UAF / OOB / race / refcount / dangling …）
安卓可达过滤       270
```

然后按子系统分布，找出「我们版本之后才修的、安卓侧可达的」漏洞。

```python
# 按 subject 前缀和关键词过滤
subs = ['futex','sched','ipc','binder','ashmem','dma-buf','uhid','hidraw',
        'bluetooth','nfc','netlink','packet','unix','sctp','tipc','xfrm',
        'netfilter','f2fs','ext4','erofs','overlayfs','fuse','io_uring',
        'pipe','eventfd','epoll','signalfd','timerfd','aio','splice',
        'seq_file','proc','namespace','bpf','seccomp','cgroup','keyring',
        'selinux','mm/','vmalloc','page_alloc','huge_memory','shmem',
        'memfd','mali','drm','gpu','trace','perf','timer','signal','cred',
        'uid','pid','tty','n_tty','binderfs','incfs','quota','xattr']
sec = re.compile(r'use-after-free|UAF|double free|out-of-bounds|OOB|'
                 r'dangling|refcount|race|TOCTOU|escalat|priv', re.I)
```

**这一步非常有价值**：它直接给出「我们内核之后才修的东西」= 潜在可利用面。

我们从中挖到的候选（部分）：

```
binder          2 条  （6.6.145 修 UAF）
af_unix         2 条
futex           1 条  （6.6.157，但只在 PREEMPT_RT 上有问题 → 排除）
epoll           9 条  （6.6.144 修，但我们已确认修补）
perf            3 条
tracing         6 条
f2fs            6 条
HID             5 条
io_uring       45 条
bpf           202 条
```

**其中 binder 那两条我们判断很可能仍未修补**（见 [03-dead-ends.md](03-dead-ends.md#binder-的两个-uaf66145-修)），
只是工程量大所以没继续。

---

## 五、方法 D：设备侧「可达性探测」

写小工具实测哪些 syscall / 设备节点真的能用：

```c
// tools/surf_probe.c 片段
r = syscall(__NR_io_uring_setup, 8, &p);
printf("io_uring_setup -> %ld errno=%d(%s)\n", r, r<0?errno:0, r<0?strerror(errno):"ok");

fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
printf("open(/dev/binder) -> %d errno=%d\n", fd, fd<0?errno:0);
```

**这能立刻排除掉一大批 CVE**：
- `userfaultfd` 被禁 → 所有 userfaultfd 相关的 CVE 全废
- 没有 NFC 硬件 → 11 个 NFC CVE 全废
- `io_uring` 在 Enforcing 下被 SELinux 拦 → 需要先 Permissive

---

## 六、方法 E：查「别人在同一内核上成功了没有」

在 [`awesome-temporary-root`](https://github.com/fynks/awesome-temporary-root) 的设备表里，
我们找到一条决定性信息：

> POCO X8 Pro (klee, MT6899)
> `6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k`
> Loader: Shark v2.5.1+ (`CVE-2026-98260`) over Shizuku
> KernelSU `ksud 3.3.1`，late-load `--kmi android15-6.6`

**内核串和我们的逐字符相同。** 这条信息直接把我们从「猜」变成「复现」。

而且它给了成功率线索：

> It is a **probabilistic slab race**: the first attempt failed at `fake_uid`
> (`FAIL=cred`, `exit=13`) and the **second succeeded in 6468 ms**

**「第一次失败是正常的」这个信息极其重要** —— 否则我们可能在第一次失败后就放弃了。

---

## 七、这套方法的产出

| 类型 | 数量 |
|---|---|
| 逐条验证并排除的路线 | 13 条 |
| 二进制级确认的「已修复」 | 4 个 CVE |
| 挖出的未修补候选 | ~270 条（其中 binder 2 条最有价值）|
| 最终成功的路线 | 1 条（CVE-2026-98260 + Shark）|

---

## 八、给你的建议

如果你在做类似研究，按这个顺序：

```
1. 先把设备的「事实」测清楚（版本、权限、可达性）
   —— 这决定了一大半 CVE 是否适用

2. 拿到内核镜像，做符号表 + 反汇编
   —— 这是唯一能证明「补丁在不在」的手段

3. 挖自己版本的 ChangeLog，找「之后才修的」
   —— 这给出候选池

4. 逐个用二进制验证候选
   —— 把候选池缩小到 1-2 条

5. 查社区有没有同内核成功案例
   —— 有的话直接复现，不要从零写
```

**最重要的心法：不要相信版本号，要相信反汇编。**
