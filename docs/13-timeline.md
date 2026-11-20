# 13 · 研究时间线

**中文** · [English](en/13-timeline.md)

> 这是一个真实的研究过程记录。**大部分时间是花在排除死路上的。**
> 如果你正卡在某个阶段，看看我们当时是什么状态。

---

## 阶段一：侦察（第 1–30 轮）

### 做了什么

- 摸清设备：型号、SoC、内核、SELinux、组权限
- 枚举所有可达的攻击面（`/dev/*`、syscall、tracefs）
- 收集社区资料：哪些 CVE 在野

### 关键发现

```
shell 的组里有两个关键项：
  3011(uhid)         → /dev/uhid 可访问
  3012(readtracefs)  → /sys/kernel/tracing 可读
```

**`readtracefs` 是后面一切的基础。**

### 同期排除的

- `userfaultfd` 被禁
- 无 NFC 硬件
- `io_uring` / `bpf` 在 Enforcing 下不可用

---

## 阶段二：内核镜像分析（约第 30–50 轮）

### 做了什么

- 从固件解出 `vmlinux.elf`（9.3 万符号，链接基址 `0xffffffc080000000`）
- 下载 `6.6.119` → `6.6.162` 共 44 个 ChangeLog（11845 条提交）
- 全部解析、按子系统归类

### 关键产出

```
全部提交        11845
安全关键词命中    2654
安卓可达过滤       270
```

**这给出了候选池。**

### 同期确认已修的

| CVE | 判据 |
|---|---|
| CVE-2026-43499 | `remove_waiter` 内无 `mrs sp_el0`（四处验证）|
| CVE-2026-46242 | `ep_remove` 有 `epi_fget` pin + `fput` |
| eventpoll RCU 延迟 | `ep_clear_and_put` 有 `kvfree_call_rcu` |

---

## 阶段三：CVE-2026-98260 攻坚（第 38–76 轮，最长的一段）

### 里程碑

| 轮次 | 成果 |
|---|---|
| 38 | **触发成功** —— 设备 kernel panic（证明 UAF 真实存在）|
| 44 | **KASLR 稳定** —— tracefs raw 记录法，5/5 正确 |
| 47 | **任意写确认** —— 逐指令验证 `rb_erase` 的写原语 |
| 48 | 写原语逐指令确认 |
| 51 | BTF 交叉验证 |
| 53–56 | 审计出 6 个自己引入的 bug |
| 57 | 极简第二实现（`pwn_min`）|
| 63 | 喷射量的定量论证 |
| 68–70 | **相位问题** —— 发现 8KB slab 拆成两半 |
| 73 | 一把梭脚本 |
| 74 | KASLR 标定表逐点校验（8/8）|

### 最大挫折

**「Stage A（打 Permissive）能成功，但 Stage C（改 cred 拿 uid 0）一直失败。」**

失败模式：

```
喷射 234 MB → 直接 reap → 50% 概率 panic
```

我们当时不知道「必须先确认命中再 reap」。

### 期间的关键发现

- **pipe 载体被 `pipe-user-pages-soft` 卡在 40 MB**
- **`io_setup` 能给 60,000 页 / 234 MB / 零失败** ← 载体的突破口
- **相位 0 和 8 都会写成，16 是浪费**

---

## 阶段四：大规模排除（第 77 轮之后）

### 试过并排除的

| 路线 | 花了多久 |
|---|---|
| MTK BROM / mtkclient / penumbra | 很久（读完全部文档）|
| fenrir / lkpatcher | 中等 |
| mqsas（小米服务） | **很久**（逐方法号探测 + 反编译 jar）|
| Magica | 中等（读 AOSP 源码）|
| binder UAF | 中等（反汇编 + 设计触发）|
| Mali GPU | 中等（写了一堆探测工具）|
| 5 个 nginx CVE | 很快（确认无关）|
| 各种公开仓库 | 中等 |

**这一段是纯投入没有产出 —— 但也是必要的，因为不知道哪条能走通。**

### 最有价值的两个负面结论

1. **Bad Epoll（99% 成功率的 PoC）已修补** —— 省得以后白试
2. **mqsas 三重封堵** —— 六条来源都说能用，我们设备上不行

---

## 阶段五：转折（找到 Shark）

### 触发点

用户给了一个 GitHub 仓库链接：`awesome-android-root`。

**那个仓库本身价值不大**（文档站，讲的 DirtyFrag / GhostLock 我们都排除过了）。

**但它链接了一个 sister project：[`awesome-temporary-root`](https://github.com/fynks/awesome-temporary-root)。**

在那个项目的设备表里，我们看到：

> POCO X8 Pro (klee, MT6899)
> `6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k`
> Loader: Shark v2.5.1+ (`CVE-2026-98260`) over Shizuku
> KernelSU `ksud 3.3.1`，late-load `--kmi android15-6.6`

**内核串和我们逐字符相同。**

而且同一页写着：

> It is a **probabilistic slab race**: the first attempt failed at `fake_uid`
> (`FAIL=cred`, `exit=13`) and the **second succeeded in 6468 ms**

**「第一次失败是正常的」这个信息救了我们。**

### 之后

1. 装 Shark APK → App 一直 `[calib] timers=0`
2. 从设备上找到手动跑 `shark2` 的日志 → `timers=512`，而且**打到了 `uid=0`**
3. 但 `euid=2000`、`CapEff=0`

**⇒ 二进制能跑，源码不能 ⇒ 决定自己编译并修**

---

## 阶段六：定位根因（关键突破）

### 时间线

```
① 用 NDK 编译 fork 的源码 → timers=0
② 对比：上游二进制 timers=512
③ 验证 copy_process+0x140 = 0xab93c 常量对不对 → 对
④ 用 shell 开 tracepoint 看文本输出 → copy_process 事件确实在
⑤ 排除：常量对、事件在 → 只剩「低21位比较」这一个变量
⑥ 反推：cred 日志里 site_low=0x164064，链接是 0xe4064，差 0x80000
⑦ 计算 slide & 0x1fffff = 0x80000 → ✅ 完全吻合
⑧ 结论：KASLR 不是 2MiB 对齐，低21位会平移
```

**从「现象」到「根因」花了大约 1 小时，但前面排除干扰花了几十轮。**

### 修复

```c
/* 4 个候选各试一遍 */
static const unsigned long long cands[4] = {0, 0x80000, 0x100000, 0x180000};
for (int ci = 0; ci < 4; ci++) {
    g_low_adj = cands[ci];
    cc = scan_timer_allocs(...);
    if (cc > c) { c = cc; best_ci = ci; }
}
```

### 修复后

```
[calib] timers=512 low_adj=0x80000
[cred] task=0xffffff807a40cb00 task_recs=1     ← 从 0 变 1
PROBE_OK
```

**第一次跑通 probe 的那一刻，是整个项目最爽的时刻。**

---

## 阶段七：拿到完整 root

### 第一次尝试

```
[+] stage fake_cred  ... burst hit=1 after 48ms
[+] stage selinux    ... burst hit=1 after 132ms
[ksu] panic_on_warn=0
[+] stage fake_uid   ... burst hit=0 after 3093ms      ← 差一点
[-] plant1 burst missed; holding zombie
FAIL=fake-uid
```

**但 `getenforce` 已经变成 `Permissive` 了！**

**⇒ 只差一次页回收。**

### 第二次尝试

```
[+] stage fake_uid   ... burst hit=1 after 103ms
[+] cred writes landed, waking child
[child] woke uid=0 euid=0
[+] child report stage=2 uid=0 euid=0 resuid=0/0/0
PLANT_CRED_OK child=18675
LATE_LOAD_SKIP=env-missing ksud=(null)                ← 差 ksud
```

**uid=0 euid=0 了，但缺 ksud 路径。**

### 第三次尝试（补上 ksud）

```
[+] stage fake_uid   ... burst hit=1 after 103ms
[+] cred writes landed, waking child
[child] woke uid=0 euid=0
resuid=0/0/0
PLANT_CRED_OK child=19711
LATE_LOAD_RC=0
LATE_LOAD_SHELL_RC=0
```

```console
$ adb shell grep kernelsu /proc/modules
kernelsu 180224 4 - Live 0x0000000000000000 (O)

$ adb shell su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```

# 🎉

---

## 总结：时间花在哪

```
侦察与攻击面枚举        ████░░░░░░░░░░░░░░░░  10%
内核镜像分析            ████░░░░░░░░░░░░░░░░  10%
98260 攻坚（Stage A）   ████████████░░░░░░░░  35%
大规模排除死路          ████████████░░░░░░░░  35%
找到 Shark              ██░░░░░░░░░░░░░░░░░░   5%
定位 KASLR 根因         ██░░░░░░░░░░░░░░░░░░   5%
```

**80% 的时间花在「搞清楚什么不行」。**

**但如果没有那 80%，最后那 20% 也做不到 ——
因为你会不知道 bug 出在哪里。**

---

## 给后来人的三句话

1. **不要相信版本号，要相信反汇编。**
2. **不要相信「别人说能用」，要自己实测。**
3. **失败要留下完整的日志和判据 —— 它们最终会串成答案。**
