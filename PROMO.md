# 传播素材包 · Promo Kit

[中文](PROMO.md) · [English](PROMO.en.md)

> 这个仓库的价值在于**那个 KASLR 对齐的坑**，而不只是「某台平板能 root」。
> 所以传播的重点应该放在「移植别人 exploit 时容易踩的通用陷阱」——
> 受众从「Redmi Pad SE 用户」扩大到「所有做内核 exploit / 安卓 root 的人」。
>
> **以下文案可直接复制使用。请如实描述，不要夸大。**

---

## 📌 仓库信息

```
仓库:   https://github.com/nestchao/redmi-pad-se-87-root
一句话: Locked bootloader → full root via CVE-2026-98260, and the KASLR-alignment
        bug that makes the public exploit fail silently on 512 KB-aligned devices.
```

**Topics 已设置：**
`android` `root` `kernel-exploit` `cve-2026-98260` `mediatek` `mt8786`
`hyperos` `kaslr` `security-research`

---

## 🐦 X / Twitter

### 推文 1（主推，英文）

```
The public CVE-2026-98260 exploit failed 100% of the time on my tablet.

Not a version mismatch. Not a patched kernel.

    slide & 0x1fffff = 0x80000

It compares low-21-bit slices of call_site against link-time addresses.
My KASLR is 512 KB aligned, not 2 MiB. Every filter silently matched nothing.

Swept 4 candidates. Full root on a locked bootloader.

https://github.com/nestchao/redmi-pad-se-87-root
```

### 推文 2（结果图）

```
uid=0(root) gid=0(root) context=u:r:ksu:s0
CapPrm=CapEff=000001ffffffffff
kernelsu 180224 4 - Live

Bootloader: still LOCKED
Partition writes: 0
Bricks: 0

Full write-up + working binary:
https://github.com/nestchao/redmi-pad-se-87-root
```

### 推文 3（死路清单，容易传播）

```
Spent weeks killing these CVE routes on HyperOS 3.0.303:

❌ GhostLock 2026-43499 — remove_waiter has 0x mrs sp_el0 (backported)
❌ Bad Epoll 2026-46242 — ep_remove has epi_fget pin + fput
❌ mqsas — only 15 methods, runCommand allowlisted, mqsasd not running
❌ MTK BROM — SLA + DAA
❌ userfaultfd — disabled

✅ 2026-98260 — and only after fixing a KASLR alignment bug

13 routes, all with disassembly evidence:
https://github.com/nestchao/redmi-pad-se-87-root
```

### 推文 4（给移植的人，最有价值）

```
If you're porting a kernel exploit and it fails with "found 0 events"
but the tracepoint clearly fires:

check the KASLR alignment.

    slide & 0x1fffff == 0 ?

If not, every hardcoded low-21-bit comparison is off by
(slide & 0x1fffff) and fails silently.

Write-up: https://github.com/nestchao/redmi-pad-se-87-root/blob/main/docs/en/09-root-cause.md
```

---

## 💬 Reddit

### r/AndroidRoot · r/androidroot

**Title:**
```
Locked bootloader → full root on Redmi Pad SE 8.7 (CVE-2026-98260), plus the KASLR bug that makes the public exploit fail silently
```

**Body:**
```
Got full kernel-level root on a Redmi Pad SE 8.7 with the bootloader still locked —
uid=0, u:r:ksu:s0, full capability set, KernelSU loaded, zero partition writes.

The interesting part isn't the device. It's why the published exploit failed first.

## The bug

Shark (the CVE-2026-98260 loader) compares the low 21 bits of each kmem call_site
against the low 21 bits of the LINK-TIME address:

    if ((site & 0x1fffff) != TIMER_SITE_LOW21) continue;

That assumes KASLR is 2 MiB aligned, so the low 21 bits don't change at runtime.
On this device:

    slide = 0x2b45280000
    slide & 0x1fffff = 0x80000      <-- not zero

So every filter shifted by 0x80000 and matched nothing:

    [calib] timers=0
    [cred]  task_recs=0

with no error. The cred path "worked" only because its filter constant is 0 (skipped),
which is also how I confirmed the theory — back-computing from its logged site_low.

## The fix

ARM64 KASLR alignment is a multiple of 0x80000, so slide mod 2 MiB has exactly 4
candidates. Sweep them and keep whichever matches the most events:

    cands[4] = {0, 0x80000, 0x100000, 0x180000}
    for each: counts = scan_timer_allocs(...)
    keep max

Immediately:

    [calib] timers=512 low_adj=0x80000
    [cred]  task_recs=1
    PROBE_OK

Then the three stages ran: fake_cred → selinux=0 → uid=0 → ksud late-load.

## Safety

Never wrote a single partition. Searched the exploit source for /dev/block, by-name,
mmcblk, dd if=, flash, reboot, insmod — zero hits. Bootloader stayed locked the whole time.
Ran it ~20 times total; about 10 panics during early blind-reap experiments, all auto-rebooted.
After the fix: 6 runs, 0 panics, because failures print PARKED and keep the zombie instead
of blindly reaping.

## What I also ruled out (with evidence)

GhostLock (CVE-2026-43499) — remove_waiter has zero `mrs sp_el0`, already uses waiter->task
Bad Epoll (CVE-2026-46242) — ep_remove has the epi_fget pin + fput
mqsas — only 15 methods exist (public exploit needs 21), runCommand is allowlisted,
        and mqsasd isn't even running
MTK BROM — penumbra: Xiaomi enables BROM SLA + DAA
fenrir / lkpatcher — need an already-unlocked bootloader
userfaultfd — disabled on this device

Full 14-chapter write-up (EN + ZH), working binary, patch script, and the diagnostic
tools I wrote are all here:
https://github.com/nestchao/redmi-pad-se-87-root

Happy to answer questions about any of the routes.
```

---

### r/netsec · r/ReverseEngineering

**Title:**
```
Write-up: KASLR alignment granularity breaks bit-slice symbol matching in a public kernel exploit (CVE-2026-98260)
```

**Body:**
```
A methodological post rather than a device post.

Public exploits that match kernel symbols from tracepoint data often use the low 21 bits
of the call_site:

    if ((site & 0x1fffff) != SYM_LOW21) continue;

That is valid only when the KASLR slide is 2 MiB aligned, because then
link_time & 0x1fffff == (link_time + slide) & 0x1fffff.

On MT8786 / 6.6.118 / 4K pages, the slide was 512 KB aligned:

    slide             = 0x2b45280000
    slide & 0x1fffff  = 0x80000

so every such comparison was off by 0x80000 and matched nothing — silently. No error,
no warning: just "0 events found" while the tracepoint demonstrably fired.

Detection trick that generalises: find a filtering path in the same code whose constant
is 0 (i.e. the check is skipped), read the value it logs, and diff it against the
link-time value. That yields (slide mod 2 MiB) exactly:

    0x164064 (runtime) - 0xe4064 (link) = 0x80000

Then sweep the four 0x80000-multiples and keep the one with the most matches.

Also in the write-up:
- why the naive fix of "just raise the match threshold" does not work
- the exact-hit approach: kprobe free_slab(x1) and a kretprobe on __filemap_get_folio,
  compare the returned folio pointer against the freed slab pointer directly
  (both are struct page* aliases) instead of doing vmemmap arithmetic
- 13 other CVE routes ruled out with disassembly evidence

https://github.com/nestchao/redmi-pad-se-87-root
CHAPTER: docs/en/09-root-cause.md
```

---

### r/hacking · r/ExploitDev · r/linuxkernel

略 —— 用上面 r/netsec 的版本，标题改成：

```
Symbol matching by low bits breaks when KASLR isn't 2MiB aligned
```

---

## 🟠 Hacker News

**Title（HN 标题要克制，别用感叹号）:**
```
KASLR alignment granularity breaks low-bit symbol matching in a kernel exploit
```

**URL:** `https://github.com/nestchao/redmi-pad-se-87-root/blob/main/docs/en/09-root-cause.md`

**First comment（自己补一条，解释背景）:**
```
Author here. Background: I was trying to reproduce a temporary-root exploit
(CVE-2026-98260) on a Redmi Pad SE 8.7 with a locked bootloader.

The published source failed with "timers=0" while the upstream binary worked on the same
device. Turned out the source compares the low 21 bits of each kmem call_site against the
link-time address, which only holds if the KASLR slide is 2 MiB aligned. This device's slide
is 512 KB aligned (slide & 0x1fffff = 0x80000), so all low bits shifted and every filter
matched nothing, with no error.

The confirmation came from an unfiltered path in the same code: its logged runtime value
minus the link-time value gave exactly 0x80000.

Fix was to sweep the four possible 0x80000 multiples and keep whichever matched the most
events.

Full repo has 14 chapters (EN + ZH), including 13 other CVE routes I ruled out with
disassembly evidence, and 7 bugs I introduced myself along the way.

Zero partition writes; bootloader stayed locked; ~20 exploit runs, 0 bricks.
```

---

## 📱 XDA Forums

**版块：** Redmi Pad SE 8.7 版 / Android General

**标题：**
```
[GUIDE] Temporary root on Redmi Pad SE 8.7 (locked bootloader) + the KASLR bug that breaks the public exploit
```

**正文用 Reddit 那版，但把 "Hi all" 开头和 "Happy to answer" 结尾改成 XDA 风格：**

```
**What this is**
Full kernel-level root (uid=0, u:r:ksu:s0, full capabilities, KernelSU loaded) on a Redmi
Pad SE 8.7 with the bootloader still locked. Nothing is flashed. Reboot and it's gone.

**Requirements**
- Kernel exactly 6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
- KernelSU manager v3.3.1 (32680) — version must match ksud
- adb

... [Reddit 正文的 The bug / The fix / Safety / What I also ruled out 部分] ...

**Confirmed working commands**

```bash
adb push artifacts/shark-k66118-fixed /data/local/tmp/shark66118
adb push artifacts/ksud-3.3.1        /data/local/tmp/ksud33
adb shell 'chmod 755 /data/local/tmp/shark66118 /data/local/tmp/ksud33'
adb install -r -g KernelSU_v3.3.1_32680-release.apk

# zero-risk self-check
adb shell '/data/local/tmp/shark66118 probe'

# fire (retry if it fails — it's probabilistic, ~2/3)
adb shell "cd /data/local/tmp && \
  PYB110_KSUD=/data/local/tmp/ksud33 \
  PYB110_MANAGER_PKG=me.weishu.kernelsu \
  PYB110_KMI=android15-6.6 \
  ./shark66118 --auto"

adb shell su -c id
```

**Do not try** (all evidence in docs/en/03-dead-ends.md):
GhostLock, Bad Epoll, mqsas, MTK BROM tools, fenrir, lkpatcher.

**Repo:** https://github.com/nestchao/redmi-pad-se-87-root
```

---

## 🇨🇳 中文社区

### V2EX

**节点：** 分享创造 / 信息安全 / Android

**标题：**
```
[开源] 在锁定 bootloader 的小米平板上拿到了完整 root，顺便挖出一个让公开 exploit 静默失败的 KASLR 坑
```

**正文：**
```markdown
折腾了很久，把过程完整开源了。

## 结果

Redmi Pad SE 8.7，bootloader 全程锁定，没刷任何分区，设备没变砖。
拿到了：

    uid=0(root) gid=0(root) context=u:r:ksu:s0
    CapPrm = CapEff = CapBnd = 000001ffffffffff
    kernelsu 180224 4 - Live

是临时 root，重启就没了，跑一条命令就回来。

## 最值钱的部分不是「能 root」，是这个坑

公开的 CVE-2026-98260 exploit（Shark）在我这台机器上 100% 失败：

    [calib] timers=0
    [cred]  task_recs=0

但上游发布的二进制在同一台机器上能跑通。说明源码和二进制行为不一致。

查下来是这样：

    if ((site & 0x1fffff) != TIMER_SITE_LOW21) continue;

它把 kmem tracepoint 里 call_site 的低 21 位，和「链接地址的低 21 位」硬比。
这成立的前提是 KASLR 2MiB 对齐 —— 那样链接地址低21位等于运行时低21位。

但我这台：

    slide            = 0x2b45280000
    slide & 0x1fffff = 0x80000      # 不是 0！512KB 对齐

所以每个过滤条件都偏了 0x80000，永远匹配不上，而且不报错。

## 怎么确认的

同一段代码里有个「不检查低21位」的路径（cred），把它的实测值打出来：

    实测 site_low = 0x164064
    链接地址低21位 = 0x0e4064
    差值 = 0x80000     ← 正好等于 slide mod 2MiB

## 怎么修的

ARM64 的 KASLR 对齐只可能是 0x80000 的倍数，所以 mod 2MiB 只有 4 个候选。
让程序自己试一遍，取命中最多的：

    cands[4] = {0, 0x80000, 0x100000, 0x180000}

改完立刻：

    [calib] timers=512 low_adj=0x80000
    [cred]  task_recs=1
    PROBE_OK

然后就一路 fake_cred → selinux=0 → uid=0 → ksud late-load。

## 免责 / 安全

- 全程零分区写入（我在源码里搜过 /dev/block、by-name、mmcblk、dd if=、flash，一个都没有）
- bootloader 始终 locked
- 跑了约 20 次，早期盲 reap 阶段崩过约 10 次，每次自动重启恢复；修复后 6 次 0 崩
- 变砖 0 次

## 还排除了哪些（都带反汇编证据）

- GhostLock CVE-2026-43499 —— remove_waiter 里 0 次 mrs sp_el0，小米提前回补了
- Bad Epoll CVE-2026-46242 —— ep_remove 有 epi_fget pin + fput，已修
- mqsas —— 方法号只到 15（公开要 21）、runCommand 有白名单、mqsasd 根本没跑
- MTK BROM 全线 —— penumbra 说了，小米同时开 SLA + DAA
- fenrir / lkpatcher —— 需要先解锁，循环依赖
- userfaultfd —— 被禁

## 仓库

https://github.com/nestchao/redmi-pad-se-87-root

14 章中英双语文档、可直接用的二进制、补丁脚本、还有我自己写的一堆诊断工具。

**如果你在别的机型上试了，不管成不成，欢迎回来留个 uname -r 和输出，对别人很有用。**
```

---

### 酷安（酷安发帖要短一些，多图）

**标题：**
```
锁定 BL 拿到完整 root｜顺便挖出一个让公开 exploit 静默失败的 KASLR 坑
```

**正文：**
```
Redmi Pad SE 8.7，BL 全程锁定，没刷分区，没变砖。

uid=0(root)  u:r:ksu:s0  CapEff=000001ffffffffff  kernelsu Live

临时 root，重启即失效。

━━━━━━━━━━━━━━

最值钱的不是「能 root」，是这个坑：

公开的 CVE-2026-98260 exploit 在我机器上 100% 失败（timers=0），
但上游二进制能跑通。查下来是它把 call_site 的低 21 位和
「链接地址低 21 位」硬比 —— 这要求 KASLR 2MiB 对齐。

我这台是 512KB 对齐：

    slide & 0x1fffff = 0x80000

所以每个过滤条件都偏了 0x80000，永远匹配不上，而且不报错。

修法：4 个候选各试一遍，取自校准。

━━━━━━━━━━━━━━

全程零分区写入，我在源码里搜过 dd if= / flash / insmod，一个都没有。
跑了约 20 次，0 次变砖。

完整 14 章中英双语文档 + 可用二进制 + 补丁脚本都在 GitHub：
https://github.com/nestchao/redmi-pad-se-87-root

配图建议：banner-zh.png + chain.png + decision-tree-zh.png（仓库 assets/ 里）
```

---

### 知乎

**问题：** 「如何评价安卓免解锁 root 的研究现状？」或自建文章

**标题：**
```
一个 KASLR 对齐假设，如何让公开的内核 exploit 在特定设备上 100% 静默失败
```

**开头（知乎要讲故事）：**
```
先说结论：

一台锁定 bootloader 的小米平板，我用 CVE-2026-98260 拿到了完整内核级 root。
但我更想讲的不是这个结果，而是中间卡了很久的一个坑 ——
它不涉及任何高深技术，只是「一个作者在自己机器上验证过的假设」。

...
```

后面用 V2EX 那版的正文。

---

### B站 / 抖音 / 小红书（视频/图文）

**标题：**
```
锁定Bootloader也能拿完整root？我踩的坑比漏洞本身更值钱
```

**文案（视频简介）：**
```
Redmi Pad SE 8.7 免解锁拿完整 root 全记录。
最关键的不是漏洞利用，是一个让公开 exploit 静默失败的 KASLR 对齐问题。

0 分区写入，0 变砖，临时 root。

完整开源（14 章中英双语文档）：
https://github.com/nestchao/redmi-pad-se-87-root
```

**话题标签：** `#安卓root` `#逆向工程` `#内核漏洞` `#小米平板` `#KASLR`

---

### Telegram / Discord 技术群

短版，直接贴：

```
Locked-bootloader full root on Redmi Pad SE 8.7 via CVE-2026-98260.

The interesting bit: the public exploit compares low-21-bit slices of kmem call_site
against link-time addresses, which assumes a 2 MiB-aligned KASLR slide. This device is
512 KB aligned (slide & 0x1fffff = 0x80000), so every filter silently matched nothing.
Fixed by sweeping the 4 possible 0x80000 multiples.

Also ruled out 13 other CVE routes with disassembly evidence (GhostLock, Bad Epoll,
mqsas, MTK BROM, ...). Zero partition writes, bootloader stayed locked.

https://github.com/nestchao/redmi-pad-se-87-root
```

---

## 📚 Awesome list 投递

这几个列表接受 PR，加进去能持续带来流量：

| 仓库 | 加在哪 |
|---|---|
| [fynks/awesome-temporary-root](https://github.com/fynks/awesome-temporary-root) | 设备表里加一行（同内核的 klee 已经在里面了，可以补一条 cross-reference）|
| [awesome-android-root/awesome-android-root](https://github.com/awesome-android-root/awesome-android-root) | Research / Write-ups 区 |
| [jiayy/android-hackers-treasure](https://github.com/jiayy/android-hackers-treasure) | 内核漏洞利用资料 |
| [ashishb/android-security-awesome](https://github.com/ashishb/android-security-awesome) | 工具/研究区 |
| [shijunqiang/awesome-android-security](https://github.com/shijunqiang/awesome-android-security) | 同上 |

**PR 里加的条目：**
```markdown
- [redmi-pad-se-87-root](https://github.com/nestchao/redmi-pad-se-87-root) —
  Locked-bootloader full root on Redmi Pad SE 8.7 via CVE-2026-98260.
  14-chapter write-up (EN/ZH) covering 13 ruled-out CVE routes with disassembly
  evidence, and a KASLR-alignment bug that makes public exploits fail silently on
  512 KB-aligned devices.
```

---

## 🎯 传播优先级建议

| 优先级 | 渠道 | 理由 |
|---|---|---|
| **1** | r/AndroidRoot | 受众完全匹配，转化率最高 |
| **2** | XDA（Redmi Pad SE 版） | 长尾流量，搜索引擎收录好 |
| **3** | 酷安 | 中文小米用户聚集地 |
| **4** | r/netsec | 受众质量高，会真的读代码 |
| **5** | V2EX | 中文技术圈，容易被转发 |
| **6** | Hacker News | 上首页的话流量爆炸（但技术要求高）|
| **7** | Awesome list PR | 长期被动流量 |
| **8** | 知乎 / B站 | 中文长尾 |

**发帖节奏建议**：先 Reddit + XDA（英文），观察反馈修 README；
两三天后再发中文渠道，用英文社区的反馈做背书。

---

## ⚠️ 发帖注意

1. **不要标题党到失真** —— 说「locked bootloader full root」是真的，
   但别写成「一键 root 所有小米平板」。
2. **一定要写「临时 root / 重启失效」** —— 否则会有人以为持久化。
3. **一定要写「仅适用于确切内核」** —— 内核串不匹配会失败。
4. **别碰别人的设备** —— 只在自有设备上做。
5. **回复优先** —— 社区里有人问「我的 X 机型能行吗」，认真回答比多发帖更能涨 star。

---

## 📈 衡量效果

发出去之后看这几个指标：

```bash
gh api repos/nestchao/redmi-pad-se-87-root --jq '.stargazers_count, .forks_count, .subscribers_count'
gh api repos/nestchao/redmi-pad-se-87-root/traffic/views --jq '.count'
gh api repos/nestchao/redmi-pad-se-87-root/traffic/popular/referrers --jq '.[] | "\(.referrer) \(.count)"'
```

**最有价值的信号不是 star 数，是有人回来报告「我在 XX 机型上试了，结果是 YY」。**
那说明这个仓库真的被用起来了。
