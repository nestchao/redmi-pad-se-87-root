# 贡献指南 · Contributing

[English below ↓](#contributing-english)

---

## 最想要的三类贡献

### 1. 在别的机型上试了 ✅/❌

**这是最有价值的。** 请在 [Discussions](https://github.com/nestchao/redmi-pad-se-87-root/discussions)
开一个帖子，附上：

```bash
adb shell getprop ro.product.device
adb shell getprop ro.product.model
adb shell uname -r
adb shell getprop ro.build.display.id
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.boot.verifiedbootstate
adb shell '/data/local/tmp/shark66118 probe' 2>&1
```

**成功了**：说一声，我会把你的机型加进 README 的兼容性表。

**失败了**：更要说。失败输出往往比成功更有信息量 —— 尤其是
`[calib] timers=0`（说明也遇到 KASLR 对齐问题，可能只需改 `low_adj` 候选）
和 `PROBE_TIMER_FAIL`（说明事件结构不同）。

---

### 2. 接上我们没走完的两条路

我们在 [03-dead-ends.md](docs/03-dead-ends.md#e-仍然可能有戏的我们没继续) 里
标了两条**尚未排除**的：

| 路线 | 目前状态 | 起点 |
|---|---|---|
| **binder UAF**（6.6.145 修） | 二进制显示未修补（`binder_free_transaction` 无 `put_task_struct`）| `binder_proc` 是 `kzalloc`，约 `0x2a8` 字节，在 **kmalloc-1k**，比 98260 好回收得多 |
| **Joyride / hidraw UAF** | 只确认了 `hid_hw_stop` 前 `0x120` 字节里没有 `flush_work` | 入口 `/dev/uhid`，我们的 shell 有 `3011(uhid)` 组 |

**这两条如果能通，工程量和风险都比 98260 低**（kmalloc-1k vs order-1）。
欢迎开 issue 讨论。

---

### 3. 文档修正 / 补充

- 数字错了、地址不对、命令跑不通 → 直接 PR
- 英文表达不地道 → 也欢迎
- 有更好的图 / 更清楚的解释 → 非常欢迎

**PR 要求**：
- 中文文档改 `docs/NN-*.md`，英文改 `docs/en/NN-*.md`，**两边都改**
- 改动要附**证据**（反汇编输出、实测日志、源码链接）
- 不要凭感觉改数字

---

## 提交 PR 之前

```bash
# 1. 确认没有提交不该提交的东西
git diff

# 2. 如果改了 assets 生成脚本，重新生成并检查图片
python scripts/make-assets.py

# 3. 如果改了工具源码，编译一遍
ANDROID_NDK=/path/to/ndk ./scripts/build.sh
```

**不要提交**：
- `recon/` 目录（我们的本地侦察产物，可能含设备序列号）
- 任何个人设备信息
- 大文件（> 10 MB）除非是必要产物

---

## 行为准则

- **只对自己拥有的设备做实验**
- 讨论技术，不针对个人
- 不问「帮我 root 我的手机」——我们不给别人的设备动手
- 不发布任何未授权的利用代码

---

## 我们不会接受的东西

| 类型 | 原因 |
|---|---|
| 「一键 root 所有小米设备」的整合包 | 内核串必须精确匹配，跨机型需要各自生成 profile |
| 需要解锁 bootloader 的方案 | 那个不需要 exploit，和本项目目标无关 |
| 未验证的「听说这个方法能用」 | 本项目所有结论都有实测或反汇编判据 |
| 含设备的真实序列号 / IMEI | 隐私 |

---

<br>

---

# Contributing (English)

## The three kinds of contribution we want most

### 1. Tried it on another model ✅/❌

**This is the most valuable thing.** Please open a
[Discussion](https://github.com/nestchao/redmi-pad-se-87-root/discussions) with:

```bash
adb shell getprop ro.product.device
adb shell getprop ro.product.model
adb shell uname -r
adb shell getprop ro.build.display.id
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.boot.verifiedbootstate
adb shell '/data/local/tmp/shark66118 probe' 2>&1
```

**If it worked**: tell us, and we will add your model to the compatibility table.

**If it failed**: tell us even more urgently. Failure output is often more informative than
success — especially `[calib] timers=0` (you likely hit the same KASLR alignment issue and
may only need to adjust the `low_adj` candidates) and `PROBE_TIMER_FAIL` (the event layout
differs).

---

### 2. Pick up the two routes we did not finish

We flagged two **not yet ruled out** in
[03-dead-ends.md](docs/en/03-dead-ends.md#e-still-possibly-viable-we-did-not-continue):

| Route | Current state | Where to start |
|---|---|---|
| **binder UAF** (fixed in 6.6.145) | binary looks unpatched (`binder_free_transaction` has no `put_task_struct`) | `binder_proc` is `kzalloc`'d at ~`0x2a8` bytes → **kmalloc-1k**, much easier to reclaim than 98260 |
| **Joyride / hidraw UAF** | we only confirmed no `flush_work` in the first `0x120` bytes of `hid_hw_stop` | entry `/dev/uhid`; our shell has the `3011(uhid)` group |

**If either works, the engineering cost and risk are both lower than 98260**
(kmalloc-1k vs order-1). Open an issue to discuss.

---

### 3. Documentation fixes / additions

- wrong number, wrong address, command does not run → PR directly
- awkward English → also welcome
- better diagrams / clearer explanations → very welcome

**PR requirements:**
- Chinese docs are `docs/NN-*.md`, English are `docs/en/NN-*.md` — **change both**
- every change must come with **evidence** (disassembly output, live log, source link)
- do not change numbers on a hunch

---

## Before opening a PR

```bash
# 1. make sure you are not committing anything you should not
git diff

# 2. if you touched the asset generator, regenerate and inspect the images
python scripts/make-assets.py

# 3. if you touched tool sources, build them
ANDROID_NDK=/path/to/ndk ./scripts/build.sh
```

**Do not commit:**
- the `recon/` directory (local reconnaissance artifacts, may contain device serials)
- any personal device information
- large files (> 10 MB) unless they are a necessary artifact

---

## Code of conduct

- **Only experiment on devices you own**
- Discuss the technology, not the person
- Do not ask "please root my phone" — we do not touch other people's devices
- Do not publish unauthorised exploit code

---

## What we will not accept

| Type | Reason |
|---|---|
| A "one-click root for all Xiaomi devices" bundle | the kernel string must match exactly; each model needs its own profile |
| Anything requiring an unlocked bootloader | that needs no exploit and is out of scope |
| Unverified "I heard this works" | every conclusion here has a measurement or disassembly criterion |
| Real serial numbers / IMEIs | privacy |
