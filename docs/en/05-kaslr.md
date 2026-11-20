# 05 · KASLR Leak

[中文](../05-kaslr.md) · **English**

> To write kernel memory, the first thing you need is to know where the kernel is.
> This chapter covers how we obtained the KASLR base **without triggering the vulnerability
> at all**, plus the three traps we fell into.

---

## 1. Why KASLR is the first hurdle

We need to write `selinux_state`, whose **link-time address** is `0xffffffc08236a2e0`,
but whose **runtime address** is link-time + slide.

The slide changes on every boot, and:

```
our measured value: slide = 0x2b45280000
                    slide & 0x1fffff = 0x80000     <- only 512KB aligned, not 2MiB!
```

**This "not 2MiB aligned" fact later became the key clue for the entire project (chapter 09).**

---

## 2. Available and unavailable leak channels

| Channel | Usable | Notes |
|---|---|---|
| `/proc/kallsyms` | No | `kptr_restrict` is high; shell sees all zeros |
| `dmesg` | No | `dmesg_restrict` |
| `perf_event_open` | No under Enforcing | requires Permissive |
| **tracefs raw records** | **Yes** | shell is in the `readtracefs` group |
| `debugfs` | No | not mounted |

**Key point: `/sys/kernel/tracing/per_cpu/cpuN/trace_pipe_raw` is 0640, shell is in the
`readtracefs` group and can read it, and its binary records contain real, unhashed pointers.**

---

## 3. Method: the `caller` field of `sched_blocked_reason`

### 3.1 Principle

`get_wchan(task)` returns where a task is blocked inside the kernel — a **kernel code address**.

The `sched/sched_blocked_reason` tracepoint records that value into the raw record.

### 3.2 Record layout

We verified this empirically:

```
event ID = 109
raw offset 16 = void* caller      <- get_wchan(task)
```

### 3.3 Implementation

```c
/* simplified core logic; the full program is tools/kaslr_leak.c */

/* 1) open trace_pipe_raw for every CPU */
for (int cpu = 0; cpu < nr_cpu; cpu++) {
    snprintf(path, sizeof(path),
             "/sys/kernel/tracing/per_cpu/cpu%d/trace_pipe_raw", cpu);
    fd[cpu] = open(path, O_RDONLY | O_NONBLOCK);
}

/* 2) create a task that blocks inside the kernel */
/*    (e.g. have a thread wait on a futex; it will block in a known function) */

/* 3) read the caller out of the raw record */
uint64_t caller;
memcpy(&caller, raw + 16, 8);

/* 4) candidate base = caller - offset_of_known_symbol */
```

### 3.4 Calibration table

We pre-computed a "return address → containing function" table and validated **8 out of 8**
entries landing inside the correct function body.

Then we took a **majority vote** over the candidates:

```
KASLR base=0xffffffd428480000 (5 votes)
```

A vote count ≥ 3 is accepted.

### 3.5 Retry

A single sample can fail (task not blocked / tracing off / buffer full), so:

```c
for (int attempt = 0; attempt < 6; attempt++) {
    /* ... sample + vote ... */
    if (votes >= 3) break;
    usleep(20000);
}
```

**After 6 retries the success rate is close to 100%.**

---

## 4. Second calibration: `page_offset` (linear-map base)

KASLR only locates **code and data-section symbols**. We also need the
"physical page number ↔ kernel virtual address" conversion, which requires `page_offset`.

### Method

```
page_offset = PAGE_OFFSET_CONST - memstart_addr
```

where:

- `PAGE_OFFSET_CONST` for 39-bit VA is `0xffffff8000000000`
- `memstart_addr` is the DRAM start physical address

### Read it from `/proc/zoneinfo`

```console
$ adb shell cat /proc/zoneinfo | head
Node 0, zone   Normal
  start_pfn:    ...
```

```
memstart_addr = start_pfn * 4096
```

### Cross-check: pair "physical page number + object virtual address" from the trace

`kmem:mm_page_alloc` gives a `pfn`.
`kmem:kmem_cache_alloc` gives the object's **kernel virtual address**.

If the same slab page appears in both (page_alloc with a pfn, cache_alloc with a ptr), then:

```
ptr - (pfn << 12) = page_offset
```

**Shark's `calibrate_base()` does exactly this, and requires the result to be 2MiB aligned:**

```c
if ((base & 0x1fffffULL) || base < 0xffffff0000000000ULL ||
    base >= 0xffffffc000000000ULL)
    continue;
```

Our measurement gave `best = 0xffffff7fc0000000` (not the standard
`0xffffff7f80000000`), meaning this SoC's DRAM start PFN differs from the reference value —
**so it must be measured, never copied.**

---

## 5. The three traps you must remember

### Trap 1: `PERF_SAMPLE_TID` is -1 for per-CPU events

We initially filtered samples with `tid == mytid` and **got nothing at all**.

**Cause**: a per-CPU perf event is not associated with a task, so `sample.tid` is `-1`.

**Fix**: drop that filter and discriminate using `bytes_req` / `call_site` instead.

### Trap 2: `bytes_req` is 184, not 192

When looking for cred allocations we initially assumed `bytes_req == 192` (the
`cred_jar` `size`) and caught nothing.

**Reality**: the tracepoint reports `bytes_req` as **`s->object_size` = 184**, while
`bytes_alloc` is the `s->size` = 192.

```
kmem_cache_alloc: call_site=prepare_creds+0x24/0x2fc
                  ptr=... bytes_req=184 bytes_alloc=192
```

**Criteria:**

- `bytes_req == 184` (`sizeof(struct cred)`)
- `(ptr % 4096) % 192 == 0` (`cred_jar` geometry: 21 objects per page)

### Trap 3: the ring buffer overflows — you must drain it frequently

Our first implementation collected **60 records in 1.6 seconds**, nowhere near enough.

**Cause**: the perf ring was not read in time and data was overwritten.

**Fix**: drain **every 20 ms**:

```c
while (1) {
    drain_all_rings();
    if (collected >= want) break;
    usleep(20000);
}
```

**Same duration, 13,861 records — a 230× difference.**

**This was the real reason we "kept getting no samples".**

---

## 6. Additional KASLR findings

### `kptr_restrict` only affects text output

```console
$ adb shell grep kmem_cache_alloc /sys/kernel/tracing/trace | head -2
sh-17367 [007] .... 3451.640059: kmem_cache_alloc:
    call_site=copy_process+0x140/0x1030
    ptr=00000000f13ff2d1                <- hashed in text output
    bytes_req=4800 bytes_alloc=4800
```

**But the binary records in `trace_pipe_raw` contain real, unhashed pointers.**

So: **debug with the text `trace`, obtain real addresses with `trace_pipe_raw`.**

### Verifying symbol offsets

```console
$ python tools/kcalls.py copy_process | grep kmem_cache_alloc
  0xffffffc0800ab938  bl -> kmem_cache_alloc_node+0x0
```

**The return address (`_RET_IP_`) is `0xffffffc0800ab93c`**, low 21 bits = `0xab93c`.

**Identical to Shark's profile value `copy_low21 = 0xab93c`.**
(But that value **cannot be compared directly at runtime** — see [chapter 09](09-root-cause.md).)
