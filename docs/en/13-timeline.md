# 13 · Research Timeline

[中文](../13-timeline.md) · **English**

> This is a record of a real research process. **Most of the time went into ruling out dead
> ends.**
> If you are stuck at some stage, see what state we were in at the time.

---

## Phase 1: Reconnaissance (rounds 1–30)

### What we did

- Establish the device facts: model, SoC, kernel, SELinux, group membership
- Enumerate every reachable attack surface (`/dev/*`, syscalls, tracefs)
- Collect community material: which CVEs are in the wild

### Key finding

```
two crucial groups in shell's group list:
  3011(uhid)         -> /dev/uhid reachable
  3012(readtracefs)  -> /sys/kernel/tracing readable
```

**`readtracefs` is the foundation of everything that followed.**

### Ruled out in the same phase

- `userfaultfd` disabled
- no NFC hardware
- `io_uring` / `bpf` unavailable under Enforcing

---

## Phase 2: Kernel image analysis (roughly rounds 30–50)

### What we did

- Extracted `vmlinux.elf` from the firmware (93k symbols, link base `0xffffffc080000000`)
- Downloaded 44 ChangeLogs covering `6.6.119` → `6.6.162` (11,845 commits)
- Parsed all of them and grouped by subsystem

### Key output

```
all commits              11845
security keyword hits     2654
Android-reachable          270
```

**This produced the candidate pool.**

### Confirmed already fixed in the same phase

| CVE | Criterion |
|---|---|
| CVE-2026-43499 | no `mrs sp_el0` inside `remove_waiter` (four independent checks) |
| CVE-2026-46242 | `ep_remove` has the `epi_fget` pin + `fput` |
| eventpoll RCU defer | `ep_clear_and_put` calls `kvfree_call_rcu` |

---

## Phase 3: CVE-2026-98260 assault (rounds 38–76, the longest stretch)

### Milestones

| Round | Achievement |
|---|---|
| 38 | **Trigger succeeded** — device kernel panic (proof the UAF is real) |
| 44 | **KASLR stabilised** — tracefs raw-record method, 5/5 correct |
| 47 | **Arbitrary write confirmed** — instruction-level verification of the `rb_erase` primitive |
| 48 | Write primitive confirmed instruction by instruction |
| 51 | BTF cross-validation |
| 53–56 | Audited out 6 self-introduced bugs |
| 57 | Minimal second implementation (`pwn_min`) |
| 63 | Quantitative argument for spray volume |
| 68–70 | **The phase problem** — discovered that the 8 KB slab splits into two halves |
| 73 | One-shot script |
| 74 | KASLR calibration table validated point by point (8/8) |

### Biggest frustration

**"Stage A (make SELinux Permissive) succeeds, but Stage C (rewrite cred to get uid 0) keeps
failing."**

Failure mode:

```
spray 234 MB -> reap immediately -> 50% chance of panic
```

At the time we did not know that "you must confirm the hit before reaping".

### Key discoveries during this phase

- **The pipe carrier is capped at 40 MB by `pipe-user-pages-soft`**
- **`io_setup` gives 60,000 pages / 234 MB / zero failures** ← the carrier breakthrough
- **Phases 0 and 8 both write; 16 is wasted**

---

## Phase 4: Large-scale elimination (after round 77)

### Tried and ruled out

| Route | Time spent |
|---|---|
| MTK BROM / mtkclient / penumbra | a long time (read all the docs) |
| fenrir / lkpatcher | medium |
| mqsas (Xiaomi service) | **a long time** (index probing + jar decompilation) |
| Magica | medium (read AOSP source) |
| binder UAF | medium (disassembly + trigger design) |
| Mali GPU | medium (wrote a pile of probe tools) |
| the 5 nginx CVEs | quickly (confirmed unrelated) |
| various public repos | medium |

**This phase was pure investment with no output — but necessary, because you do not know in
advance which route works.**

### The two most valuable negative results

1. **Bad Epoll (a 99%-reliable PoC) is patched** — saves future effort
2. **mqsas is triple-blocked** — six sources said it works; it does not on our device

---

## Phase 5: The turning point (finding Shark)

### Trigger

The user provided a GitHub link: `awesome-android-root`.

**That repository itself was of limited value** (a docs site covering DirtyFrag / GhostLock,
both already ruled out).

**But it linked a sister project:
[`awesome-temporary-root`](https://github.com/fynks/awesome-temporary-root).**

In that project's device table we found:

> POCO X8 Pro (klee, MT6899)
> `6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k`
> Loader: Shark v2.5.1+ (`CVE-2026-98260`) over Shizuku
> KernelSU `ksud 3.3.1`, late-load `--kmi android15-6.6`

**The kernel string is character-for-character identical to ours.**

And the same page said:

> It is a **probabilistic slab race**: the first attempt failed at `fake_uid`
> (`FAIL=cred`, `exit=13`) and the **second succeeded in 6468 ms**

**"The first attempt failing is normal" saved us.**

### After that

1. Installed the Shark APK → the app always reported `[calib] timers=0`
2. Found logs from running `shark2` manually on the device → `timers=512`, and it **reached `uid=0`**
3. But `euid=2000`, `CapEff=0`

**⇒ the binary works, the source does not ⇒ decide to compile it ourselves and fix it**

---

## Phase 6: Locating the root cause (the breakthrough)

### Timeline

```
1. Compiled the fork source with the NDK -> timers=0
2. Compared with the upstream binary -> timers=512
3. Verified whether copy_process+0x140 = 0xab93c is correct -> it is
4. Enabled the tracepoint from the shell and read text output -> the copy_process event is there
5. Ruled out: constant correct, event present -> only "the low-21 comparison" remains
6. Back-computed: cred log shows site_low=0x164064, link is 0xe4064, difference 0x80000
7. Computed slide & 0x1fffff = 0x80000 -> exact match
8. Conclusion: KASLR is not 2MiB aligned, so the low 21 bits shift
```

**Going from "symptom" to "root cause" took about an hour, but the preceding distraction
elimination took dozens of rounds.**

### The fix

```c
/* try all 4 candidates */
static const unsigned long long cands[4] = {0, 0x80000, 0x100000, 0x180000};
for (int ci = 0; ci < 4; ci++) {
    g_low_adj = cands[ci];
    cc = scan_timer_allocs(...);
    if (cc > c) { c = cc; best_ci = ci; }
}
```

### After the fix

```
[calib] timers=512 low_adj=0x80000
[cred] task=0xffffff807a40cb00 task_recs=1     <- 0 became 1
PROBE_OK
```

**The moment the probe first passed was the best moment of the whole project.**

---

## Phase 7: Full root

### First attempt

```
[+] stage fake_cred  ... burst hit=1 after 48ms
[+] stage selinux    ... burst hit=1 after 132ms
[ksu] panic_on_warn=0
[+] stage fake_uid   ... burst hit=0 after 3093ms      <- just missed
[-] plant1 burst missed; holding zombie
FAIL=fake-uid
```

**But `getenforce` had already become `Permissive`!**

**⇒ only one page reclaim short.**

### Second attempt

```
[+] stage fake_uid   ... burst hit=1 after 103ms
[+] cred writes landed, waking child
[child] woke uid=0 euid=0
[+] child report stage=2 uid=0 euid=0 resuid=0/0/0
PLANT_CRED_OK child=18675
LATE_LOAD_SKIP=env-missing ksud=(null)                <- missing ksud
```

**uid=0 euid=0 achieved, but the ksud path was missing.**

### Third attempt (with ksud)

```
[+] stage fake_uid   ... burst hit=1 after 103ms
[+] cred writes landed, waking child
[child] woke uid=0 euid=0
resuid=0/0/0
PLANT_CRED_OK child=19711
LATE_LOAD_RC=0
LATE_LOAD_SHELL_RC=0
```

```console
$ adb shell grep kernelsu /proc/modules
kernelsu 180224 4 - Live 0x0000000000000000 (O)

$ adb shell su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```

# 🎉

---

## Summary: where the time went

```
recon and attack-surface enumeration   ####................   10%
kernel image analysis                  ####................   10%
98260 assault (Stage A)                ############........   35%
large-scale dead-end elimination       ############........   35%
finding Shark                          ##..................    5%
locating the KASLR root cause          ##..................    5%
```

**80% of the time went into "figuring out what does not work".**

**But without that 80%, the final 20% would have been impossible — because you would not know
where the bug was.**

---

## Three sentences for the next person

1. **Do not trust version numbers; trust disassembly.**
2. **Do not trust "someone says it works"; measure it yourself.**
3. **Leave complete logs and criteria behind when you fail — they will eventually add up to
   the answer.**
