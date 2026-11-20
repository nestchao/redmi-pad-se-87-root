# 02 · Recon Methodology

[中文](../02-methodology.md) · **English**

> This project tried a great many routes. Systematically ruling them out was not luck —
> it was the method below. **If you are doing similar research, this chapter will save
> you an enormous amount of time.**

---

## 1. Core principle: treat your own kernel as the source of truth

Blog posts, CVE advisories and other people's success reports **cannot** be used directly
to judge the device in your hands.

Reasons:

1. **OEMs backport security fixes.** Our kernel is `6.6.118` while CVE-2026-43499 was
   fixed upstream in `6.6.140` — by version number we should be vulnerable, but **the fix
   is actually present** (Xiaomi backported it early).
2. **The same kernel version string can behave differently on different machines.** Our
   KASLR alignment differs from theirs (see chapter 09).
3. **Vendors disable features.** The mqsas service exists, but its methods were removed.

**Therefore: the final verdict must always come from evidence on the device itself.**

---

## 2. Method A: verify "is the patch present" from the kernel image

### 2.1 Obtain vmlinux

We extracted the kernel image from the device firmware and converted it to an ELF with
symbols using `vmlinux-to-elf`:

```
recon/vmlinux.elf      # 93,000 symbols
link base 0xffffffc080000000
```

### 2.2 Disassemble and look for the "fixed" code shape

Take CVE-2026-43499. The fix changes `remove_waiter()` from using `current` to using
`waiter->task`.

On ARM64 the **only** way to read `current` is to read `sp_el0`:

```asm
mrs x8, sp_el0
```

So we simply check whether that instruction appears inside `remove_waiter`:

```console
$ python tools/kcalls.py remove_waiter
=== remove_waiter @ 0xffffffc08106c758  span 0x278 ===
  ... (not a single mrs sp_el0)
```

**Zero occurrences of `mrs sp_el0` within the 0x278-byte function span ⇒ it does not use
`current` ⇒ already fixed.**

We can also see the instruction that clears `pi_blocked_on`:

```asm
0xffffffc08106c7dc  str xzr, [x20, #0x938]   ; clear pi_blocked_on
                    ; x20 comes from [x23, #0x50]  <- read from the struct, not current
```

**Confirmed instruction by instruction, no doubt left.**

### 2.3 Use symbol naming as corroboration

The CVE-2026-46242 (Bad Epoll) fix came with a series of rename commits:

```
eventpoll: rename ep_remove_safe() back to ep_remove()
eventpoll: kill __ep_remove()
eventpoll: drop vestigial __ prefix from ep_remove_{file,epi}()
```

So the symbol table itself becomes evidence:

| Symbol | Pre-fix | Post-fix |
|---|---|---|
| `ep_remove_safe` | present | absent |
| `__ep_remove` | present | absent |
| `ep_remove_epi` | absent | present |

Our kernel has **`ep_remove` and `ep_remove_epi`, and no `ep_remove_safe` / `__ep_remove`**
⇒ the naming is **post-fix**.

Going one step further, we confirmed the inlined `epi_fget` inside `ep_remove`:

```asm
0x431568  ldr   x20, [x21, #0x30]     ; epi->ffd.file
0x43156c  ldr   x8,  [x20, #0x18]     ; file->f_count
0x4315a0  ldxr  x10, [x11]            ; get_file_rcu() atomic increment
0x4315ac  stlxr w12, x9, [x11]
0x4315bc  cbz   x20, 0x4316d4         ; skip critical section if the pin failed
0x4316d0  bl    fput                  ; release the pin
```

**pin + critical-section gate + matching `fput` = the fixed shape.**

---

## 3. Method B: turn patch descriptions into probes

The commit messages in the ChangeLog often describe the code change directly. Translate
them into binary signatures:

| Commit message | Binary signature |
|---|---|
| "Pin @file via epi_fget()" | inlined `fget` / `get_file_rcu` + matching `fput` |
| "Use waiter::task instead of current" | no `mrs sp_el0` in the function |
| "defer free to RCU grace period" | presence of `call_rcu` / `kvfree_call_rcu` |
| "pin the target thread" | calls to `put_task_struct` / `__put_task_struct` |

**Caveat:** `get_task_struct` and `refcount_inc` get inlined, so **the absence of a `bl`
does not prove absence of the pin**. Only use "missing-call" reasoning for calls that are
not inlined (`put_task_struct`, `fput`, `call_rcu`).

---

## 4. Method C: mine your own kernel ChangeLog

We downloaded **44 ChangeLogs covering 6.6.119 → 6.6.162 (11,845 commits)** and parsed them all:

```
all commits              11845
security keyword hits     2654      (UAF / OOB / race / refcount / dangling ...)
Android-reachable          270
```

Then we grouped them by subsystem to find vulnerabilities **fixed after our version and
reachable from Android**.

```python
subs = ['futex','sched','ipc','binder','ashmem','dma-buf','uhid','hidraw',
        'bluetooth','nfc','netlink','packet','unix','sctp','tipc','xfrm',
        'netfilter','f2fs','ext4','erofs','overlayfs','fuse','io_uring',
        'pipe','eventfd','epoll','signalfd','timerfd','aio','splice',
        'seq_file','proc','namespace','bpf','seccomp','cgroup','keyring',
        'selinux','mm/','vmalloc','page_alloc','huge_memory','shmem',
        'memfd','mali','drm','gpu','trace','perf','timer','signal','cred',
        'uid','pid','tty','n_tty','binderfs','incfs','quota','xattr']
sec = re.compile(r'use-after-free|UAF|double free|out-of-bounds|OOB|'
                 r'dangling|refcount|race|TOCTOU|escalat|priv', re.I)
```

**This step is extremely valuable**: it directly yields "what was fixed after our kernel",
i.e. the potential attack surface.

Some candidates we found:

```
binder          2 commits   (UAF fixed in 6.6.145)
af_unix         2 commits
futex           1 commit    (6.6.157, but PREEMPT_RT only -> ruled out)
epoll           9 commits   (fixed in 6.6.144, but we confirmed already patched)
perf            3 commits
tracing         6 commits
f2fs            6 commits
HID             5 commits
io_uring       45 commits
bpf           202 commits
```

**We judged the two binder ones as likely still unpatched** (see
[03-dead-ends.md](03-dead-ends.md#binder-two-uafs-fixed-in-66145)), but did not pursue
them because of the engineering cost.

---

## 5. Method D: device-side reachability probing

Write small tools to measure which syscalls and device nodes actually work:

```c
// excerpt from tools/surf_probe.c
r = syscall(__NR_io_uring_setup, 8, &p);
printf("io_uring_setup -> %ld errno=%d(%s)\n", r, r<0?errno:0, r<0?strerror(errno):"ok");

fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
printf("open(/dev/binder) -> %d errno=%d\n", fd, fd<0?errno:0);
```

**This immediately eliminates a large class of CVEs:**

- `userfaultfd` disabled → every userfaultfd CVE is dead
- no NFC hardware → 11 NFC CVEs are dead
- `io_uring` blocked by SELinux under Enforcing → requires Permissive first

---

## 6. Method E: check whether anyone succeeded on the same kernel

In the device table of
[`awesome-temporary-root`](https://github.com/fynks/awesome-temporary-root) we found the
decisive piece of information:

> POCO X8 Pro (klee, MT6899)
> `6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k`
> Loader: Shark v2.5.1+ (`CVE-2026-98260`) over Shizuku
> KernelSU `ksud 3.3.1`, late-load `--kmi android15-6.6`

**The kernel string is character-for-character identical to ours.** That single entry turned
the problem from "guess" into "reproduce".

It also gave us a success-rate hint:

> It is a **probabilistic slab race**: the first attempt failed at `fake_uid`
> (`FAIL=cred`, `exit=13`) and the **second succeeded in 6468 ms**

**"The first attempt failing is normal" was extremely important** — without it we might have
given up after the first failure.

---

## 7. Output of this methodology

| Type | Count |
|---|---|
| Routes ruled out with per-route evidence | 13 |
| CVEs confirmed "already fixed" at the binary level | 4 |
| Unpatched candidates discovered | ~270 (binder and Joyride being the most interesting) |
| Routes that actually worked | 1 (CVE-2026-98260 + Shark) |

---

## 8. Advice

If you are doing similar research, follow this order:

```
1. Measure the device facts first (version, privilege, reachability)
   -> this decides whether a large fraction of CVEs applies at all

2. Get the kernel image, build a symbol table, disassemble
   -> the only way to prove whether a patch is present

3. Mine the ChangeLog for your own version
   -> this produces the candidate pool

4. Verify each candidate at the binary level
   -> narrow the pool to one or two

5. Check whether the community succeeded on the same kernel
   -> if yes, reproduce; do not write from scratch
```

**The single most important habit: do not trust version numbers, trust disassembly.**
