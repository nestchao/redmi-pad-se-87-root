# Promo Kit

[中文](PROMO.md) · **English**

> The value of this repo is **the KASLR alignment trap**, not just "one tablet got rooted".
> So the pitch should focus on the *universal porting pitfall* —
> that widens the audience from "Redmi Pad SE owners" to "anyone doing kernel exploits or
> Android root".
>
> **Everything below is copy-paste ready. Stay factual; do not exaggerate.**

---

## 📹 There is a film now

**Lead with the video.** Video posts travel much further than link-only posts.

| File | Direct URL |
|---|---|
| 43-second film (1920×1080, 30 fps) | https://github.com/nestchao/redmi-pad-se-87-root/releases/download/v1.2.0/promo-98260.mp4 |
| Poster frame | https://github.com/nestchao/redmi-pad-se-87-root/releases/download/v1.2.0/promo-poster.jpg |
| Score only (for your own re-cut / other languages) | https://github.com/nestchao/redmi-pad-se-87-root/releases/download/v1.2.0/promo-score.wav |

**Every post below works better with the film attached + the repo link** rather than the
repo link alone. On X, post the video natively and put the link in the reply.

**Note on vertical:** only 16:9 exists so far. Reels / Shorts / 小红书 need 9:16, and that
is not a crop — the layouts are left-anchored, so a vertical cut would leave the right half
empty. The project is plain HTML + GSAP, so a vertical pass means re-blocking each scene,
not just resizing the canvas.

---

## 📌 Repo facts

```
Repo:  https://github.com/nestchao/redmi-pad-se-87-root
Hook:  Locked bootloader → full root via CVE-2026-98260, and the KASLR-alignment bug
       that makes the public exploit fail silently on 512 KB-aligned devices.
```

**Topics already set:**
`android` `root` `kernel-exploit` `cve-2026-98260` `mediatek` `mt8786`
`hyperos` `kaslr` `security-research`

---

## 🐦 X / Twitter

### Post 1 (main, English)

```
The public CVE-2026-98260 exploit failed 100% of the time on my tablet.

Not a version mismatch. Not a patched kernel.

    slide & 0x1fffff = 0x80000

It compares low-21-bit slices of call_site against link-time addresses.
My KASLR is 512 KB aligned, not 2 MiB. Every filter silently matched nothing.

Swept 4 candidates. Full root on a locked bootloader.

https://github.com/nestchao/redmi-pad-se-87-root
```

### Post 2 (result)

```
uid=0(root) gid=0(root) context=u:r:ksu:s0
CapPrm=CapEff=000001ffffffffff
kernelsu 180224 4 - Live

Bootloader: still LOCKED
Partition writes: 0
Bricks: 0

Full write-up + working binary:
https://github.com/nestchao/redmi-pad-se-87-root
```

### Post 3 (dead-end list — very shareable)

```
Spent weeks killing these CVE routes on HyperOS 3.0.303:

x GhostLock 2026-43499 — remove_waiter has zero mrs sp_el0 (backported)
x Bad Epoll 2026-46242 — ep_remove has epi_fget pin + fput
x mqsas — only 15 methods, runCommand allowlisted, mqsasd not running
x MTK BROM — SLA + DAA
x userfaultfd — disabled

v 2026-98260 — and only after fixing a KASLR alignment bug

13 routes, all with disassembly evidence:
https://github.com/nestchao/redmi-pad-se-87-root
```

### Post 4 (for people porting exploits — the most valuable one)

```
If you're porting a kernel exploit and it fails with "found 0 events"
while the tracepoint clearly fires:

check the KASLR alignment.

    slide & 0x1fffff == 0 ?

If not, every hardcoded low-21-bit comparison is off by
(slide & 0x1fffff) and fails silently.

Write-up: https://github.com/nestchao/redmi-pad-se-87-root/blob/main/docs/en/09-root-cause.md
```

---

## 💬 Reddit

### r/AndroidRoot · r/androidroot

**Title:**
```
Locked bootloader → full root on Redmi Pad SE 8.7 (CVE-2026-98260), plus the KASLR bug that makes the public exploit fail silently
```

**Body:**
```
Got full kernel-level root on a Redmi Pad SE 8.7 with the bootloader still locked —
uid=0, u:r:ksu:s0, full capability set, KernelSU loaded, zero partition writes.

The interesting part isn't the device. It's why the published exploit failed first.

## The bug

Shark (the CVE-2026-98260 loader) compares the low 21 bits of each kmem call_site
against the low 21 bits of the LINK-TIME address:

    if ((site & 0x1fffff) != TIMER_SITE_LOW21) continue;

That assumes KASLR is 2 MiB aligned, so the low 21 bits don't change at runtime.
On this device:

    slide = 0x2b45280000
    slide & 0x1fffff = 0x80000      <-- not zero

So every filter shifted by 0x80000 and matched nothing:

    [calib] timers=0
    [cred]  task_recs=0

with no error. The cred path "worked" only because its filter constant is 0 (skipped),
which is also how I confirmed the theory — back-computing from its logged site_low.

## The fix

ARM64 KASLR alignment is a multiple of 0x80000, so slide mod 2 MiB has exactly 4
candidates. Sweep them and keep whichever matches the most events:

    cands[4] = {0, 0x80000, 0x100000, 0x180000}
    for each: counts = scan_timer_allocs(...)
    keep max

Immediately:

    [calib] timers=512 low_adj=0x80000
    [cred]  task_recs=1
    PROBE_OK

Then the three stages ran: fake_cred -> selinux=0 -> uid=0 -> ksud late-load.

## Safety

Never wrote a single partition. Searched the exploit source for /dev/block, by-name,
mmcblk, dd if=, flash, reboot, insmod — zero hits. Bootloader stayed locked the whole time.
Ran it ~20 times total; about 10 panics during early blind-reap experiments, all auto-rebooted.
After the fix: 6 runs, 0 panics, because failures print PARKED and keep the zombie instead
of blindly reaping.

## What I also ruled out (with evidence)

GhostLock (CVE-2026-43499) — remove_waiter has zero `mrs sp_el0`, already uses waiter->task
Bad Epoll (CVE-2026-46242) — ep_remove has the epi_fget pin + fput
mqsas — only 15 methods exist (public exploit needs 21), runCommand is allowlisted,
        and mqsasd isn't even running
MTK BROM — penumbra: Xiaomi enables BROM SLA + DAA
fenrir / lkpatcher — need an already-unlocked bootloader
userfaultfd — disabled on this device

Full 14-chapter write-up (EN + ZH), working binary, patch script, and the diagnostic
tools I wrote are all here:
https://github.com/nestchao/redmi-pad-se-87-root

Happy to answer questions about any of the routes.
```

---

### r/netsec · r/ReverseEngineering

**Title:**
```
Write-up: KASLR alignment granularity breaks bit-slice symbol matching in a public kernel exploit (CVE-2026-98260)
```

**Body:**
```
A methodological post rather than a device post.

Public exploits that match kernel symbols from tracepoint data often use the low 21 bits
of the call_site:

    if ((site & 0x1fffff) != SYM_LOW21) continue;

That is valid only when the KASLR slide is 2 MiB aligned, because then
link_time & 0x1fffff == (link_time + slide) & 0x1fffff.

On MT8786 / 6.6.118 / 4K pages, the slide was 512 KB aligned:

    slide             = 0x2b45280000
    slide & 0x1fffff  = 0x80000

so every such comparison was off by 0x80000 and matched nothing — silently. No error,
no warning: just "0 events found" while the tracepoint demonstrably fired.

Detection trick that generalises: find a filtering path in the same code whose constant
is 0 (i.e. the check is skipped), read the value it logs, and diff it against the
link-time value. That yields (slide mod 2 MiB) exactly:

    0x164064 (runtime) - 0xe4064 (link) = 0x80000

Then sweep the four 0x80000-multiples and keep the one with the most matches.

Also in the write-up:
- why the naive fix of "just raise the match threshold" does not work
- the exact-hit approach: kprobe free_slab(x1) and a kretprobe on __filemap_get_folio,
  compare the returned folio pointer against the freed slab pointer directly
  (both are struct page* aliases) instead of doing vmemmap arithmetic
- 13 other CVE routes ruled out with disassembly evidence

https://github.com/nestchao/redmi-pad-se-87-root
CHAPTER: docs/en/09-root-cause.md
```

---

### r/hacking · r/ExploitDev · r/linuxkernel

Use the r/netsec body above with the title:

```
Symbol matching by low bits breaks when KASLR isn't 2MiB aligned
```

---

## 🟠 Hacker News

**Title (HN titles should be restrained, no exclamation marks):**
```
KASLR alignment granularity breaks low-bit symbol matching in a kernel exploit
```

**URL:** `https://github.com/nestchao/redmi-pad-se-87-root/blob/main/docs/en/09-root-cause.md`

**First comment (post it yourself for context):**
```
Author here. Background: I was trying to reproduce a temporary-root exploit
(CVE-2026-98260) on a Redmi Pad SE 8.7 with a locked bootloader.

The published source failed with "timers=0" while the upstream binary worked on the same
device. Turned out the source compares the low 21 bits of each kmem call_site against the
link-time address, which only holds if the KASLR slide is 2 MiB aligned. This device's slide
is 512 KB aligned (slide & 0x1fffff = 0x80000), so all low bits shifted and every filter
matched nothing, with no error.

The confirmation came from an unfiltered path in the same code: its logged runtime value
minus the link-time value gave exactly 0x80000.

Fix was to sweep the four possible 0x80000 multiples and keep whichever matched the most
events.

Full repo has 14 chapters (EN + ZH), including 13 other CVE routes I ruled out with
disassembly evidence, and 7 bugs I introduced myself along the way.

Zero partition writes; bootloader stayed locked; ~20 exploit runs, 0 bricks.
```

---

## 📱 XDA Forums

**Section:** Redmi Pad SE 8.7 / Android General

**Title:**
```
[GUIDE] Temporary root on Redmi Pad SE 8.7 (locked bootloader) + the KASLR bug that breaks the public exploit
```

**Body:** use the Reddit version, replacing the greeting/closing with XDA style:

```
**What this is**
Full kernel-level root (uid=0, u:r:ksu:s0, full capabilities, KernelSU loaded) on a Redmi
Pad SE 8.7 with the bootloader still locked. Nothing is flashed. Reboot and it's gone.

**Requirements**
- Kernel exactly 6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
- KernelSU manager v3.3.1 (32680) — version must match ksud
- adb

... [The bug / The fix / Safety / What I also ruled out from the Reddit body] ...

**Confirmed working commands**

```bash
adb push artifacts/shark-k66118-fixed /data/local/tmp/shark66118
adb push artifacts/ksud-3.3.1        /data/local/tmp/ksud33
adb shell 'chmod 755 /data/local/tmp/shark66118 /data/local/tmp/ksud33'
adb install -r -g KernelSU_v3.3.1_32680-release.apk

# zero-risk self-check
adb shell '/data/local/tmp/shark66118 probe'

# fire (retry if it fails — it's probabilistic, ~2/3)
adb shell "cd /data/local/tmp && \
  PYB110_KSUD=/data/local/tmp/ksud33 \
  PYB110_MANAGER_PKG=me.weishu.kernelsu \
  PYB110_KMI=android15-6.6 \
  ./shark66118 --auto"

adb shell su -c id
```

**Do not try** (all evidence in docs/en/03-dead-ends.md):
GhostLock, Bad Epoll, mqsas, MTK BROM tools, fenrir, lkpatcher.

**Repo:** https://github.com/nestchao/redmi-pad-se-87-root
```

---

## 💬 Telegram / Discord / IRC

Short version, paste directly:

```
Locked-bootloader full root on Redmi Pad SE 8.7 via CVE-2026-98260.

The interesting bit: the public exploit compares low-21-bit slices of kmem call_site
against link-time addresses, which assumes a 2 MiB-aligned KASLR slide. This device is
512 KB aligned (slide & 0x1fffff = 0x80000), so every filter silently matched nothing.
Fixed by sweeping the 4 possible 0x80000 multiples.

Also ruled out 13 other CVE routes with disassembly evidence (GhostLock, Bad Epoll,
mqsas, MTK BROM, ...). Zero partition writes, bootloader stayed locked.

https://github.com/nestchao/redmi-pad-se-87-root
```

---

## 📚 Awesome-list submissions

These lists accept PRs and bring steady passive traffic:

| Repo | Where to add |
|---|---|
| [fynks/awesome-temporary-root](https://github.com/fynks/awesome-temporary-root) | add a row to the device table (the same-kernel `klee` entry is already there — cross-reference it) |
| [awesome-android-root/awesome-android-root](https://github.com/awesome-android-root/awesome-android-root) | Research / Write-ups section |
| [jiayy/android-hackers-treasure](https://github.com/jiayy/android-hackers-treasure) | kernel exploitation material |
| [ashishb/android-security-awesome](https://github.com/ashishb/android-security-awesome) | tools / research |
| [shijunqiang/awesome-android-security](https://github.com/shijunqiang/awesome-android-security) | same |

**Entry to add in the PR:**

```markdown
- [redmi-pad-se-87-root](https://github.com/nestchao/redmi-pad-se-87-root) —
  Locked-bootloader full root on Redmi Pad SE 8.7 via CVE-2026-98260.
  14-chapter write-up (EN/ZH) covering 13 ruled-out CVE routes with disassembly
  evidence, and a KASLR-alignment bug that makes public exploits fail silently on
  512 KB-aligned devices.
```

---

## 🎯 Suggested priority

| Priority | Channel | Why |
|---|---|---|
| **1** | r/AndroidRoot | audience matches exactly; highest conversion |
| **2** | XDA (Redmi Pad SE section) | long-tail traffic, well indexed by search |
| **3** | r/netsec | high-quality audience that actually reads code |
| **4** | Hacker News | explosive if it hits the front page (but hard) |
| **5** | Awesome-list PRs | steady passive traffic |
| **6** | X / Twitter | good for the one-liner and the diagrams |

**Pacing suggestion**: post Reddit + XDA first, watch the feedback and improve the README;
post the other channels two or three days later, using the early feedback as social proof.

---

## ⚠️ Posting rules

1. **Do not clickbait past the truth.** "Locked bootloader full root" is accurate;
   "one-click root for all Xiaomi tablets" is not.
2. **Always state "temporary root / lost on reboot".** Otherwise people will assume persistence.
3. **Always state "exact kernel only".** A different kernel string will fail.
4. **Never touch someone else's device.** Own hardware only.
5. **Prioritise replies.** Answering "will this work on my X?" thoughtfully grows stars faster
   than posting more.

---

## 📈 Measuring impact

```bash
gh api repos/nestchao/redmi-pad-se-87-root --jq '.stargazers_count, .forks_count, .subscribers_count'
gh api repos/nestchao/redmi-pad-se-87-root/traffic/views --jq '.count'
gh api repos/nestchao/redmi-pad-se-87-root/traffic/popular/referrers --jq '.[] | "\(.referrer) \(.count)"'
```

**The most valuable signal is not star count — it is someone coming back to report
"I tried it on model XX and the result was YY".** That means the repo is genuinely being used.
