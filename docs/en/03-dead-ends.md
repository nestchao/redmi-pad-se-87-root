# 03 · Every Dead End, With Evidence

[中文](../03-dead-ends.md) · **English**

> **This chapter exists so you do not repeat our mistakes.**
> Every entry has a verdict criterion. If your device falls in the same range, skip it.

---

## Contents

- [A. Kernel CVEs](#a-kernel-cves)
  - [A1. CVE-2026-43499 (GhostLock)](#a1-cve-2026-43499-ghostlock)
  - [A2. CVE-2026-46242 (Bad Epoll)](#a2-cve-2026-46242-bad-epoll)
  - [A3. DirtyFrag / Dirty Pipe](#a3-dirtyfrag--dirty-pipe)
  - [A4. Other CVEs](#a4-other-cves)
- [B. Vendor-service routes](#b-vendor-service-routes)
  - [B1. mqsas (three separate blocks)](#b1-mqsas-three-separate-blocks)
  - [B2. Magica](#b2-magica)
- [C. MediaTek boot chain](#c-mediatek-boot-chain)
  - [C1. BROM / mtkclient / penumbra](#c1-brom--mtkclient--penumbra)
  - [C2. fenrir](#c2-fenrir)
  - [C3. lkpatcher](#c3-lkpatcher)
  - [C4. Kamakiri / Heapbait / Carbonara](#c4-kamakiri--heapbait--carbonara)
- [D. Unrelated CVEs](#d-unrelated-cves)
- [E. Still possibly viable (we did not continue)](#e-still-possibly-viable-we-did-not-continue)

---

# A. Kernel CVEs

## A1. CVE-2026-43499 (GhostLock)

**The hottest Android temporary-root bug of 2026, with at least four public implementations:**

- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) (upstream, Pixel)
- [BuSung-dev/Root-My-Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy) (Samsung)
- [yijiacloud/ghostlock-...-4.19-k40](https://github.com/yijiacloud/ghostlock-cve-2026-43499-4.19-k40) (Qualcomm 4.19)
- [Delta-Water/CVE-2026-43499-phq110-root](https://github.com/Delta-Water/CVE-2026-43499-phq110-root) (OnePlus)

**Bug**: `remove_waiter()` in the rtmutex code uses `current` instead of `waiter->task`,
leaving an `rt_mutex_waiter` dangling on the kernel stack (CWE-416).

**Upstream fix**: Linux 6.6.140, commit `3bfdc63936dd`
("rtmutex: Use waiter::task instead of current in remove_waiter()").

**Our kernel is 6.6.118**, which by version number is *before* the fix.

### Criterion: disassembly

```console
$ python tools/kcalls.py remove_waiter
=== remove_waiter @ 0xffffffc08106c758  span 0x278 ===
  (not a single mrs sp_el0)
```

The instruction that clears `pi_blocked_on`:

```asm
0xffffffc08106c7d4  bl   #0xffffffc08104786c   ; rb_erase(waiter->tree)
0xffffffc08106c7d8  str  x23, [x23]            ; RB_CLEAR_NODE
0xffffffc08106c7dc  str  xzr, [x20, #0x938]    ; clear pi_blocked_on
                    ; x20 comes from [x23, #0x50] <- read from the struct
```

**On ARM64 the only way to read `current` is `mrs x, sp_el0`. Zero occurrences inside the
function ⇒ it does not read `current` ⇒ already fixed.**

(The function span is 0x278. Two `mrs sp_el0` exist at `0xc9f8` / `0xca94`, but they fall
inside the **next** function `rt_mutex_wait_proxy_lock`, not within `remove_waiter`.)

### Verdict

**Xiaomi already backported the 6.6.140 fix into 6.6.118. This route is completely dead.**

> **Lesson:** do not judge by version number. The `ghostlock419` README itself says
> "OEM kernels may have backported an equivalent fix, so the version string alone cannot
> be used to decide" — we experienced that first hand.

---

## A2. CVE-2026-46242 (Bad Epoll)

**The most tempting one**: an epoll UAF with a public PoC reporting **~99% reliability**,
explicitly stated to affect Android.

Source: [Bad Epoll analysis](https://labs.cosmicbytez.ca/news/2026-07-04-new-bad-epoll-linux-kernel-flaw-lets-unprivileged-users-gain-root-hits-android)

**Upstream fix**: Linux 6.6.144, upstream `a6dc643c6931`:

> **Pin @file via epi_fget() at the top of ep_remove()** and gate the critical
> section on the pin succeeding.

### Criterion 1: symbol naming

6.6.144 shipped a series of renames:

```
eventpoll: use hlist_is_singular_node() in __ep_remove()
eventpoll: split __ep_remove()
eventpoll: kill __ep_remove()
eventpoll: drop vestigial __ prefix from ep_remove_{file,epi}()
eventpoll: rename ep_remove_safe() back to ep_remove()
```

Our symbol table:

```
ep_remove              0xffffffc0804314f4   present
ep_remove_epi          0xffffffc0804308fc   present
ep_remove_safe         absent
__ep_remove            absent
```

**⇒ the naming matches the post-fix state.**

### Criterion 2: disassemble `ep_remove`

```asm
0x431568  ldr   x20, [x21, #0x30]     ; x20 = epi->ffd.file
0x43156c  ldr   x8,  [x20, #0x18]     ; file->f_count
0x431574  add   x9, x8, #1
0x4315a0  ldxr  x10, [x11]            ; atomic_long_inc_not_zero = get_file_rcu()
0x4315ac  stlxr w12, x9, [x11]
0x4315bc  cbz   x20, 0x4316d4         ; skip the critical section if the pin failed
0x4315c0  add   x22, x20, #0x10       ; &file->f_lock
0x4315c8  bl    _raw_spin_lock
0x4315d8  str   x9, [x8]              ; hlist_del_rcu's *pprev = next
0x4316d0  bl    fput                  ; release the pin
```

**Inlined `epi_fget` + gate + matching `fput` — exactly the fixed shape.**

### Verdict

**Bad Epoll is patched. The most tempting route is completely dead.**

---

## A3. DirtyFrag / Dirty Pipe

| CVE | Description | Status |
|---|---|---|
| CVE-2022-0847 (Dirty Pipe) | pipe buffer / page cache write | long patched |
| CVE-2026-43284 (DirtyFrag) | page cache write in the IPsec ESP path | **patched** |

The temporary-root guide in `awesome-android-root` only covers these two plus GhostLock —
**all three fail on our device.**

---

## A4. Other CVEs

| CVE | Reason |
|---|---|
| CVE-2024-31317 | Zygote injection, only affects SPL ≤ 2024-06-01; ours is 2026-09-01 |
| CVE-2026-49881 (TLPE) | Android 17 Telecom → system_server, **fixed in SPL 2026-09-01** — exactly our level |
| CVE-2026-2091 | io_uring fixed-file-table TOCTOU, fixed in 6.6.28; we are on 6.6.118 |
| CVE-2025-21479 (Adreno micronode) | Qualcomm GPU; we have Mali |
| CVE-2026-21385 (Qualcomm Display) | same |
| CVE-2026-31413 (BPF verifier) | affects 6.1 LTS; we are on 6.6 |
| CVE-2026-53365 (VsockDrop) | needs an `AF_VSOCK` socket; EACCES under Enforcing |
| CVE-2026-43494 (PinTheft) | needs an `AF_RDS` socket; EACCES under Enforcing |

---

# B. Vendor-service routes

## B1. mqsas (three separate blocks)

**This was the most promising route; it took significant effort to prove it is dead.**

### Background

`miui.mqsas.IMQSNative` is a Xiaomi diagnostics service. Public sources (six independent
ones) claim that **method 21** executes an arbitrary script as `uid=0`:

```bash
service call miui.mqsas.IMQSNative 21 \
    i32 1 s16 '/system/bin/sh' \
    i32 1 s16 '/data/local/tmp/script.sh' \
    s16 '/data/local/tmp/out.txt' i32 180
```

Sources:
[XDA Qualcomm Xiaomi no-BL-unlock](https://xdaforums.com/t/kernelsu-root-without-unlocked-bootloader-for-most-qualcomm-xiaomi-devices.4781779/),
[XDA ROLLBACK METHOD](https://xdaforums.com/t/tool-unofficial-bootloader-unlock-rollback-method.4802695/),
[mrdong916/mi_nobl_root](https://github.com/mrdong916/mi_nobl_root),
[HyperUnlocked #34](https://github.com/ukriu/HyperUnlocked/issues/34),
[PTT Xiaomi 17 no-BL-unlock](https://pttdigits.com/MobileComm/1fjGZB-Y),
[linux.do](https://linux.do/t/topic/1707800/8?page=2)

### Block 1: method indices 16–30 do not exist

We probed method indices 1–30 one by one:

```console
$ for i in $(seq 1 30); do
    service call miui.mqsas.IMQSNative $i
  done
```

Result:

```
[1..15]   respond (various return codes)
[16..30]  all EBADMSG "Not a data message"      <- method does not exist
```

**⇒ the `IMQSNative` interface on our ROM has only 15 methods, while the public exploit
needs the 21st.**

### Block 2: the real interface has no exec method, and `runCommand` has an allowlist

Decompiling `miui-services.jar` gave us the actual interface methods:

```
runCommand(String, String, int)                     <- method index 4
readFile(String)
captureLogByRunCommand(List, List, String, int)
attachSockFilter(String, String, int x5, byte[], int, String)
getStationInfo(String, String)
setCoreFilter(int, boolean)
flashDebugPolicy(int)
captureLog(...)   // very long parameter list
```

`runCommand` is method index **4**, but:

```console
$ adb shell service call miui.mqsas.IMQSNative 4 s16 'id' s16 '' i32 5
Result: Parcel( fffffff8 00000032 'runCommand:145: Command not allowed for shell user')

# from a uid=0 root shell:
Result: Parcel( fffffff8 00000023 'runCommand:152: Command not allowed')
```

**⇒ there is a command allowlist. uid 0 passes the user check but not the allowlist.**

### Block 3: the backing daemon is not even running

Strings extracted from `miui-services.jar`:

```
runCommand no mqsasd!
mqsasd not available!
CaptureLog no mqsasd!
```

And on the device:

```console
$ adb shell ps -A | grep mqsasd
(empty)
```

**⇒ the native daemon `mqsasd` is not running at all; the whole path is dead.**

### Other facts

- The service is provided by **`com.miui.daemon`**, running as **`system` (uid 1000)**
- Even if the allowlist were bypassed, the result would be uid 1000, **not root**

### Verdict

**mqsas is completely hardened on our ROM (HyperOS 3.0.303.0.WHXMIXM). Do not try again.**

---

## B2. Magica

[vvb2060/Magica](https://github.com/vvb2060/Magica):
> **Privilege Escalation PoC when seccomp is disabled for Android 10 - Android 16.**

**Mechanism (confirmed from AOSP source):**

```cpp
static void ..._nativeInstallSeccompUidGidFilter(...) {
  if (!gIsSecurityEnforced) {
    ALOGI("seccomp disabled by setenforce 0");
    return;                    // permissive => setuid filter not installed
  }
  ...
}
```

Sources: [AOSP Zygote.cpp](https://android.googlesource.com/platform/frameworks/base/+/0bccbf7984e482b66dd4f4f6561b25c6a65af37f/core/jni/com_android_internal_os_Zygote.cpp),
[commit 86f08a5190c8](https://android.googlesource.com/platform/frameworks/base/+/86f08a5190c8a36497ff3b9848ce3e6d0ba2e951%5e%21/core/java/android/os/ZygoteProcess.java)

**Android 17 added SafeSetID LSM to close this. We are on Android 16 — so it should work in
principle.**

### Why we did not use it

It requires an **app zygote to be forked while SELinux is Permissive**. The Permissive
window is short and we would have had to restart zygote / drain the USAP pool. We chose the
more direct Shark route instead and never measured this one.

**⇒ This route may still be viable**, it needs:
1. Become Permissive first
2. Within that window, start an app that declares `android:useAppZygote="true"` (Magica itself)
3. Its `onBind` calls `setresuid(0,0,0)`

---

# C. MediaTek boot chain

**Bottom line: the whole line is unusable for us.**
The single reason — **Xiaomi enables both BROM SLA and DAA, so there is no free BROM write path.**

---

## C1. BROM / mtkclient / penumbra

[penumbra](https://github.com/shomykohai/penumbra) is the authoritative MTK documentation.
Its FAQ is explicit:

> **"No signer available" / DA SLA challenge**
> Your device needs additional auth to proceed. Without exploits, this means that most of
> the times you'll need paid auth. While penumbra includes some SLA keys, they are
> **not enough to cover all devices, especially Xiaomi**, OnePlus and some other OEMs.
> **THIS IS NOT A BUG!**

> **SLA on!** ... you'll need to get online auth from **paid tools**,
> or hope for future exploits.

> I get error 0x7017 / 0x7024 on my device when trying to upload DA1
> This means your device has **DAA** on! ... you can only load the official DA provided by
> your device manufacturer.

**⇒ Xiaomi MTK devices enable both BROM SLA and DAA; free tooling cannot get through.**

The commercial tool Infinity-Box CM2MT2 v3.00 does list `Xiaomi Redmi-Pad-SE-8-flare` in its
changelog — but that is a paid authorisation path.

---

## C2. fenrir

[R0rt1z2/fenrir](https://github.com/R0rt1z2/fenrir): unverified bl2_ext → EL3 code execution.

**Why it fails:**

> This exploit abuses a flaw in the MediaTek boot chain. **When the bootloader is unlocked
> (seccfg)**, the Preloader skips verification of the `bl2_ext` partition

**⇒ It requires the device to already be unlocked. And the repo is archived.**

(One useful by-product: the README notes that some devices — e.g. Vivo X80 Pro — do not
verify `bl2_ext` even while locked. The check is to dump `expdb` and look for
`img_auth_required = 0`. That is only actionable *after* root, as a permanent-unlock step.)

---

## C3. lkpatcher

[R0rt1z2/lkpatcher](https://github.com/R0rt1z2/lkpatcher): patch LK plus certificate bypass.

README verbatim:

> - To successfully boot patched images, **unlock seccfg using mtkclient**.
> - If your device doesn't boot after unlocking with mtkclient, it likely uses
>   **SBC** and is not supported.

**⇒ needs mtkclient (BROM) to unlock seccfg first — right back to the C1 dead end.**

Also, every pattern in `patches.json` is **32-bit Thumb** (`2de9f04f...`), while our LK is arm64.

---

## C4. Kamakiri / Heapbait / Carbonara

| Bug | Target | Status |
|---|---|---|
| **Kamakiri** | BROM `if_info[wIndex]` unchecked index + `SendCert` residue | fix added a `wIndex` bounds check; 2023+ silicon almost certainly has it |
| **Heapbait** | DA2 `fp_read_host_file` heap overflow | fixed around 2024-11; our firmware is 2026-07 → **patched** |
| **Carbonara** | DA1 `boot_to` arbitrary write → overwrite the DA2 hash | requires a **signed DA1** (DAA), otherwise `0xc0070004 DA_HASH_MISMATCH` |

**Carbonara is the only theoretical possibility** ("devices released during or after 2024
aren't guaranteed to work, but there have been instances"), but it needs a signed DA1 and
Xiaomi's DAs are encrypted/authorised.

---

# D. Unrelated CVEs

Someone once asked us about these five CVE identifiers:

| CVE | What it actually is |
|---|---|
| CVE-2026-123007 | **nginx RCE (NGINX2Root)** |
| CVE-2026-123633 | **nginx HTTP/2 RCE** |
| CVE-2026-123634 | **nginx memory corruption** |
| CVE-2026-121810 | **NGINX Plus** |
| CVE-2026-113425 | **nginx** |

**All five are web-server bugs, entirely unrelated to Android kernel privilege escalation.**

Sources: [CrowdStrike](https://www.crowdstrike.com/en-us/blog/crowdstrike-helps-protect-against-nginx2root-cve-2026-123007/),
[NVD](https://nvd.nist.gov/vuln/detail/cve-2026-123634),
[cve.org](https://www.cve.org/CVERecord?id=CVE-2026-113425&source=nginx2root.pl)

**The 11 NFC CVEs are also out — the device has no NFC hardware (no `/dev/nfc*`).**

---

# E. Still possibly viable (we did not continue)

## binder: two UAFs fixed in 6.6.145

**Why we think it is viable:**

| Fact | Evidence |
|---|---|
| Fixed in 6.6.145, we are on 6.6.118 | ChangeLog |
| Binary looks **unpatched** | `binder_free_transaction` has **no** `put_task_struct` / `__put_task_struct`, while both symbols exist in the kernel |
| Entry point is **0666** | `crw-rw-rw- 1 root root 506, 1 /dev/binderfs/binder` |

**Bug mechanics** (from the fix description):

```
binder_free_transaction():
  t->to_proc is read safely under t->lock, but once the lock is dropped the target
  process can die. Acquiring to_proc->inner_lock right after is then a UAF.
  Fix: pin t->to_thread.
```

Our `binder_free_transaction` disassembly (0xffffffc080cd0bd0, span 0x220):

```asm
0xcd0be8  ldr  x21, [x0, #0x40]     ; x21 = t->to_proc
0xcd0c14  add  x20, x21, #0x228     ; &to_proc->inner_lock (raw pointer)
0xcd0c1c  bl   _raw_spin_lock       ; <- the UAF happens here
0xcd0c20  ldr  w8, [x21, #0x6c]     ; to_proc->tmp_ref
0xcd0c28  str  w2, [x21, #0x6c]     ; write back 4 bytes
0xcd0c3c  add  x0, x21, #0x78
0xcd0c4c  bl   __wake_up            ; treats to_proc+0x78 as a wait_queue_head
0xcd0c58  str  xzr, [x8, #0x30]     ; write 0 to [x8+0x30]
```

**Primitive idea**: `__wake_up(&to_proc->0x78)` is an arbitrary-address dereference. If the
slab can be reclaimed with controlled contents, this becomes the start of an arbitrary
read/write chain.

**Why we stopped**: it is a race and the engineering cost is high (binder protocol,
reclaim design, heap spray), while the Shark route already looked promising.

**If you want to pick this up, start here** — `binder_proc` is `kzalloc`'d at about 0x2a8
bytes, so it lands in **kmalloc-1k**, much easier to reclaim than the 98260 "one page".

## CVE-2026-93189 (Joyride, hidraw UAF)

- `hid_hw_stop()` does not wait for input to stop, so a failed probe frees `hidraw` while
  `hidraw_report_event()` is still writing to it
- Entry point is `/dev/uhid`, and **our shell has the `3011(uhid)` group**
- We only confirmed that the first 0x120 bytes of `hid_hw_stop` contain no `flush_work` /
  `cancel_work_sync` / `synchronize_rcu` — **we did not analyse deeper**

**This one is not ruled out either.**

---

## Summary table

| Route | Verdict | Confidence |
|---|---|---|
| CVE-2026-43499 | Dead, patched | disassembly |
| CVE-2026-46242 Bad Epoll | Dead, patched | symbols + disassembly |
| DirtyFrag / Dirty Pipe | Dead, patched | — |
| mqsas | Dead, triple-blocked | index probing + decompilation + process check |
| Magica | Possibly viable, untested | AOSP source confirms the mechanism |
| MTK BROM (all) | Dead, SLA + DAA | penumbra official docs |
| 5 nginx CVEs | Dead, unrelated | — |
| 11 NFC CVEs | Dead, no hardware | — |
| **binder UAF** | **Possibly viable** | binary looks unpatched |
| **Joyride (hidraw)** | **Not investigated deeply** | entry point reachable |
| **CVE-2026-98260** | **Worked** | see [10-breakthrough.md](10-breakthrough.md) |
