# 12 · Pitfalls (Complete List)

[中文](../12-pitfalls.md) · **English**

> This chapter records every pitfall we actually hit, including:
> - 7 bugs we introduced ourselves
> - 9 encoding / tooling incidents
> - various misleading observations
>
> **We hope this saves you some弯路 (detours).**

---

## 1. Seven bugs we introduced ourselves

All of these were in our own `pwn.c` / `pwn_min.c`, and each one wasted an experiment.

### Bug 1: out-of-bounds fd array in `pipe_spray`

```c
/* wrong: never checks npipes against array capacity */
for (int i = 0; i < npipes; i++) {
    pipe(pfd[i]);                /* pfd has only 512 elements */
    ...
}
```

**Symptom**: random crashes / data corruption.
**Fix**: add bounds checks.

### Bug 2: `(void)phase` discarded the command-line argument

```c
/* wrong: the parameter overwrote the global */
static void build_page(unsigned char *p, int phase)
{
    phase = (void)phase;         /* typo, parameter discarded */
    ...
}
```

**Symptom**: no matter what phase value we passed, behaviour was identical.
**Fix**: delete the line.

**This bug is especially insidious — it does not error, it just silently does nothing.**

### Bug 3: `static timer_t *tv` double free

```c
/* wrong: static pointer, calling the function twice double-frees */
static timer_t *tv;
void make_timers(void) {
    tv = calloc(N, sizeof(timer_t));
    ...
}
```

**Fix**: use a local variable, or set it back to NULL at the end.

### Bug 4: unchecked `F_SETPIPE_SZ` return → blocking `write`

```c
/* wrong: if setting the pipe size fails, the write blocks */
pipe(pfd);
fcntl(pfd[1], F_SETPIPE_SZ, 4096 * 16);   /* may fail */
write(pfd[1], buf, 4096 * 16);            /* blocks! */
```

**Symptom**: the program hangs.
**Fix**:

```c
int sz = fcntl(pfd[1], F_SETPIPE_SZ, want);
if (sz < want) { /* use sz, not want */ }
```

### Bug 5: bounds check placed outside the loop

```c
/* wrong: checked once before entering the loop */
if (i < MAX) {
    for (; i < n; i++) spray_sock(...);   /* i may exceed MAX */
}
```

**Fix**: move the check inside the loop body.

### Bug 6: memory cap not divided by the number of waves → OOM

```c
/* wrong: allocates max each time, but runs N waves */
for (int wave = 0; wave < N; wave++)
    spray(mem_total);        /* total usage = N x mem_total */
```

**Symptom**: device OOMs, system freezes.
**Fix**:

```c
size_t per_wave = mem_total / N;
for (int wave = 0; wave < N; wave++)
    spray(per_wave);
```

### Bug 7: contiguous full-page payload caused phase cycling

```c
/* wrong: payload laid out contiguously from the page start, so the phase repeats
   every 24 bytes, but 4096 is not a multiple of 24, so the phase differs by position */
for (off = 0; off + 24 <= 4096; off += 24) { ... }
/*  4096 / 24 = 170.67 -> the final chunk is a truncated period */
```

**Symptom**: no matter how we tuned the phase parameter, the hit rate stayed at 1/3.
**Fix**: use **one phase across the whole page**, start at `phase`, and ensure
`phase + 24*k` never crosses a page boundary.

---

## 2. Nine encoding / tooling incidents

### Incident 1: a `UTF-8 without BOM` `.ps1` fails to parse

**Symptom**: PowerShell reports inexplicable syntax errors.

**Cause**: PowerShell 5.1 reads files without a BOM as ANSI, so Chinese comments are decoded
incorrectly and quotes/brackets become unbalanced.

**Fix**: **any `.ps1` containing non-ASCII must be saved as UTF-8 with BOM.**

### Incident 2: a literal `` `r`n `` written into a C file

**Symptom**: backticks inside C code, compilation fails.

**Cause**: concatenating C code inside a PowerShell double-quoted string let
`` `r`n `` be treated as an escape sequence, and sometimes the code was written literally.

**Fix**: use here-strings (`@'...'@`) instead of double-quoted concatenation.

### Incident 3: `aqlr.py` crashes on a GBK console

**Symptom**: `UnicodeEncodeError: 'gbk' codec can't encode character`.

**Fix**:

```python
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
```

### Incident 4: garbled output from scheduled tasks

**Symptom**: log files from scheduled tasks are full of mojibake.

**Fix**:

```powershell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# and use ASCII-only markers for machine-read lines
```

### Incidents 5-7: `.Replace(old, new, count)` does not exist in PS 5.1

**Symptom**: `.Replace(...)` silently does nothing; you think you changed the file but did not.

**Cause**: `String.Replace(String, String, Int32)` is a .NET Core overload. PS 5.1 runs on
.NET Framework, which only has `Replace(String, String)`.

**Fix**:
- use the `edit` tool instead of string replacement
- or read the file as a line array, modify, and write back

### Incidents 8-9: UTF-8 content written by `Set-Content -Encoding UTF8` gains a BOM, then breaks on re-read

**Symptom**: a `` character appears at the start of the file and Python fails with
`invalid non-printable character U+FEFF`.

**Fix**: write without BOM:

```powershell
[System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
```

---

## 3. Misleading observations

### Observation 1: `bytes_req` is 184, not 192

Looking for cred allocations, we first assumed 192 (the `cred_jar` `size`) and caught nothing.

**Reality:**

```
bytes_req   = s->object_size  = 184   <- sizeof(struct cred)
bytes_alloc = s->size         = 192   <- slab size after alignment
```

**slabinfo reports objsize as 192, but the tracepoint reports bytes_req as 184.**

### Observation 2: `PERF_SAMPLE_TID` is -1 for per-CPU events

We first filtered with `tid == mytid` and **lost every sample**.

**Reality**: per-CPU perf events are not associated with a task; `sample.tid` is `-1`.

**Fix**: drop that filter.

### Observation 3: `MemFree` is only 80 MB but `MemAvailable` is 2.2 GB

Planning spray volume from `MemFree`, we only dared to spray 80 MB — nowhere near enough.

**Reality**: on Android most memory is page cache. `MemFree` is low but `MemAvailable` is high.

**Fix**: read `MemAvailable` from `/proc/meminfo`.

### Observation 4: our first KASLR leak collected only 60 records in 1.6 s

We thought the trace had no data.

**Reality**: the perf ring was overflowing. After draining every 20 ms we got **13,861
records — a 230× difference**.

### Observation 5: `io_setup` appeared to be disabled

Early probing showed `io_setup` returning EACCES, so we assumed it was unusable.

**Reality**: that was **SELinux Enforcing** blocking it. Under **Permissive** `io_setup` works
fine and gave us 234 MB.

**⇒ always confirm the SELinux state before probing syscalls.**

### Observation 6: `id` shows `uid=0` but nothing works

After the first stage succeeded:

```
uid=0(root) gid=0(root) ... context=u:r:shell:s0
CapEff: 0000000000000000     <- empty capability set!
```

**Reality**: the default mode only clears `cred->uid`, not `cred->cap_*`.

**Without `CAP_DAC_OVERRIDE`, uid=0 still cannot read other users' files.**

**⇒ "uid=0" is not root. Always check `CapEff`.**

### Observation 7: `setuid(0)` returns 0 but `resuid`'s third value is still 2000

```
[child] setuid(0)=0 errno=0 resuid=0/0/2000
```

**Reality**: in the "unprivileged" branch, `setuid(0)` only sets euid and leaves suid alone.
To zero everything you need `setresuid(0,0,0)`, or set euid=0 first and call again.

### Observation 8: `getenforce` says Permissive, but `setenforce 0` still gives Permission denied

**Reality**: we patched `selinux_state.enforcing`, but `setenforce` goes through SELinux's
permission-check path. Even in permissive mode, `u:r:shell:s0` is not permitted to call it.

**⇒ "permissive" only disables LSM enforcement; it does not grant capabilities.**

### Observation 9: the device unexpectedly disconnects

**Reality**: the kernel panicked and auto-rebooted; it comes back in 30–60 seconds.
We crashed more than a dozen times this way, **and it recovered every time.**

**⇒ a disconnect does not mean the device is broken. Wait a minute and check again.**

---

## 4. Methodology-level pitfalls

### Pitfall 1: judging vulnerability by version number

**Wrong**: `ghostlock419`'s README says "affects 6.6.x, fixed in 6.6.140", we are on
6.6.118 → assumed vulnerable.

**Reality**: **Xiaomi backported the fix early.** Disassembly confirmed it is patched.

**⇒ always verify by disassembly, never by version number alone.**

### Pitfall 2: trusting "this method works" from the community

mqsas had six independent sources claiming it works. On our device:
- method indices were removed
- commands are allowlisted
- the backing daemon is not running

**⇒ vendors tailor builds per model/region/version. Always measure.**

### Pitfall 3: assuming the source works

The public Shark source (fork v2.3.2) and the upstream binary (v2.5.1) **behave differently**.

**⇒ binary behaviour is the truth. Source may lag.**

### Pitfall 4: giving up after the first failure

The report for the identical kernel said:
> the **first attempt failed** at `fake_uid` (`FAIL=cred`, `exit=13`)
> and the **second succeeded in 6468 ms**

**Had we stopped at our first failures, we would never have succeeded.**

**⇒ probabilistic exploits need multiple attempts.**

### Pitfall 5: mistaking "memory leak" for "feature unavailable"

`io_uring` is unusable under Enforcing but usable under Permissive.
Without distinguishing the states you will misjudge many routes.

---

## 5. Safety record

### What we did right

| Practice | Effect |
|---|---|
| **zero partition writes throughout** | never bricked |
| greeted the source for `dd` / `flash` / `insmod` before running | confirmed safe |
| `PARKED` instead of blind reaping on failure | drastically fewer panics |
| waiting 30–60 s after a panic | recovered every time |
| `fsync` each important log line | logs survive a panic |

### Measured data

| Item | Value |
|---|---|
| total exploit runs | ~20 |
| kernel panics | ~10 (all in the early blind-reap phase) |
| **panics after the fix** | **0** (6 runs) |
| bricks | **0** |
| partition writes | **0** |

### What to do if it panics

1. Wait 30–60 seconds; the device reboots itself
2. Files in `/data/local/tmp` **survive** (that is the /data partition)
3. KASLR is re-randomised → the slide changes
4. SELinux returns to Enforcing
5. **Just re-run**

### The only thing to be careful about

If a panic happens while a file is being written, that file may be corrupted.
**Back up important data first.**

---

## 6. Symptom → cause quick reference

| Symptom | Most likely cause |
|---|---|
| `[calib] timers=0` | KASLR low-21 bits not compensated (chapter 09) |
| `task_recs=0` but `recs=1` | same |
| `burst hit=0` + `holding zombie` | page-reclaim probability; re-run |
| `LATE_LOAD_SKIP=env-missing` | `PYB110_KSUD` not set |
| `su: not found` | KSU module not loaded |
| `uid=0` but `CapEff=0` | default mode, not fake mode |
| program hangs | blocking pipe `write` / tracing not stopped |
| device disconnects | kernel panic; wait 60 s |
| `io_setup` EACCES | SELinux Enforcing; needs Permissive |
| `ptr` hashed in the trace | you are using the text `trace`; use `trace_pipe_raw` |
| `.ps1` reports odd syntax errors | file is UTF-8 without BOM |
