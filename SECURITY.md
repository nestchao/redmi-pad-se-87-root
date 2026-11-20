# Security Policy / 安全策略

## Reporting a vulnerability in this project

This repository contains **offensive security research** by design. If you find a bug in
**our code** (the exploit wrapper, the patch script, the diagnostic tools) — for example
something that writes to a partition, something that could brick a device, or something
that leaks data — please report it privately:

**Use GitHub Security Advisories:**
https://github.com/nestchao/redmi-pad-se-87-root/security/advisories/new

We aim to respond within 7 days.

### What counts

| In scope | Out of scope |
|---|---|
| A code path in `artifacts/` or `tools/` that can write to a partition | The upstream CVE-2026-98260 itself (report to kernel.org) |
| A bug that could brick a device | The fact that the exploit grants root (that is the point) |
| A bug that leaks user data | KernelSU / ksud bugs (report to tiann/KernelSU) |
| Credential / key accidentally committed | Vulnerabilities in the apps we reference |

## Known and accepted risks

| Risk | Status |
|---|---|
| Kernel panic during exploitation | **Accepted by design.** The exploit prints `PARKED` and keeps zombies instead of blindly reaping, which reduced panics to 0 in 6 measured runs after the fix. |
| Temporary root is lost on reboot | **Accepted by design.** Persistence would require unlocking the bootloader. |
| The exploit only works on one exact kernel string | **Accepted by design.** A different kernel needs a regenerated profile. |

## Safety guarantees we maintain

These are promises about the code in this repo:

1. **No partition writes.** Searching the source for `/dev/block`, `by-name`, `mmcblk`,
   `dd if=`, `flash`, `reboot`, `insmod` yields zero hits.
2. **No persistent modification.** Everything lives in kernel memory and is gone after reboot.
3. **Failure is safe.** On a missed page reclaim the exploit prints `PARKED` and keeps the
   zombie rather than reaping it.
4. **A zero-risk self-check exists.** `shark66118 probe` only leaks and validates; it never
   triggers the UAF.

## If we ever break one of those guarantees

That is a security advisory, not a normal bug. Report it privately, do not open a public issue.