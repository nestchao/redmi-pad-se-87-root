# Changelog

All notable changes to this research repository.

## [1.1.0] - 2026-11-21

### Added
- `assets/` — five generated diagrams: EN/ZH banners, exploit chain, EN/ZH decision trees
- `scripts/make-assets.py` — regenerates all assets from code (no binary blobs in git history)
- `docs/CHEATSHEET.md` + `docs/en/CHEATSHEET.md` — one-page quick reference with every
  measured constant, offset, log marker and symptom->cause mapping
- `PROMO.md` + `docs/en/PROMO.md` — copy-paste promo kit for Reddit / XDA / HN / X / Telegram
  and Chinese platforms, plus awesome-list submission entries
- `CONTRIBUTING.md` — bilingual, with the three most-wanted contributions
- `SECURITY.md` — threat model and the four safety guarantees
- `README.md` / `README.en.md` fully rewritten around the actual contribution
  (the KASLR alignment trap) rather than the device

### Changed
- README now leads with a banner, a 30-second result block, the one-line root cause,
  and a "why you should read this even if you don't own this tablet" table

## [1.0.1] - 2026-11-21

### Added
- Complete English translation: `README.en.md` + `docs/en/` (13 chapters)
- Bidirectional language switchers on every document

## [1.0.0] - 2026-11-21

### Added
- Initial public release
- `docs/` — 13 chapters covering device baseline, methodology, every dead end, vulnerability
  internals, KASLR leak, slab measurement, carriers, EXACT HIT, root cause, breakthrough,
  reproduction, pitfalls and timeline
- `artifacts/` — patched source, patch script, working aarch64 binary, matching ksud, checksums
- `tools/` — 10 independent diagnostic programs
- `scripts/build.sh`, `scripts/check-device.sh`

### Fixed
- **KASLR alignment bug in the public Shark source.** The source compares the low 21 bits of
  kmem `call_site` values against link-time addresses, which assumes a 2 MiB-aligned KASLR
  slide. On this device the slide is 512 KB aligned (`slide & 0x1fffff = 0x80000`), so every
  filter silently matched nothing (`timers=0`, `task_recs=0`). Fixed with a four-candidate
  self-calibrating sweep. See `docs/09-root-cause.md`.

### Verified
- Full root achieved: `uid=0`, `u:r:ksu:s0`, `CapEff=0x1ffffffffff`, KernelSU module loaded
- Bootloader remained locked throughout; zero partition writes; zero bricks