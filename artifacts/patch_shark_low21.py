"""给 Shark 的 plant_core.inc 打「KASLR slide 自校准」补丁。

问题：源码里 scan_timer_allocs / scan_task_allocs 把 call_site 的低 21 位
      和「链接地址的低 21 位」硬比。但低 21 位会随 KASLR slide 的
      mod 2MiB 部分一起平移。上游那台机器 slide 是 2MiB 对齐的（平移 0），
      我们这台是 512KB 对齐的（平移 0x80000），所以永远匹配不上。

修法：加一个全局 g_low_adj，表示 slide mod 2MiB；
      所有低21位比较都加上它；校准阶段把 4 个候选值各试一遍取命中最多者。
"""
import io
import sys

PATH = r"tools\bin\sharkbuild\plant_core.inc"

src = io.open(PATH, encoding="utf-8").read()
orig = src
applied = []

# --- 1. 加全局变量 ---------------------------------------------------------
anchor = "static uint64_t g_slide = UINT64_C(0);"
add = anchor + "\n/* PATCH: KASLR slide 的 mod-2MiB 分量，用于把链接地址的低21位\n * 平移到运行时位置。0 = 2MiB 对齐（上游原假设）。 */\nstatic unsigned long long g_low_adj = 0ULL;"
if anchor in src and "g_low_adj = 0ULL" not in src:
    src = src.replace(anchor, add, 1)
    applied.append("global g_low_adj")
elif "g_low_adj = 0ULL" in src:
    applied.append("global g_low_adj (already)")
else:
    print("!! 找不到 g_slide 定义", file=sys.stderr)

# --- 2. timer 过滤 ---------------------------------------------------------
t_old = "if ((site & 0x1fffffULL) != TIMER_SITE_LOW21)"
t_new = "if ((site & 0x1fffffULL) != ((TIMER_SITE_LOW21 + g_low_adj) & 0x1fffffULL))"
n = src.count(t_old)
src = src.replace(t_old, t_new)
applied.append("timer filter x%d" % n)

# --- 3. task 过滤 ---------------------------------------------------------
k_old = "if ((site & 0x1fffffULL) != COPY_PROCESS_LOW21)"
k_new = "if ((site & 0x1fffffULL) != ((COPY_PROCESS_LOW21 + g_low_adj) & 0x1fffffULL))"
n = src.count(k_old)
src = src.replace(k_old, k_new)
applied.append("task filter x%d" % n)

# --- 4. 校准阶段扫 4 个候选 ------------------------------------------------
cal_old = """    {
        int c = scan_timer_allocs(raw, (size_t)n, me, ptrs, 512, NULL);

        ntimers = c;
        logf("[calib] timers=%d\\n", c);"""
cal_new = """    {
        int c = 0;

        /* PATCH: KASLR slide 的 mod-2MiB 部分未知，4 个候选各试一遍。 */
        {
            static const unsigned long long cands[4] = {
                0ULL, 0x80000ULL, 0x100000ULL, 0x180000ULL};
            int best_ci = 0;

            for (int ci = 0; ci < 4; ci++) {
                int cc;

                g_low_adj = cands[ci];
                cc = scan_timer_allocs(raw, (size_t)n, me, ptrs, 512, NULL);
                if (cc > c) { c = cc; best_ci = ci; }
            }
            g_low_adj = cands[best_ci];
            c = scan_timer_allocs(raw, (size_t)n, me, ptrs, 512, NULL);
        }

        ntimers = c;
        logf("[calib] timers=%d low_adj=%#llx\\n", c, g_low_adj);"""
if cal_old in src:
    src = src.replace(cal_old, cal_new, 1)
    applied.append("calib candidate sweep")
else:
    print("!! 找不到 calibrate_base 里的 scan_timer_allocs 调用", file=sys.stderr)

if src == orig:
    print("没有任何改动", file=sys.stderr)
    sys.exit(1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(src)
print("已应用:")
for a in applied:
    print("  -", a)
