"""生成仓库的营销素材：横幅、攻击链图、决策树。

输出到 assets/ 目录，供 README 引用，也可直接作为 GitHub social preview。
"""
import os
from PIL import Image, ImageDraw, ImageFont

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")
os.makedirs(OUT, exist_ok=True)

FB = "C:/Windows/Fonts/seguisb.ttf"      # Segoe UI Semibold
FE = "C:/Windows/Fonts/segoeuib.ttf"     # Segoe UI Bold
FC = "C:/Windows/Fonts/consola.ttf"      # Consolas
FCB = "C:/Windows/Fonts/consolab.ttf"    # Consolas Bold
FM = "C:/Windows/Fonts/msyh.ttc"         # 微软雅黑
FMB = "C:/Windows/Fonts/msyhbd.ttc"      # 微软雅黑 Bold

def font(path, size):
    return ImageFont.truetype(path, size)

# 配色（GitHub dark 风格）
BG      = (13, 17, 23)
BG2     = (22, 27, 34)
FG      = (230, 237, 243)
DIM     = (139, 148, 158)
DIM2    = (90, 100, 112)
RED     = (248, 81, 73)
ORANGE  = (219, 109, 40)
YELLOW  = (210, 168, 255)
GREEN   = (63, 185, 80)
CYAN    = (88, 166, 255)
PURPLE  = (188, 140, 255)
BORDER  = (48, 54, 61)


def vgrad(w, h, top, bottom):
    img = Image.new("RGB", (w, h))
    d = ImageDraw.Draw(img)
    for y in range(h):
        t = y / max(1, h - 1)
        c = tuple(int(top[i] + (bottom[i] - top[i]) * t) for i in range(3))
        d.line([(0, y), (w, y)], fill=c)
    return img


def rrect(d, box, r, fill=None, outline=None, width=1):
    d.rounded_rectangle(box, radius=r, fill=fill, outline=outline, width=width)


def text_c(d, cx, y, s, f, fill):
    bb = d.textbbox((0, 0), s, font=f)
    d.text((cx - (bb[2] - bb[0]) / 2 - bb[0], y), s, font=f, fill=fill)
    return bb[3] - bb[1]


# ============================================================
# 1. 英文横幅 1280x640
# ============================================================
def banner_en(path):
    W, H = 1280, 640
    img = vgrad(W, H, (16, 20, 28), (8, 11, 16))
    d = ImageDraw.Draw(img)

    # 顶部细线装饰
    for x in range(0, W, 8):
        d.line([(x, 0), (x, 2)], fill=(30, 40, 55))

    # CVE 徽章
    f_badge = font(FCB, 20)
    label = "CVE-2026-98260"
    bb = d.textbbox((0, 0), label, font=f_badge)
    bw = bb[2] - bb[0] + 28
    rrect(d, (60, 48, 60 + bw, 48 + 36), 6, fill=(48, 22, 22), outline=RED, width=1)
    d.text((74, 56), label, font=f_badge, fill=RED)

    # 主标题
    f_h1 = font(FE, 62)
    d.text((60, 106), "LOCKED BOOTLOADER", font=f_h1, fill=(120, 132, 148))
    d.text((60, 172), "FULL ROOT", font=f_h1, fill=GREEN)

    # 副标题
    f_sub = font(FB, 22)
    d.text((62, 258), "Redmi Pad SE 8.7  ·  HyperOS 3.0.303  ·  Android 16  ·  MT8786", font=f_sub, fill=DIM)

    # 三段链
    stages = [
        ("1", "fake_cred", "forge full-cap cred", CYAN),
        ("2", "selinux=0", "Permissive", YELLOW),
        ("3", "uid=0", "resuid=0/0/0", GREEN),
    ]
    f_num = font(FCB, 26)
    f_stage = font(FCB, 19)
    f_desc = font(FB, 14)

    x = 62
    y = 318
    box_w, box_h = 300, 96
    for i, (num, title, desc, col) in enumerate(stages):
        rrect(d, (x, y, x + box_w, y + box_h), 10, fill=BG2, outline=col, width=2)
        d.ellipse((x + 16, y + 16, x + 16 + 34, y + 16 + 34), outline=col, width=2)
        cb = d.textbbox((0, 0), num, font=f_num)
        d.text((x + 16 + 17 - (cb[2] - cb[0]) / 2 - cb[0], y + 16 + 17 - (cb[3] - cb[1]) / 2 - cb[1]),
               num, font=f_num, fill=col)
        d.text((x + 62, y + 20), title, font=f_stage, fill=FG)
        d.text((x + 62, y + 50), desc, font=f_desc, fill=DIM)
        if i < 2:
            ax = x + box_w + 8
            d.line([(ax, y + box_h / 2), (ax + 26, y + box_h / 2)], fill=DIM2, width=2)
            d.polygon([(ax + 26, y + box_h / 2 - 6), (ax + 36, y + box_h / 2), (ax + 26, y + box_h / 2 + 6)], fill=DIM2)
            x += box_w + 44
        else:
            x += box_w

    # KSU 徽章
    rrect(d, (x + 8, y + box_h / 2 - 30, x + 8 + 152, y + box_h / 2 + 30), 28,
          fill=(16, 40, 20), outline=GREEN, width=2)
    f_ksu = font(FCB, 18)
    d.text((x + 26, y + box_h / 2 - 12), "KernelSU", font=f_ksu, fill=GREEN)

    # 核心洞察框
    by = 452
    rrect(d, (60, by, W - 60, by + 104), 10, fill=(18, 22, 30), outline=(60, 48, 24), width=2)
    d.rectangle((60, by, 64, by + 104), fill=ORANGE)
    f_ins = font(FCB, 20)
    f_ins2 = font(FB, 18)
    d.text((84, by + 14), "ROOT CAUSE", font=f_ins, fill=ORANGE)
    d.text((84, by + 44), "KASLR is 512 KB-aligned here, not 2 MiB.", font=f_ins2, fill=FG)
    d.text((84, by + 70), "Every low-21-bit call_site filter silently matches nothing.", font=f_ins2, fill=DIM)

    # 底部结果
    f_foot = font(FCB, 19)
    d.text((60, 588), "uid=0(root)   u:r:ksu:s0   CapEff=000001ffffffffff", font=f_foot, fill=GREEN)
    f_right = font(FCB, 17)
    rt = "0 partition writes  ·  bootloader stays LOCKED"
    rb = d.textbbox((0, 0), rt, font=f_right)
    d.text((W - 60 - (rb[2] - rb[0]), 590), rt, font=f_right, fill=DIM2)

    img.save(path)
    print("  ", path)


# ============================================================
# 2. 中文横幅 1280x640
# ============================================================
def banner_zh(path):
    W, H = 1280, 640
    img = vgrad(W, H, (16, 20, 28), (8, 11, 16))
    d = ImageDraw.Draw(img)

    for x in range(0, W, 8):
        d.line([(x, 0), (x, 2)], fill=(30, 40, 55))

    f_badge = font(FCB, 20)
    label = "CVE-2026-98260"
    bb = d.textbbox((0, 0), label, font=f_badge)
    bw = bb[2] - bb[0] + 28
    rrect(d, (60, 48, 60 + bw, 48 + 36), 6, fill=(48, 22, 22), outline=RED, width=1)
    d.text((74, 56), label, font=f_badge, fill=RED)

    f_h1 = font(FMB, 58)
    d.text((60, 108), "免解锁 BOOTLOADER", font=f_h1, fill=(120, 132, 148))
    d.text((60, 176), "完整 ROOT", font=f_h1, fill=GREEN)

    f_sub = font(FMB, 21)
    d.text((62, 262), "Redmi Pad SE 8.7  ·  HyperOS 3.0.303  ·  Android 16  ·  MT8786", font=f_sub, fill=DIM)

    stages = [
        ("1", "假 cred", "伪造完整能力集", CYAN),
        ("2", "selinux=0", "打成 Permissive", YELLOW),
        ("3", "uid=0", "resuid=0/0/0", GREEN),
    ]
    f_num = font(FCB, 26)
    f_stage = font(FMB, 19)
    f_desc = font(FM, 14)

    x, y = 62, 318
    box_w, box_h = 300, 96
    for i, (num, title, desc, col) in enumerate(stages):
        rrect(d, (x, y, x + box_w, y + box_h), 10, fill=BG2, outline=col, width=2)
        d.ellipse((x + 16, y + 16, x + 16 + 34, y + 16 + 34), outline=col, width=2)
        cb = d.textbbox((0, 0), num, font=f_num)
        d.text((x + 16 + 17 - (cb[2] - cb[0]) / 2 - cb[0], y + 16 + 17 - (cb[3] - cb[1]) / 2 - cb[1]),
               num, font=f_num, fill=col)
        d.text((x + 62, y + 20), title, font=f_stage, fill=FG)
        d.text((x + 62, y + 50), desc, font=f_desc, fill=DIM)
        if i < 2:
            ax = x + box_w + 8
            d.line([(ax, y + box_h / 2), (ax + 26, y + box_h / 2)], fill=DIM2, width=2)
            d.polygon([(ax + 26, y + box_h / 2 - 6), (ax + 36, y + box_h / 2), (ax + 26, y + box_h / 2 + 6)], fill=DIM2)
            x += box_w + 44
        else:
            x += box_w

    rrect(d, (x + 8, y + box_h / 2 - 30, x + 8 + 152, y + box_h / 2 + 30), 28,
          fill=(16, 40, 20), outline=GREEN, width=2)
    f_ksu = font(FCB, 18)
    d.text((x + 26, y + box_h / 2 - 12), "KernelSU", font=f_ksu, fill=GREEN)

    by = 452
    rrect(d, (60, by, W - 60, by + 104), 10, fill=(18, 22, 30), outline=(60, 48, 24), width=2)
    d.rectangle((60, by, 64, by + 104), fill=ORANGE)
    f_ins = font(FMB, 19)
    f_ins2 = font(FMB, 19)
    d.text((84, by + 14), "根因", font=f_ins, fill=ORANGE)
    d.text((84, by + 46), "这台机器的 KASLR 是 512 KB 对齐，不是 2 MiB。", font=f_ins2, fill=FG)
    d.text((84, by + 74), "所有「低 21 位」call_site 过滤都静默匹配不上。", font=f_ins2, fill=DIM)

    f_foot = font(FCB, 19)
    d.text((60, 588), "uid=0(root)   u:r:ksu:s0   CapEff=000001ffffffffff", font=f_foot, fill=GREEN)
    f_right = font(FMB, 16)
    rt = "零分区写入  ·  bootloader 始终锁定"
    rb = d.textbbox((0, 0), rt, font=f_right)
    d.text((W - 60 - (rb[2] - rb[0]), 592), rt, font=f_right, fill=DIM2)

    img.save(path)
    print("  ", path)


# ============================================================
# 3. 攻击链总图
# ============================================================
def chain(path):
    W, H = 1400, 780
    img = vgrad(W, H, (13, 17, 23), (9, 12, 17))
    d = ImageDraw.Draw(img)

    f_title = font(FE, 30)
    f_sub = font(FB, 16)
    d.text((48, 34), "CVE-2026-98260  ·  Exploit Chain", font=f_title, fill=FG)
    d.text((48, 76), "From adb shell (uid 2000) to full root, without touching a single partition",
           font=f_sub, fill=DIM)

    f_box = font(FCB, 16)
    f_small = font(FB, 13)
    f_tiny = font(FC, 12)

    def box(x, y, w, h, title, lines, col, fill=None):
        rrect(d, (x, y, x + w, y + h), 9, fill=fill or BG2, outline=col, width=2)
        d.text((x + 14, y + 12), title, font=f_box, fill=col)
        for i, ln in enumerate(lines):
            d.text((x + 14, y + 38 + i * 18), ln, font=f_small, fill=DIM)

    def arrow(x1, y1, x2, y2, col=DIM2):
        d.line([(x1, y1), (x2, y2)], fill=col, width=2)
        if abs(y2 - y1) < 4:
            d.polygon([(x2 - 10, y2 - 6), (x2, y2), (x2 - 10, y2 + 6)], fill=col)
        else:
            d.polygon([(x2 - 6, y2 - 10), (x2, y2), (x2 + 6, y2 - 10)], fill=col)

    # 第 0 行：前提
    box(48, 120, 420, 108, "① PREREQUISITES (measured)", [
        "shell in group 3012(readtracefs)  -> trace_pipe_raw readable",
        "events/*/enable 0666  ·  tracing_on 0666",
        "kptr_restrict only affects TEXT output",
    ], CYAN)

    box(496, 120, 420, 108, "② LEAK (zero risk)", [
        "trace_pipe_raw binary records -> real pointers",
        "sched_blocked_reason.caller  -> KASLR base (vote)",
        "kmem_cache_alloc.site/ptr    -> victim address",
    ], CYAN)

    box(944, 120, 408, 108, "③ MEASURE (never copy)", [
        "posix_timers_cache 264 B, 31/slab, order-1",
        "cred_jar 192 B, 21/slab  ·  sizeof(cred)=184",
        "BTF: task.cred=0x820  ·  cap sets=0x30..0x48",
    ], CYAN)

    # 关键修复行
    rrect(d, (48, 258, 1352, 348), 9, fill=(30, 22, 14), outline=ORANGE, width=2)
    d.rectangle((48, 258, 54, 348), fill=ORANGE)
    f_ins = font(FCB, 19)
    f_ins2 = font(FB, 15)
    d.text((72, 272), "★ THE FIX THAT MAKES IT WORK", font=f_ins, fill=ORANGE)
    d.text((72, 300), "KASLR slide is 512 KB-aligned on this device, so the low 21 bits of every call_site shift by 0x80000.", font=f_ins2, fill=FG)
    d.text((72, 322), "Sweep the 4 candidates {0, 0x80000, 0x100000, 0x180000} and keep the one matching the most events.", font=f_ins2, fill=DIM)

    # 三个阶段
    f_stage = font(FE, 17)
    stages = [
        ("STAGE 1 · fake_cred", CYAN, [
            "reclaim the freed order-1 slab with AIO pages",
            "lay out a fake cred: uid=0 + 0x1ffffffffff",
            "zero-write task->cred  (0x820) -> fake cred",
            "child forks -> prepare_creds() normalises it",
        ]),
        ("STAGE 2 · selinux", YELLOW, [
            "zero-write selinux_state.enforcing",
            "getenforce -> Permissive",
            "opens perf / kprobe / io_uring / bpf",
        ]),
        ("STAGE 3 · fake_uid", GREEN, [
            "zero-write fake_cred->uid/gid (0x08)",
            "resuid = 0/0/0",
            "late-load KernelSU LKM via ksud",
        ]),
    ]
    x = 48
    for title, col, lines in stages:
        w = 420
        rrect(d, (x, 378, x + w, 378 + 130), 9, fill=BG2, outline=col, width=2)
        d.text((x + 14, 390), title, font=f_stage, fill=col)
        for i, ln in enumerate(lines):
            d.text((x + 14, 418 + i * 20), "- " + ln, font=f_small, fill=DIM)
        x += w + 22

    # 关键机制说明
    rrect(d, (48, 528, 1352, 620), 9, fill=(14, 26, 20), outline=(40, 90, 50), width=2)
    f_m = font(FCB, 17)
    f_m2 = font(FB, 15)
    d.text((72, 542), "EXACT HIT", font=f_m, fill=GREEN)
    d.text((72, 568), "kprobe free_slab(x1) + kprobe __filemap_get_folio($retval)  ->  compare slab == folio directly", font=f_m2, fill=FG)
    d.text((72, 592), "Only reap the zombie when the pointers match. Otherwise print PARKED and keep the zombie. This is why we ran 6 times with 0 panics.", font=f_m2, fill=DIM)

    # 结果
    rrect(d, (48, 640, 1352, 736), 9, fill=BG2, outline=GREEN, width=2)
    f_res = font(FCB, 18)
    f_res2 = font(FC, 16)
    d.text((72, 654), "RESULT", font=f_res, fill=GREEN)
    d.text((72, 682), "uid=0(root) gid=0(root) context=u:r:ksu:s0", font=f_res2, fill=FG)
    d.text((72, 708), "CapPrm=CapEff=CapBnd=000001ffffffffff    kernelsu 180224 4 - Live", font=f_res2, fill=GREEN)

    img.save(path)
    print("  ", path)


# ============================================================
# 4. 决策树（最容易被传播的一张）
# ============================================================
def decision(path):
    W, H = 1280, 900
    img = vgrad(W, H, (13, 17, 23), (9, 12, 17))
    d = ImageDraw.Draw(img)

    f_title = font(FE, 28)
    f_sub = font(FB, 15)
    d.text((44, 30), "Which route should you try?", font=f_title, fill=FG)
    d.text((44, 70), "13 routes we tested to death. Check the criterion before burning a weekend.", font=f_sub, fill=DIM)

    f_q = font(FCB, 16)
    f_a = font(FB, 14)
    f_tag = font(FCB, 13)

    rows = [
        ("Is the kernel version < 6.6.158?",
         "Not enough. OEM backports exist. DISASSEMBLE remove_waiter / begin_new_exec instead.", "CHECK FIRST", YELLOW),
        ("mqsas: do method indices 16-30 respond?",
         "Ours: only 1-15 exist, runCommand allowlisted, mqsasd not even running. Dead on HyperOS 3.0.303.", "DEAD", RED),
        ("Bad Epoll: does ep_remove contain an epi_fget pin + fput?",
         "If yes it is patched. Ours has it. The 99% PoC will not work.", "DEAD", RED),
        ("GhostLock: any mrs sp_el0 inside remove_waiter?",
         "Zero occurrences means it already uses waiter->task. Patched.", "DEAD", RED),
        ("Does /proc/sys/vm/unprivileged_userfaultfd read 1?",
         "If 0, every userfaultfd CVE is out immediately.", "DEAD", RED),
        ("Is there a working free BROM write path? (penumbra)",
         "Xiaomi enables BROM SLA + DAA. Fenrir needs unlocked BL. Lkpatcher needs mtkclient.", "DEAD", RED),
        ("Does the shell have group 3012(readtracefs)?",
         "Then trace_pipe_raw is readable and CVE-2026-98260 is on the table.", "GOOD", GREEN),
        ("Kernel string matches a known-working Shark profile?",
         "6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k does. Otherwise regenerate the profile.", "GOOD", GREEN),
        ("Does the exploit fail with timers=0 / task_recs=0?",
         "Then it is the KASLR alignment bug. Sweep {0, 0x80000, 0x100000, 0x180000}.", "FIX THIS", CYAN),
    ]

    y = 108
    for q, a, tag, col in rows:
        rrect(d, (44, y, 44 + 1192, y + 78), 8, fill=BG2, outline=BORDER, width=1)
        d.rectangle((44, y, 48, y + 78), fill=col)
        d.text((66, y + 13), q, font=f_q, fill=FG)
        d.text((66, y + 40), a, font=f_a, fill=DIM)
        tw = d.textbbox((0, 0), tag, font=f_tag)
        tw = tw[2] - tw[0] + 20
        rrect(d, (44 + 1192 - tw - 14, y + 24, 44 + 1192 - 14, y + 24 + 28), 5,
              fill=(20, 24, 30), outline=col, width=1)
        d.text((44 + 1192 - tw - 4, y + 30), tag, font=f_tag, fill=col)
        y += 86

    img.save(path)
    print("  ", path)




# ============================================================
# 5. 中文决策树
# ============================================================
def decision_zh(path):
    W, H = 1280, 900
    img = vgrad(W, H, (13, 17, 23), (9, 12, 17))
    d = ImageDraw.Draw(img)

    f_title = font(FMB, 27)
    f_sub = font(FM, 15)
    d.text((44, 30), "你该试哪条路？", font=f_title, fill=FG)
    d.text((44, 70), "我们把这 13 条路全试死了。动手前先看判据，省得白熬一个周末。", font=f_sub, fill=DIM)

    f_q = font(FMB, 16)
    f_a = font(FM, 14)
    f_tag = font(FMB, 13)

    rows = [
        ("内核版本 < 6.6.158 就一定有漏洞吗？",
         "不一定。厂商会提前回补。必须反汇编 remove_waiter / begin_new_exec 确认。", "先验证", YELLOW),
        ("mqsas：方法号 16-30 有响应吗？",
         "我们的只有 1-15，runCommand 有白名单，mqsasd 根本没跑。HyperOS 3.0.303 上死透。", "死路", RED),
        ("Bad Epoll：ep_remove 里有 epi_fget pin + fput 吗？",
         "有就是已修补。我们的有。那个 99% 成功率的 PoC 不会work。", "死路", RED),
        ("GhostLock：remove_waiter 里有 mrs sp_el0 吗？",
         "一次都没有说明它已经在用 waiter->task。已修补。", "死路", RED),
        ("unprivileged_userfaultfd 是不是 1？",
         "如果是 0，所有 userfaultfd 相关 CVE 一次性全废。", "死路", RED),
        ("有没有免费的 BROM 写入门路？（penumbra）",
         "小米开着 BROM SLA + DAA。fenrir 要解锁，lkpatcher 要 mtkclient。", "死路", RED),
        ("shell 有没有 3012(readtracefs) 组？",
         "有的话 trace_pipe_raw 可读，CVE-2026-98260 这条路就打开了。", "可行", GREEN),
        ("内核串能不能匹配到一个已知可用的 Shark profile？",
         "6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k 可以。否则要重新生成。", "可行", GREEN),
        ("exploit 是不是卡在 timers=0 / task_recs=0？",
         "那就是 KASLR 对齐 bug。把 {0, 0x80000, 0x100000, 0x180000} 四个候选都试一遍。", "就修它", CYAN),
    ]

    y = 108
    for q, a, tag, col in rows:
        rrect(d, (44, y, 44 + 1192, y + 78), 8, fill=BG2, outline=BORDER, width=1)
        d.rectangle((44, y, 48, y + 78), fill=col)
        d.text((66, y + 13), q, font=f_q, fill=FG)
        d.text((66, y + 40), a, font=f_a, fill=DIM)
        tw = d.textbbox((0, 0), tag, font=f_tag)
        tw = tw[2] - tw[0] + 20
        rrect(d, (44 + 1192 - tw - 14, y + 24, 44 + 1192 - 14, y + 24 + 28), 5,
              fill=(20, 24, 30), outline=col, width=1)
        d.text((44 + 1192 - tw - 4, y + 30), tag, font=f_tag, fill=col)
        y += 86

    img.save(path)
    print("  ", path)

if __name__ == "__main__":
    print("生成素材:")
    banner_en(os.path.join(OUT, "banner.png"))
    banner_zh(os.path.join(OUT, "banner-zh.png"))
    chain(os.path.join(OUT, "chain.png"))
    decision(os.path.join(OUT, "decision-tree.png"))
    decision_zh(os.path.join(OUT, "decision-tree-zh.png"))
    print("完成")
