# 12 · 踩过的坑（完整清单）

**中文** · [English](en/12-pitfalls.md)

> 这一章记录我们实际踩过的所有坑，包括：
> - 自己写代码引入的 7 个 bug
> - 9 次编码/工具事故
> - 各种误导性的现象
>
> **希望能帮你少走弯路。**

---

## 一、自己写代码引入的 7 个 bug

这些都是在我们自己写的 `pwn.c` / `pwn_min.c` 里出现的，
每一个都让某次实验白跑。

### bug 1：pipe_spray 里 fd 数组越界

```c
/* 错：没检查 npipes 和数组容量的关系 */
for (int i = 0; i < npipes; i++) {
    pipe(pfd[i]);                /* pfd 只有 512 个元素 */
    ...
}
```

**症状**：随机崩溃 / 数据错乱。
**修法**：加边界检查。

### bug 2：`(void)phase` 把命令行参数丢了

```c
/* 错：形参覆盖了全局 */
static void build_page(unsigned char *p, int phase)
{
    phase = (void)phase;         /* 手误，把参数丢了 */
    ...
}
```

**症状**：无论传什么相位参数，行为都一样。
**修法**：删掉这行。

**这个 bug 特别阴险 —— 因为它不报错，只是「参数没生效」。**

### bug 3：`static timer_t *tv` 双重释放

```c
/* 错：static 指针，函数被调两次就 double free */
static timer_t *tv;
void make_timers(void) {
    tv = calloc(N, sizeof(timer_t));
    ...
}
```

**修法**：改成局部变量，或者在函数末尾置 NULL。

### bug 4：`F_SETPIPE_SZ` 没检查返回值 → 阻塞的 write

```c
/* 错：设置 pipe 大小失败时，write 会阻塞 */
pipe(pfd);
fcntl(pfd[1], F_SETPIPE_SZ, 4096 * 16);   /* 可能失败 */
write(pfd[1], buf, 4096 * 16);            /* 阻塞！ */
```

**症状**：程序卡住不动。
**修法**：

```c
int sz = fcntl(pfd[1], F_SETPIPE_SZ, want);
if (sz < want) { /* 用 sz 而不是 want */ }
```

### bug 5：spray_sock 的边界检查写在了循环外面

```c
/* 错：检查一次就进循环 */
if (i < MAX) {
    for (; i < n; i++) spray_sock(...);   /* i 可能超过 MAX */
}
```

**修法**：检查放在循环体内。

### bug 6：内存上限没除以波数 → OOM

```c
/* 错：每次都申请 max/1，但跑了 N 波 */
for (int wave = 0; wave < N; wave++)
    spray(mem_total);        /* 总用量 = N × mem_total */
```

**症状**：设备 OOM，系统卡死。
**修法**：

```c
size_t per_wave = mem_total / N;
for (int wave = 0; wave < N; wave++)
    spray(per_wave);
```

### bug 7：整页连续 payload 导致相位循环

```c
/* 错：payload 从页首开始连续铺，导致页内每 24 字节一个周期，
   但 4096 不是 24 的整数倍，于是不同位置相位不同 */
for (off = 0; off + 24 <= 4096; off += 24) { ... }
/*  4096 / 24 = 170.67 → 最后一小段是残缺的周期 */
```

**症状**：无论怎么调相位参数，命中率都只有 1/3。
**修法**：让整页**只用同一个相位**，从 `phase` 开始铺，
并且确保 `phase + 24*k` 不跨页边界。

---

## 二、9 次编码 / 工具事故

### 事故 1：UTF-8 without BOM 的 `.ps1` 解析失败

**症状**：PowerShell 报莫名其妙的语法错误。

**原因**：PowerShell 5.1 默认按 ANSI 读无 BOM 文件，
中文注释被错误解码，导致引号/括号失配。

**修法**：**含非 ASCII 字符的 `.ps1` 必须存成 UTF-8 with BOM**。

### 事故 2：字面 `` `r`n `` 被写进 C 文件

**症状**：C 代码里有反引号，编译失败。

**原因**：在 PowerShell 里用双引号字符串拼接 C 代码时，
`` `r`n `` 被当成转义序列，但有时代码被原样写入。

**修法**：用 here-string（`@'...'@`）而不是双引号拼接。

### 事故 3：`aqlr.py` 在 GBK 控制台崩溃

**症状**：`UnicodeEncodeError: 'gbk' codec can't encode character`。

**修法**：

```python
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
```

### 事故 4：计划任务输出乱码

**症状**：定时任务的日志文件里全是乱码。

**修法**：

```powershell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# 并且机器读的标记只用 ASCII
```

### 事故 5-7：`.Replace(old, new, count)` 在 PS 5.1 不存在

**症状**：`.Replace(...)` 静默不生效，以为改了其实没改。

**原因**：`String.Replace(String, String, Int32)` 是 .NET Core 才有的重载，
PS 5.1 用的是 .NET Framework，只能 `Replace(String, String)`。

**修法**：
- 用 `edit` 工具而不是字符串替换
- 或者把文件读成行数组，改完再写回

### 事故 8-9：UTF-8 内容被 `Set-Content -Encoding UTF8` 加上 BOM 后又被重复读取

**症状**：文件开头出现 `` 字符，Python 解析报 `invalid non-printable character U+FEFF`。

**修法**：用无 BOM 写入：

```powershell
[System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
```

---

## 三、误导性现象

### 现象 1：`bytes_req` 是 184 不是 192

我们找 cred 分配时，一开始以为应该是 192（`cred_jar` 的 `size`）。
结果一条都抓不到。

**真相**：

```
bytes_req   = s->object_size  = 184   ← sizeof(struct cred)
bytes_alloc = s->size         = 192   ← 对齐后的 slab 大小
```

**slabinfo 里报的 objsize 是 192，但 tracepoint 报的 bytes_req 是 184。**

### 现象 2：`PERF_SAMPLE_TID` 在 per-CPU 事件里是 -1

我们一开始用 `tid == mytid` 过滤，**样本全丢**。

**真相**：per-CPU 的 perf 事件不关联具体任务，`sample.tid` 是 `-1`。

**修法**：去掉这个过滤。

### 现象 3：`MemFree` 只有 80 MB，但 `MemAvailable` 有 2.2 GB

我们用 `MemFree` 算可用内存来规划喷射量，结果只敢喷 80 MB，完全不够。

**真相**：Android 上大部分内存是 page cache，`MemFree` 很低但 `MemAvailable` 很高。

**修法**：读 `/proc/meminfo` 的 `MemAvailable`。

### 现象 4：第一版 KASLR 泄露只有 1.6 秒 60 条记录

我们以为 trace 里没数据。

**真相**：perf ring 溢出。改成每 20 ms 排空一次后，**13861 条，230 倍差距**。

### 现象 5：`io_setup` 看起来被关了

早期探测发现 `io_setup` 返回 EACCES，以为不能用。

**真相**：那是 **SELinux Enforcing** 下的拦截。
在 **Permissive** 下 `io_setup` 是完全可以用的，而且给了我们 234 MB。

**⇒ 探测任何 syscall 前，先确认 SELinux 状态。**

### 现象 6：`id` 显示 `uid=0` 但什么都干不了

第一阶段成功后：

```
uid=0(root) gid=0(root) ... context=u:r:shell:s0
CapEff: 0000000000000000     ← 能力集是空的！
```

**真相**：默认模式只清 `cred->uid`，不清 `cred->cap_*`。

**没有 `CAP_DAC_OVERRIDE`，uid=0 也读不了别人的文件。**

**⇒ 「uid=0」不等于 root。必须检查 `CapEff`。**

### 现象 7：`setuid(0)` 返回 0 但 `resuid` 第三个还是 2000

```
[child] setuid(0)=0 errno=0 resuid=0/0/2000
```

**真相**：`setuid(0)` 在「非特权」分支下只设 euid，不改 suid。
要全部归零需要 `setresuid(0,0,0)`，或者先让 euid=0 再调一次。

### 现象 8：`getenforce` 显示 Permissive，但 `setenforce 0` 还是 Permission denied

**真相**：我们改的是 `selinux_state.enforcing`，
但 `setenforce` 走的是 SELinux 的权限检查路径，
即使已经是 permissive，`u:r:shell:s0` 仍然无权调用。

**⇒ 「permissive」只关闭 LSM 的强制检查，不授予 capability。**

### 现象 9：设备莫名其妙掉线

**真相**：内核 panic 后自动重启，30–60 秒回来。
这一路我们崩了十几次，**每次都自己恢复了。**

**⇒ 掉线不一定是设备坏了，等一分钟再看。**

---

## 四、方法论层面的坑

### 坑 1：按版本号判断漏洞是否存在

**错**：`ghostlock419` 的 README 写「影响 6.6.x，修于 6.6.140」，我们是 6.6.118 → 以为中招。

**真相**：**小米提前 backport 了修复。** 反汇编确认已经修好。

**⇒ 必须反汇编验证，不能只看版本号。**

### 坑 2：相信社区的「这个方法能用」

mqsas 有六条独立来源证明能用。但我们设备上：
- 方法号被砍
- 命令有白名单
- 后端守护进程没跑

**⇒ 厂商会按机型/地区/版本做差异化阉割。必须实测。**

### 坑 3：以为「源码能用」

Shark 的公开源码（fork v2.3.2）和上游二进制（v2.5.1）**行为不同**。

**⇒ 二进制行为才是真相。源码可能滞后。**

### 坑 4：第一次失败就放弃

同内核机型的报告说：
> the **first attempt failed** at `fake_uid` (`FAIL=cred`, `exit=13`)
> and the **second succeeded in 6468 ms**

**我们有几次失败如果就停了，就不会成功。**

**⇒ 概率型漏洞，多试几次。**

### 坑 5：把「内存泄漏」当成「功能不可用」

`io_uring` 在 Enforcing 下不可用，在 Permissive 下可用。
如果不区分状态，会误判很多条路。

---

## 五、安全相关的记录

### 我们做对了什么

| 做法 | 效果 |
|---|---|
| **全程零分区写入** | 从未变砖 |
| exploit 前检查源码里有没有 `dd` / `flash` / `insmod` | 确认安全 |
| 失败时 `PARKED` 不盲 reap | 大幅减少 panic |
| panic 后等 30–60 秒 | 每次自动恢复 |
| 重要日志每行 `fsync` | panic 后还能看到 |

### 实测数据

| 项 | 数值 |
|---|---|
| 总共跑 exploit 次数 | ~20 次 |
| 内核 panic 次数 | ~10 次（都在早期盲 reap 阶段） |
| **修复后 panic 次数** | **0**（6 次运行） |
| 变砖次数 | **0** |
| 分区写入次数 | **0** |

### 如果 panic 了怎么办

1. 等 30–60 秒，设备会自己重启
2. `/data/local/tmp` 里的文件**还在**（那是 /data 分区）
3. KASLR 会重新随机 → slide 变了
4. SELinux 回到 Enforcing
5. **重跑即可**

### 唯一需要小心的

如果 panic 时正好有文件在写，那个文件可能损坏。
**所以重要数据建议先备份。**

---

## 六、一张「症状 → 原因」速查表

| 症状 | 最可能的原因 |
|---|---|
| `[calib] timers=0` | KASLR 低21位没补偿（见 09 章）|
| `task_recs=0` 但 `recs=1` | 同上 |
| `burst hit=0` + `holding zombie` | 页回收概率问题，重跑 |
| `LATE_LOAD_SKIP=env-missing` | 没设 `PYB110_KSUD` |
| `su: not found` | KSU 模块没加载 |
| `uid=0` 但 `CapEff=0` | 用的是默认模式，不是 fake 模式 |
| 程序卡住不動 | pipe 的 `write` 阻塞 / trace 没关 |
| 设备掉线 | 内核 panic，等 60 秒 |
| `io_setup` EACCES | SELinux Enforcing，需要 Permissive |
| trace 里 `ptr` 是 hash 的 | 用了文本 `trace`，要用 `trace_pipe_raw` |
| `.ps1` 报奇怪语法错误 | 文件是 UTF-8 无 BOM |
