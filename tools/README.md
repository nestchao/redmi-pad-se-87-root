# tools/ · 我们写的诊断工具

这些工具都是**独立的、可单独编译的小程序**，用来测量和分析。
大部分是零风险的（只读），少数会触发漏洞。

编译：

```bash
ANDROID_NDK=/path/to/ndk ./scripts/build.sh
```

---

## 零风险（只读 / 探测）

### `surf_probe.c`

探测哪些「高危但常被关闭」的子系统在本机可用。

```console
$ ./surf_probe
io_uring_setup      -> 3  errno=0(ok)
bpf(MAP_CREATE)     -> 3  errno=0(ok)
keyctl(GET_KEYRING) -> 128329442  errno=0(ok)
userfaultfd         -> -1  errno=1(Operation not permitted)
open(/dev/binder)   -> 3  errno=0(ok)
open(vhost-vsock)   -> 3  errno=0(ok)
open(/dev/uhid)     -> 3  errno=0(ok)
```

**⚠️ 注意**：结果严重依赖 SELinux 状态。
Enforcing 下 `io_uring_setup` / `bpf` 会返回 EACCES，Permissive 下才 OK。

### `trace_probe.c`

验证 EXACT HIT 方案的三个基石（**不触发 UAF**）。

```bash
adb shell /data/local/tmp/trace_probe 512 256
```

它做三件事：

| 步骤 | 验证什么 |
|---|---|
| 往 `kprobe_events` 写两条探针 | kprobe 通路能不能建 |
| 建/销 512 个 posix timer | `free_slab` 能不能抓到我们的 cache |
| 建 256 个 AIO 上下文 | `__filemap_get_folio` 能不能拿到 folio |

### `task_finder.c`

确认本机 `task_struct` 分配的 call_site 长什么样。
用来验证 `copy_process+0x140` 这个常量。

**⚠️ 需要 Permissive 才能用 perf。**

### `kaslr_leak.c`

KASLR 泄露的独立实现（tracefs raw 记录法）。

### `aio_probe.c`

验证 `io_setup` 能给多少页。

```console
$ ./aio_probe
创建 AIO 上下文: 60000 个，失败 0 个，占用 234 MB
```

### `kmem_perf.c`

perf `kmem:kmem_cache_alloc` 事件的读取参考实现。
演示了正确的 mmap 布局和 ring 排空方式。

---

## 会触发漏洞（谨慎）

### `pwn_min.c`

最小的 Stage A 实现 —— 把 SELinux 打成 Permissive。

```bash
./pwn_min 8 30000 1 aio same
#          │ │     │ │    └─ 统一相位
#          │ │     │ └─ AIO 载体
#          │ │     └─ 每单位 1 页
#          │ └─ 30000 个上下文（≈234 MB）
#          └─ 相位 8
```

**风险**：约 1/3 概率 kernel panic（相位 16 那次写不成）。
重启后恢复，不会砖。

### `cred_finder.c`

用 perf 采样找 cred 地址。

**判据**（三条同时成立）：
- `bytes_req == 184`（`sizeof(struct cred)`）
- `(addr % 4096) % 192 == 0`（`cred_jar` 几何）
- `call_site ∈ prepare_creds`（`base + 0xe4040`，跨度 `0x2fc`）

**⚠️ 需要 Permissive 才能开 perf。**

### `trace_raw_leak.c`

从 `trace_pipe_raw` 的二进制记录里提取真实指针。
演示了「文本 trace 会 hash，raw 不会」。

---

## 这些工具在项目里的角色

```
surf_probe        →  阶段一：摸清攻击面
kaslr_leak        →  阶段二：拿 KASLR
aio_probe         →  阶段二：验证载体容量
kmem_perf         →  阶段二：perf 读取参考
cred_finder       →  阶段三：定位 cred（三条判据）
trace_probe       →  阶段四：验证 EXACT HIT 通路
task_finder       →  阶段四：验证 task 分配常量
pwn_min           →  实战：Stage A
trace_raw_leak    →  贯穿：拿真实指针
```

**真正成功的路径是 Shark，这些工具是用来「理解和验证」的。**

**但如果没有它们，我们不会知道 `timers=0` 的真正原因。**
