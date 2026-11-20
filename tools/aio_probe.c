/*
 * aio_probe —— 测试 io_setup（AIO ring）能否作为 order-0 UNMOVABLE 载体
 *
 * 背景：pipe 页受 /proc/sys/fs/pipe-user-pages-soft 限制（默认 16384 页 = 64MB），
 *      喷不到 500MB。AIO ring 每页一次 find_or_create_page(GFP_USER|__GFP_ZERO)，
 *      order-0、UNMOVABLE、用户态可直接读写，且没有 per-user pipe 限额。
 *
 * 用法：aio_probe [max_ctx] [events_per_ctx]
 *   每建成功一个上下文，就往 ring 首页写一个标记并读回，验证可写。
 *   最后打印：成功上下文数、总页数、估算 MB
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_io_setup
#define __NR_io_setup 0
#endif
#define IOCB_FLAG_RESFD 1
typedef unsigned long aio_context_t;

static inline long io_setup(unsigned nr, aio_context_t *ctx)
{
	return syscall(__NR_io_setup, nr, ctx);
}

static inline long io_destroy(aio_context_t ctx)
{
	return syscall(__NR_io_destroy, ctx);
}

int main(int argc, char **argv)
{
	int maxctx = (argc > 1) ? atoi(argv[1]) : 20000;
	int ev = (argc > 2) ? atoi(argv[2]) : 1;
	long ok = 0, fail = 0, wr_ok = 0;
	int first_errno = 0;
	aio_context_t *ctxs = calloc((size_t)maxctx, sizeof(aio_context_t));

	if (!ctxs) {
		printf("calloc failed\n");
		return 1;
	}
	for (int i = 0; i < maxctx; i++) {
		volatile unsigned long *ring;
		aio_context_t c = 0;
		long r = io_setup((unsigned)ev, &c);

		if (r < 0) {
			fail++;
			if (!first_errno)
				first_errno = errno;
			if (fail > 50)
				break;
			continue;
		}
		ok++;
		/* ring 的首页可写吗？ */
		ring = (volatile unsigned long *)(unsigned long)c;
		ring[8] = 0x4141414142424242UL + (unsigned long)i;
		if (ring[8] == 0x4141414142424242UL + (unsigned long)i)
			wr_ok++;
		ctxs[i] = c;
	}
	printf("io_setup: ok=%ld fail=%ld 可写=%ld first_errno=%d(%s)\n",
	       ok, fail, wr_ok, first_errno, strerror(first_errno));
	printf("每上下文 %d 事件 ⇒ 估算 %ld 页 ≈ %ld MB\n",
	       ev, ok, ok * 4 / 1024);
	fflush(stdout);

	/* 不销毁：验证「持有型页」 */
	printf("hold...\n");
	fflush(stdout);
	sleep(30);
	for (long i = 0; i < ok && i < maxctx; i++)
		if (ctxs[i])
			io_destroy(ctxs[i]);
	return 0;
}
