/*
 * trace_probe —— 无害验证工具：确认 tracefs 的 kprobe 通路在我们设备上能用
 *
 * 它**不触发任何 UAF**，只做三件事：
 *   1. 建两个探针：free_slab（kprobe）和 __filemap_get_folio（kretprobe）
 *   2. 制造两种事件：创建/销毁 posix timer（触发 free_slab）、
 *      创建 AIO 上下文（触发 __filemap_get_folio）
 *   3. 读 /sys/kernel/tracing/trace，把抓到的 slab / folio 地址打出来
 *
 * 目的：验证 EXACT HIT 方案的三块基石是否成立
 *   - kprobe_events 能不能写（0777 是 DAC，还要看 SELinux）
 *   - free_slab 能不能抓到 posix_timers_cache 的释放
 *   - __filemap_get_folio 能不能拿到 AIO 页的 folio 指针
 *
 * 用法：trace_probe [timers] [aio]
 *   默认 timers=512 aio=256
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef __NR_io_setup
#define __NR_io_setup 0
#endif
#ifndef __NR_io_destroy
#define __NR_io_destroy 1
#endif

typedef unsigned long aio_context_t;

#define TRACE "/sys/kernel/tracing"
#define GROUP "probe98260"

static int write_file(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0) {
		fprintf(stderr, "[!] open %s: %s\n", path, strerror(errno));
		return -1;
	}
	n = write(fd, text, strlen(text));
	close(fd);
	if (n < 0) {
		fprintf(stderr, "[!] write %s: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

static void probe_cleanup(void)
{
	/* 删掉我们建的探针（写 "-:GROUP/EVENT"） */
	write_file(TRACE "/kprobe_events", "-:" GROUP "/free_slab\n");
	write_file(TRACE "/kprobe_events", "-:" GROUP "/folio\n");
}

static int probe_create(void)
{
	char buf[512];
	int rc = 0;

	/* kprobe：free_slab(struct kmem_cache *s, struct slab *slab) */
	snprintf(buf, sizeof(buf),
		 "p:" GROUP "/free_slab free_slab cache=%%x0:x64 slab=%%x1:x64\n");
	if (write_file(TRACE "/kprobe_events", buf)) {
		fprintf(stderr, "[!] free_slab 探针创建失败（可能没有 kprobe 权限）\n");
		rc = -1;
	} else {
		printf("[+] free_slab 探针已建\n");
	}

	/* kretprobe：__filemap_get_folio 的返回值就是 folio */
	snprintf(buf, sizeof(buf),
		 "r:" GROUP "/folio __filemap_get_folio folio=$retval:x64\n");
	if (write_file(TRACE "/kprobe_events", buf)) {
		fprintf(stderr, "[!] folio 探针创建失败\n");
		rc = -1;
	} else {
		printf("[+] __filemap_get_folio 探针已建\n");
	}
	return rc;
}

static void tracing_on(void)
{
	write_file(TRACE "/tracing_on", "0");
	write_file(TRACE "/trace", "");		/* 清空 */
	write_file(TRACE "/events/" GROUP "/free_slab/enable", "1");
	write_file(TRACE "/events/" GROUP "/folio/enable", "1");
	write_file(TRACE "/tracing_on", "1");
}

static void tracing_off(void)
{
	write_file(TRACE "/tracing_on", "0");
	write_file(TRACE "/events/" GROUP "/free_slab/enable", "0");
	write_file(TRACE "/events/" GROUP "/folio/enable", "0");
}

/* 创建并销毁一批 posix timer，触发 posix_timers_cache 的 free_slab */
static void make_timers(int n)
{
	timer_t *tv = calloc((size_t)n, sizeof(timer_t));

	if (!tv)
		return;
	for (int i = 0; i < n; i++) {
		struct sigevent sev;

		memset(&sev, 0, sizeof(sev));
		sev.sigev_notify = SIGEV_NONE;
		if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &tv[i]))
			tv[i] = (timer_t)-1;
	}
	/* 再销毁，这会走到 k_itimer 的释放 → free_slab(posix_timers_cache, ...) */
	for (int i = 0; i < n; i++)
		if (tv[i] != (timer_t)-1)
			timer_delete(tv[i]);
	free(tv);
}

/* 创建一批 AIO 上下文，触发 __filemap_get_folio */
static void make_aio(int n)
{
	aio_context_t *ctx = calloc((size_t)n, sizeof(*ctx));

	if (!ctx)
		return;
	for (int i = 0; i < n; i++) {
		ctx[i] = 0;
		if (syscall(__NR_io_setup, 1, &ctx[i]))
			ctx[i] = 0;
	}
	sleep(1);
	for (int i = 0; i < n; i++)
		if (ctx[i])
			syscall(__NR_io_destroy, ctx[i]);
	free(ctx);
}

static void dump_trace(int limit)
{
	FILE *f = fopen(TRACE "/trace", "r");
	char line[512];
	int shown = 0, slab = 0, folio = 0;

	if (!f) {
		fprintf(stderr, "[!] 打不开 trace: %s\n", strerror(errno));
		return;
	}
	while (fgets(line, sizeof(line), f) && shown < limit) {
		if (strstr(line, "free_slab") || strstr(line, "folio")) {
			if (strstr(line, "free_slab"))
				slab++;
			else
				folio++;
			printf("  %s", line);
			shown++;
		}
	}
	fclose(f);
	printf("\n[统计] free_slab 事件 %d 条，folio 事件 %d 条（显示前 %d 条）\n",
	       slab, folio, shown);
}

int main(int argc, char **argv)
{
	int ntimers = argc > 1 ? atoi(argv[1]) : 512;
	int naio = argc > 2 ? atoi(argv[2]) : 256;

	printf("=== trace_probe: 验证 kprobe / free_slab / folio 通路 ===\n");

	probe_cleanup();		/* 清掉上次残留 */
	if (probe_create()) {
		printf("[结论] 探针建不起来 —— EXACT HIT 方案在这台设备上不可用\n");
		return 1;
	}

	tracing_on();
	printf("[*] 创建 %d 个 posix timer 后销毁……\n", ntimers);
	make_timers(ntimers);
	printf("[*] 创建 %d 个 AIO 上下文……\n", naio);
	make_aio(naio);
	sleep(1);
	tracing_off();

	printf("\n=== trace 内容（只显示我们的两类事件）===\n");
	dump_trace(40);

	probe_cleanup();
	printf("\n=== 结束（探针已清理，没有做任何危险操作）===\n");
	return 0;
}
