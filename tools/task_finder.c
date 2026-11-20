/*
 * task_finder —— 确认本机 task_struct 分配事件长什么样
 *
 * 用 perf 盯 kmem:kmem_cache_alloc，fork 一个子进程，
 * 把所有 bytes_alloc 落在 [0x1000, 0x1a00] 的记录打出来：
 *   pid / call_site / call_site&0x1fffff / bytes_req / bytes_alloc / ptr
 *
 * 目的：验证 Shark 的 COPY_PROCESS_LOW21 = 0x0ab93c 对不对。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __NR_perf_event_open
#define __NR_perf_event_open 241
#endif

#define RING_PAGES 16

static int gfd[16];
static struct perf_event_mmap_page *meta[16];
static unsigned char *pdata[16];
static size_t pg, dsize;
static int nfd;
static uint64_t tail[16];
static int off_pid, off_ptr, off_req, off_alloc, off_site;

static int rd_int(const char *p)
{
	FILE *f = fopen(p, "r");
	int v = -1;

	if (f) {
		if (fscanf(f, "%d", &v) != 1)
			v = -1;
		fclose(f);
	}
	return v;
}

static int field_off(const char *path, const char *name)
{
	FILE *f = fopen(path, "r");
	char line[512];
	int off = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, name) && strstr(line, "offset:")) {
			off = atoi(strstr(line, "offset:") + 7);
			break;
		}
	}
	fclose(f);
	return off;
}

static int perf_open_all(void)
{
	const char *tp = "/sys/kernel/tracing/events/kmem/kmem_cache_alloc";
	char p[256];
	int id;

	snprintf(p, sizeof(p), "%s/id", tp);
	id = rd_int(p);
	snprintf(p, sizeof(p), "%s/format", tp);
	off_pid = field_off(p, "common_pid");
	off_ptr = field_off(p, "ptr");
	off_req = field_off(p, "bytes_req");
	off_alloc = field_off(p, "bytes_alloc");
	off_site = field_off(p, "call_site");
	printf("  [fmt] pid=%d ptr=%d req=%d alloc=%d site=%d (tp_id=%d)\n",
	       off_pid, off_ptr, off_req, off_alloc, off_site, id);
	if (id < 0 || off_site < 0)
		return -1;

	pg = (size_t)sysconf(_SC_PAGESIZE);
	dsize = pg * RING_PAGES;
	for (int c = 0; c < 16; c++) {
		struct perf_event_attr a;
		void *b;
		int fd;

		memset(&a, 0, sizeof(a));
		a.type = PERF_TYPE_TRACEPOINT;
		a.size = sizeof(a);
		a.config = (uint64_t)id;
		a.sample_period = 1;
		a.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_TID;
		a.wakeup_events = 1;
		fd = (int)syscall(__NR_perf_event_open, &a, -1, c, -1, 0);
		if (fd < 0)
			continue;
		b = mmap(NULL, dsize + pg, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (b == MAP_FAILED) {
			close(fd);
			continue;
		}
		gfd[nfd] = fd;
		meta[nfd] = b;
		pdata[nfd] = (unsigned char *)b + pg;
		tail[nfd] = 0;
		ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
		nfd++;
	}
	printf("  [perf] 打开 %d 个环\n", nfd);
	return nfd ? 0 : -1;
}

static void drain(void)
{
	for (int i = 0; i < nfd; i++) {
		uint64_t head = meta[i]->data_head;
		unsigned char *d = pdata[i];

		__sync_synchronize();
		while (tail[i] < head) {
			struct perf_event_header *h =
				(void *)(d + (tail[i] % dsize));

			if (!h->size || h->size > dsize)
				break;
			if (h->type == PERF_RECORD_SAMPLE) {
				unsigned char *rec = (unsigned char *)h;
				size_t pos = sizeof(*h);
				uint32_t rawsz = 0;

				if (pos + 8 <= h->size)
					pos += 8;
				if (pos + 4 <= h->size) {
					memcpy(&rawsz, rec + pos, 4);
					pos += 4;
					if (pos + rawsz <= h->size && rawsz >= 40) {
						unsigned char *r = rec + pos;
						uint32_t pid = 0;
						uint64_t ptr = 0, req = 0, alloc = 0, site = 0;

						if (off_pid >= 0 && (size_t)off_pid + 4 <= rawsz)
							memcpy(&pid, r + off_pid, 4);
						if ((size_t)off_ptr + 8 <= rawsz)
							memcpy(&ptr, r + off_ptr, 8);
						if ((size_t)off_req + 8 <= rawsz)
							memcpy(&req, r + off_req, 8);
						if ((size_t)off_alloc + 8 <= rawsz)
							memcpy(&alloc, r + off_alloc, 8);
						if ((size_t)off_site + 8 <= rawsz)
							memcpy(&site, r + off_site, 8);
						if (alloc >= 0x1000 && alloc <= 0x1a00)
							printf("    pid=%u site=0x%llx low21=0x%llx req=%llu alloc=%llu ptr=0x%llx\n",
							       pid, (unsigned long long)site,
							       (unsigned long long)(site & 0x1fffff),
							       (unsigned long long)req,
							       (unsigned long long)alloc,
							       (unsigned long long)ptr);
					}
				}
			}
			tail[i] += h->size;
		}
		meta[i]->data_tail = tail[i];
	}
}

int main(void)
{
	printf("=== task_finder ===\n");
	if (perf_open_all())
		return 1;

	/* 先排空 */
	for (int i = 0; i < 20; i++) {
		drain();
		usleep(20000);
	}
	printf("  [*] 开始 fork……\n");
	for (int i = 0; i < 40; i++) {
		pid_t c = fork();

		if (c == 0)
			_exit(0);
		if (c > 0) {
			waitpid(c, NULL, 0);
			drain();
			usleep(10000);
		}
	}
	drain();
	printf("=== 结束 ===\n");
	return 0;
}
