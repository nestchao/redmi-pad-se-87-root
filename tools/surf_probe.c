/*
 * surf_probe —— 探测本机对几个「高危但常被关闭」的子系统是否放行
 *
 * 只做无害的创建/查询，不触发任何漏洞。
 *   1) io_uring_setup        —— Android 12+ 常被 seccomp 关掉
 *   2) bpf(BPF_MAP_CREATE)   —— unprivileged_bpf_disabled 常为 2
 *   3) keyctl(KEYCTL_GET_KEYRING_ID)
 *   4) userfaultfd
 *   5) perf_event_open(tracepoint)
 *   6) open("/dev/binder")
 *   7) open("/dev/vhost-vsock")
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef __NR_bpf
#define __NR_bpf 280
#endif
#ifndef __NR_keyctl
#define __NR_keyctl 219
#endif
#ifndef __NR_userfaultfd
#define __NR_userfaultfd 282
#endif
#ifndef __NR_perf_event_open
#define __NR_perf_event_open 241
#endif

#define KEYCTL_GET_KEYRING_ID 0
#define KEY_SPEC_SESSION_KEYRING (-3)
#define BPF_MAP_CREATE 0
#define BPF_MAP_TYPE_ARRAY 2

struct io_uring_params_min {
	uint32_t sq_entries, cq_entries, flags, sq_thread_cpu, sq_thread_idle;
	uint32_t features, wq_fd, resv[3];
	uint32_t sq_off[10];
	uint32_t cq_off[10];
};

static int bpf_map_create(void)
{
	union {
		struct {
			uint32_t map_type, key_size, value_size, max_entries, map_flags;
		} in;
		char buf[64];
	} u;
	char log[256];

	memset(&u, 0, sizeof(u));
	u.in.map_type = BPF_MAP_TYPE_ARRAY;
	u.in.key_size = 4;
	u.in.value_size = 8;
	u.in.max_entries = 4;
	memset(log, 0, sizeof(log));
	return (int)syscall(__NR_bpf, BPF_MAP_CREATE, &u, sizeof(u.in));
}

int main(void)
{
	struct io_uring_params_min p;
	int fd;
	long r;

	memset(&p, 0, sizeof(p));
	r = syscall(__NR_io_uring_setup, 8, &p);
	printf("io_uring_setup      -> %ld  errno=%d(%s)\n", r, r < 0 ? errno : 0,
	       r < 0 ? strerror(errno) : "ok");
	if (r >= 0)
		close((int)r);

	fd = bpf_map_create();
	printf("bpf(MAP_CREATE)     -> %d  errno=%d(%s)\n", fd, fd < 0 ? errno : 0,
	       fd < 0 ? strerror(errno) : "ok");
	if (fd >= 0)
		close(fd);

	r = syscall(__NR_keyctl, KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, 1);
	printf("keyctl(GET_KEYRING) -> %ld  errno=%d(%s)\n", r, r < 0 ? errno : 0,
	       r < 0 ? strerror(errno) : "ok");

	r = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	printf("userfaultfd         -> %ld  errno=%d(%s)\n", r, r < 0 ? errno : 0,
	       r < 0 ? strerror(errno) : "ok");
	if (r >= 0)
		close((int)r);

	fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	printf("open(/dev/binder)   -> %d  errno=%d(%s)\n", fd, fd < 0 ? errno : 0,
	       fd < 0 ? strerror(errno) : "ok");
	if (fd >= 0)
		close(fd);

	fd = open("/dev/vhost-vsock", O_RDWR | O_CLOEXEC);
	printf("open(vhost-vsock)   -> %d  errno=%d(%s)\n", fd, fd < 0 ? errno : 0,
	       fd < 0 ? strerror(errno) : "ok");
	if (fd >= 0)
		close(fd);

	fd = open("/dev/uhid", O_RDWR | O_CLOEXEC);
	printf("open(/dev/uhid)     -> %d  errno=%d(%s)\n", fd, fd < 0 ? errno : 0,
	       fd < 0 ? strerror(errno) : "ok");
	if (fd >= 0)
		close(fd);

	return 0;
}
