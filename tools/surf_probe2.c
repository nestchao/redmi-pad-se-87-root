/*
 * surf_probe2 —— 第二轮探测：确认几个「有公开 PoC 的 CVE」所需入口是否放行
 *
 *   CVE-2026-46242 "Bad Epoll"   → epoll_create1 + 常规 fd
 *   CVE-2026-43494 "PinTheft"    → socket(AF_RDS) + io_uring fixed buffers
 *   CVE-2026-53365 "VsockDrop"   → socket(AF_VSOCK) + io_uring zerocopy
 *   CVE-2026-31413 BPF verifier  → bpf(PROG_LOAD)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef AF_RDS
#define AF_RDS 21
#endif
#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

static void rep(const char *what, long r)
{
	printf("%-34s -> %ld  errno=%d(%s)\n", what, r, r < 0 ? errno : 0,
	       r < 0 ? strerror(errno) : "ok");
}

int main(void)
{
	long r;
	int fd;

	r = epoll_create1(EPOLL_CLOEXEC);
	rep("epoll_create1", r);
	if (r >= 0) close((int)r);

	r = socket(AF_RDS, SOCK_SEQPACKET, 0);
	rep("socket(AF_RDS,SEQPACKET)", r);
	if (r >= 0) close((int)r);

	r = socket(AF_VSOCK, SOCK_STREAM, 0);
	rep("socket(AF_VSOCK,STREAM)", r);
	if (r >= 0) close((int)r);

	r = socket(AF_VSOCK, SOCK_DGRAM, 0);
	rep("socket(AF_VSOCK,DGRAM)", r);
	if (r >= 0) close((int)r);

	r = socket(AF_NETLINK, SOCK_RAW, 0);
	rep("socket(AF_NETLINK)", r);
	if (r >= 0) close((int)r);

	r = socket(AF_PACKET, SOCK_RAW, 0);
	rep("socket(AF_PACKET,RAW)", r);
	if (r >= 0) close((int)r);

	r = socket(AF_BLUETOOTH, SOCK_RAW, 1 /* BTPROTO_HCI */);
	rep("socket(AF_BLUETOOTH,RAW)", r);
	if (r >= 0) close((int)r);

	/* io_uring + fixed buffer 这条链需要 IORING_REGISTER_BUFFERS 可用 */
	{
		struct {
			uint32_t sq_entries, cq_entries, flags, sq_thread_cpu,
				 sq_thread_idle, features, wq_fd, resv[3];
			uint32_t sq_off[10], cq_off[10];
		} p;
		memset(&p, 0, sizeof(p));
		r = syscall(425 /* io_uring_setup */, 8, &p);
		rep("io_uring_setup(8)", r);
		if (r >= 0) {
			printf("    sq_entries=%u cq_entries=%u features=0x%x\n",
			       p.sq_entries, p.cq_entries, p.features);
			close((int)r);
		}
	}

	fd = open("/dev/net/tun", O_RDWR);
	rep("open(/dev/net/tun)", fd);
	if (fd >= 0) close(fd);

	return 0;
}
