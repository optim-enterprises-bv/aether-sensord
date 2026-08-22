/*
 * Benchmark scaffolding -- NOT shipped.
 *
 * Measures NEW-FLOW RATE: how many TCP connections per second can be
 * established. That is the metric the aether-sensord design turns on, because
 * only the first packets of a flow would ever be queued to userspace; the rest
 * are verdicted once and fly.
 *
 * Bulk throughput is deliberately NOT measured. A box can forward gigabits of
 * established traffic and still fall over on connection setups, and setups are
 * what cost us.
 *
 * Runs against a listener on loopback so no household traffic is involved.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
	int port = (argc > 2) ? atoi(argv[2]) : 9999;
	int count = (argc > 3) ? atoi(argv[3]) : 2000;

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
		fprintf(stderr, "bad host %s\n", host);
		return 2;
	}

	struct timeval t0, t1;
	int ok = 0, fail = 0;

	gettimeofday(&t0, NULL);
	for (int i = 0; i < count; i++) {
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0) {
			fail++;
			continue;
		}
		/* Send the FIN immediately on close rather than lingering, so the
		 * run is not throttled by TIME_WAIT accumulation. */
		struct linger lg = { 1, 0 };
		setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

		if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
			/* One byte, so the flow carries data as a real one would. */
			ssize_t w = write(fd, "x", 1);
			(void)w;
			ok++;
		} else {
			fail++;
		}
		close(fd);
	}
	gettimeofday(&t1, NULL);

	double secs = (double)(t1.tv_sec - t0.tv_sec) +
	              (double)(t1.tv_usec - t0.tv_usec) / 1e6;
	printf("%d ok, %d failed in %.3fs", ok, fail, secs);
	if (secs > 0.0001 && ok > 0)
		printf(" = %.0f conn/s, %.1f us/conn", (double)ok / secs,
		       secs * 1e6 / (double)ok);
	printf("\n");
	return 0;
}
