/*
 * Benchmark scaffolding -- NOT shipped, NOT part of aether-sensord.
 *
 * Minimal NFQUEUE handler: pull a packet, verdict ACCEPT, count it. It does no
 * classification at all, deliberately -- the number it produces is the FLOOR
 * cost of a userspace round trip per packet. Anything real (nDPI dissection,
 * signature matching, policy) is strictly on top of this.
 *
 * That floor is the number that decides whether a userspace NFQUEUE design can
 * replace an in-kernel module. If the floor alone is too expensive, no amount
 * of optimising the classification helps.
 *
 * Uses libnetfilter_queue, which is GPL-2.0-or-later. That is fine HERE and
 * only here: this program is a measuring instrument, never linked into and
 * never shipped with the product. The shipping design would speak nfnetlink
 * over libmnl (LGPL-2.1+) instead.
 */

#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;
static unsigned long packets;
static struct timeval t_first, t_last;

static void on_sig(int s)
{
	(void)s;
	running = 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
	(void)nfmsg;
	(void)data;
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
	uint32_t id = ph ? ntohl(ph->packet_id) : 0;

	if (packets == 0)
		gettimeofday(&t_first, NULL);
	packets++;
	gettimeofday(&t_last, NULL);

	/* Verdict immediately. No inspection -- this is the floor. */
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	int queue_num = (argc > 1) ? atoi(argv[1]) : 0;

	struct nfq_handle *h = nfq_open();
	if (!h) {
		fprintf(stderr, "nfq_open failed (need root?)\n");
		return 1;
	}
	nfq_unbind_pf(h, AF_INET);
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "nfq_bind_pf failed\n");
		return 1;
	}
	struct nfq_q_handle *qh = nfq_create_queue(h, (uint16_t)queue_num, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "nfq_create_queue(%d) failed\n", queue_num);
		return 1;
	}
	/* Copy only what a real classifier would need to see a ClientHello. */
	nfq_set_mode(qh, NFQNL_COPY_PACKET, 0x600);
	nfq_set_queue_maxlen(qh, 8192);

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_sig;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	fprintf(stderr, "nfq_accept: bound to queue %d, verdict=ACCEPT, no inspection\n",
	        queue_num);

	int fd = nfq_fd(h);
	char buf[65536] __attribute__((aligned));
	while (running) {
		int rv = (int)recv(fd, buf, sizeof(buf), 0);
		if (rv >= 0) {
			nfq_handle_packet(h, buf, rv);
		} else if (rv < 0) {
			break;
		}
	}

	double secs = (double)(t_last.tv_sec - t_first.tv_sec) +
	              (double)(t_last.tv_usec - t_first.tv_usec) / 1e6;
	fprintf(stderr, "nfq_accept: %lu packets in %.3fs", packets, secs);
	if (secs > 0.001 && packets > 1)
		fprintf(stderr, " = %.0f pkt/s, %.1f us/packet",
		        (double)packets / secs, secs * 1e6 / (double)packets);
	fprintf(stderr, "\n");

	nfq_destroy_queue(qh);
	nfq_close(h);
	return 0;
}
