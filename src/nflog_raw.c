/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 */

#include "nflog_raw.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netlink.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* NFULNL config commands are a nfgenmsg followed by attributes. */
struct nfr_nfgenmsg {
	uint8_t nfgen_family;
	uint8_t version;
	uint16_t res_id; /* group, big-endian */
};

/*
 * Read the ACK the kernel owes us for an NLM_F_ACK request.
 *
 * Returns true only on an explicit success ACK (NLMSG_ERROR with error == 0).
 * A negative error, a malformed reply, or no reply at all is a failure: the
 * whole point is to refuse to claim success we have not been told about.
 *
 * The wait is bounded. A blocking recv here would hang the daemon at startup
 * on a kernel that never answers, which is a worse failure than not sensing.
 */
bool nfr_parse_ack(const uint8_t *buf, size_t len)
{
	const struct nlmsghdr *nlh;
	const struct nlmsgerr *err;

	if (!buf || len < NLMSG_HDRLEN)
		return false;
	nlh = (const struct nlmsghdr *)buf;
	if (!NLMSG_OK(nlh, (unsigned)len))
		return false;
	if (nlh->nlmsg_type != NLMSG_ERROR)
		return false; /* unexpected: do not read it as consent */
	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*err)))
		return false;

	err = (const struct nlmsgerr *)NLMSG_DATA(nlh);
	if (err->error != 0) {
		errno = -err->error;
		return false;
	}
	return true;
}

static bool nfr_read_ack(int fd)
{
	uint8_t buf[512];
	struct pollfd pfd;
	ssize_t n;
	int rc;

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	do {
		rc = poll(&pfd, 1, 1000);
	} while (rc < 0 && errno == EINTR);
	if (rc <= 0) {
		errno = (rc == 0) ? ETIMEDOUT : errno;
		return false;
	}

	do {
		n = recv(fd, buf, sizeof(buf), 0);
	} while (n < 0 && errno == EINTR);
	if (n < 0)
		return false;
	if ((size_t)n < NLMSG_HDRLEN)
		return false;

	return nfr_parse_ack(buf, (size_t)n);
}

static bool nfr_send_config(int fd, uint16_t group, uint8_t family,
                            uint8_t command, const void *extra,
                            size_t extra_len, uint16_t extra_type)
{
	uint8_t buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct nfr_nfgenmsg *nfg;
	struct nlattr *attr;
	size_t off;
	struct sockaddr_nl dst;
	ssize_t n;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = (uint16_t)((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG);
	/* ACK is requested so the caller can tell "the kernel accepted this"
	 * from "the write returned a positive number". Without it, an
	 * unprivileged bind succeeds at sendto() and fails in the kernel, and
	 * the sensor reports itself live while receiving nothing. */
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = 1;
	nlh->nlmsg_pid = 0;

	nfg = (struct nfr_nfgenmsg *)NLMSG_DATA(nlh);
	nfg->nfgen_family = family;
	nfg->version = NFNETLINK_V0;
	/* res_id carries the group and is big-endian on the wire. */
	nfg->res_id = (uint16_t)((group >> 8) | (group << 8));

	off = NLMSG_LENGTH(sizeof(*nfg));

	if (extra && extra_len) {
		size_t alen = NLA_HDRLEN + extra_len;

		if (off + NLA_ALIGN(alen) > sizeof(buf))
			return false;
		attr = (struct nlattr *)(buf + off);
		attr->nla_len = (uint16_t)alen;
		attr->nla_type = extra_type;
		memcpy((uint8_t *)attr + NLA_HDRLEN, extra, extra_len);
		off += NLA_ALIGN(alen);
	}
	(void)command;

	nlh->nlmsg_len = (uint32_t)off;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;

	do {
		n = sendto(fd, buf, off, 0, (struct sockaddr *)&dst, sizeof(dst));
	} while (n < 0 && errno == EINTR);
	if (n <= 0)
		return false;

	return nfr_read_ack(fd);
}

bool nfr_open(struct nfr_conn *c, uint16_t group, uint16_t copy_range)
{
	struct sockaddr_nl sa;
	struct nfulnl_msg_config_cmd cmd;
	struct nfulnl_msg_config_mode mode;

	if (!c)
		return false;
	memset(c, 0, sizeof(*c));
	c->group = group;

	c->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (c->fd < 0)
		return false;

	/*
	 * Ask for a large receive buffer BEFORE binding.
	 *
	 * Classification copies whole packets, so the default netlink buffer
	 * overflows within seconds of real forwarded traffic and the socket
	 * starts reporting errors. Losing packets is acceptable -- dissection
	 * only needs the first few of a flow -- but the overflow must not look
	 * like a broken socket.
	 */
	{
		int rcv = 8 * 1024 * 1024;

		if (setsockopt(c->fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcv,
		               sizeof(rcv)) != 0)
			(void)setsockopt(c->fd, SOL_SOCKET, SO_RCVBUF, &rcv,
			                 sizeof(rcv));
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(c->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		close(c->fd);
		c->fd = -1;
		return false;
	}

	/* PF_BIND for both families. A v6-only or v4-only deployment simply
	 * sees no traffic on the unused one.
	 *
	 * Deliberately advisory: PF_BIND is a no-op on current kernels, so a
	 * failure here is not evidence that logging will not work. The group
	 * BIND below is the one that decides, and that one is checked. */
	memset(&cmd, 0, sizeof(cmd));
	cmd.command = NFULNL_CFG_CMD_PF_BIND;
	nfr_send_config(c->fd, 0, AF_INET, 0, &cmd, sizeof(cmd), NFULA_CFG_CMD);
	nfr_send_config(c->fd, 0, AF_INET6, 0, &cmd, sizeof(cmd), NFULA_CFG_CMD);

	/* Bind the group. */
	memset(&cmd, 0, sizeof(cmd));
	cmd.command = NFULNL_CFG_CMD_BIND;
	if (!nfr_send_config(c->fd, group, AF_UNSPEC, 0, &cmd, sizeof(cmd),
	                     NFULA_CFG_CMD)) {
		close(c->fd);
		c->fd = -1;
		return false;
	}

	/*
	 * Copy mode. Asking for only the headers is what keeps packet CONTENTS
	 * out of this process: we read addresses and ports, never payload.
	 */
	memset(&mode, 0, sizeof(mode));
	mode.copy_mode = NFULNL_COPY_PACKET;
	/* Big-endian on the wire. htonl rather than a hand-rolled swap: the
	 * open-coded version happened to be right for 16-bit values on a
	 * little-endian host and wrong on big-endian, and OpenWrt still ships
	 * big-endian MIPS targets. */
	mode.copy_range = htonl((uint32_t)copy_range);
	c->copy_range = copy_range;
	/*
	 * CHECK THIS ACK. The group bind was checked and the copy mode was not,
	 * which is the difference between "we get whole packets" and "we get
	 * whatever the kernel felt like sending".
	 *
	 * A rejected mode leaves the default copy length in force. That is
	 * enough bytes to recognise TLS from its first handshake byte and NOT
	 * enough to reach the SNI inside the ClientHello -- so every flow
	 * classifies and none of them yields a hostname, which is exactly what
	 * the BPI-R4 showed: 8 named out of 37, against 48% on the same code
	 * replaying full packets from a pcap.
	 *
	 * Failing the open() is deliberate. A dissector fed truncated packets
	 * does not degrade gracefully; it reports protocols it cannot act on.
	 */
	if (!nfr_send_config(c->fd, group, AF_UNSPEC, 0, &mode, sizeof(mode),
	                     NFULA_CFG_MODE)) {
		close(c->fd);
		c->fd = -1;
		return false;
	}

	return true;
}

void nfr_close(struct nfr_conn *c)
{
	if (c && c->fd >= 0) {
		close(c->fd);
		c->fd = -1;
	}
}

long nfr_parse_buffer(struct nfr_conn *c, const uint8_t *buf, size_t len,
                      nfr_packet_fn cb, void *user)
{
	const struct nlmsghdr *nlh;
	size_t remaining = len;
	long dispatched = 0;

	if (!c || !buf || !cb)
		return 0;

	nlh = (const struct nlmsghdr *)buf;
	/* NLMSG_OK bounds every step against `remaining`; nothing below
	 * dereferences without it. */
	while (remaining >= sizeof(*nlh) && NLMSG_OK(nlh, remaining)) {
		uint16_t subsys = (uint16_t)(nlh->nlmsg_type >> 8);
		uint16_t mtype = (uint16_t)(nlh->nlmsg_type & 0xff);

		if (nlh->nlmsg_type == NLMSG_ERROR ||
		    nlh->nlmsg_type == NLMSG_DONE)
			break;

		if (subsys == NFNL_SUBSYS_ULOG && mtype == NFULNL_MSG_PACKET) {
			const uint8_t *p = (const uint8_t *)NLMSG_DATA(nlh);
			size_t plen = NLMSG_PAYLOAD(nlh, 0);
			const uint8_t *payload = NULL;
			uint32_t payload_len = 0;

			/* Skip the nfgenmsg that precedes the attributes. */
			if (plen < sizeof(struct nfr_nfgenmsg)) {
				c->malformed++;
				goto next;
			}
			p += sizeof(struct nfr_nfgenmsg);
			plen -= sizeof(struct nfr_nfgenmsg);

			/* Walk attributes. Every advance is bounded by plen. */
			while (plen >= NLA_HDRLEN) {
				const struct nlattr *a = (const struct nlattr *)p;
				uint16_t alen = a->nla_len;
				uint16_t atype = (uint16_t)(a->nla_type & NLA_TYPE_MASK);

				if (alen < NLA_HDRLEN || alen > plen) {
					c->malformed++;
					break;
				}
				if (atype == NFULA_PAYLOAD) {
					payload = p + NLA_HDRLEN;
					payload_len = (uint32_t)(alen - NLA_HDRLEN);
				}
				/* NLA_ALIGN yields a signed int on this libc; compare
				 * as size_t so a large aligned length cannot wrap
				 * the bound check and let the walk run on. */
				{
					size_t step = (size_t)NLA_ALIGN(alen);
					if (step > plen)
						break;
					p += step;
					plen -= step;
				}
			}

			if (payload && payload_len) {
				cb(payload, payload_len, user);
				dispatched++;
			}
		}
next:
		nlh = NLMSG_NEXT(nlh, remaining);
	}

	return dispatched;
}

long nfr_dispatch(struct nfr_conn *c, nfr_packet_fn cb, void *user)
{
	static uint8_t buf[NFR_RECV_BUF];
	ssize_t n;

	if (!c || c->fd < 0 || !cb)
		return -1;

	do {
		n = recv(c->fd, buf, sizeof(buf), 0);
	} while (n < 0 && errno == EINTR);

	if (n < 0) {
		if (errno == ENOBUFS) {
			/* The kernel queue overran and we lost records. Not
			 * fatal, but it must be visible: a sensor that hides
			 * its own data loss reports a quiet network during
			 * exactly the event that matters. */
			c->overruns++;
			return 0;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		c->recv_errors++;
		return -1;
	}
	if (n == 0)
		return 0;

	return nfr_parse_buffer(c, buf, (size_t)n, cb, user);
}
