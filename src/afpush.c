/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 */

#include "afpush.h"

#include <errno.h>
#include <linux/netlink.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Mirrors struct af_msg_hdr in the module. Packed, little-endian native --
 * both ends are the same machine. */
struct afpush_hdr {
	uint16_t type;
	uint16_t count;
	uint32_t len;
} __attribute__((packed));

struct afpush_rule_wire {
	uint64_t name_hash;
	uint8_t mac[AFPUSH_MAC_LEN];
	uint8_t per_subject;
	uint8_t _pad;
} __attribute__((packed));

struct afpush_subject_wire {
	uint8_t mac[AFPUSH_MAC_LEN];
	uint8_t _pad[2];
} __attribute__((packed));

struct afpush_hello_wire {
	uint32_t version;
	uint32_t _pad;
} __attribute__((packed));

uint64_t afpush_hash_name(const char *name, size_t len)
{
	/* Constants fixed and duplicated in the module. Any drift here stops
	 * every rule matching, silently. */
	uint64_t h = 1469598103934665603ULL;
	size_t i;

	if (!name)
		return 0;
	for (i = 0; i < len && name[i]; i++) {
		unsigned char c = (unsigned char)name[i];
		if (c >= 'A' && c <= 'Z')
			c = (unsigned char)(c - 'A' + 'a');
		h ^= c;
		h *= 1099511628211ULL;
	}
	return h;
}

static size_t put_hdr(uint8_t *buf, size_t cap, uint16_t type, uint16_t count,
                      uint32_t len)
{
	struct afpush_hdr h;

	if (cap < sizeof(h) + len)
		return 0;
	h.type = type;
	h.count = count;
	h.len = len;
	memcpy(buf, &h, sizeof(h));
	return sizeof(h);
}

size_t afpush_build_hello(uint8_t *buf, size_t cap)
{
	struct afpush_hello_wire hi;
	size_t n;

	if (!buf)
		return 0;
	n = put_hdr(buf, cap, AFPUSH_HELLO, 1, sizeof(hi));
	if (n == 0)
		return 0;
	memset(&hi, 0, sizeof(hi));
	hi.version = AFPUSH_PROTO_VERSION;
	memcpy(buf + n, &hi, sizeof(hi));
	return n + sizeof(hi);
}

size_t afpush_build_simple(uint8_t *buf, size_t cap, enum afpush_msg type)
{
	if (!buf)
		return 0;
	return put_hdr(buf, cap, (uint16_t)type, 0, 0);
}

size_t afpush_build_rules(uint8_t *buf, size_t cap, const uint64_t *hashes,
                          const uint8_t (*macs)[AFPUSH_MAC_LEN],
                          const bool *per_subject, size_t n,
                          size_t *n_written)
{
	size_t hdr_len = sizeof(struct afpush_hdr);
	size_t fit, i, off;

	if (n_written)
		*n_written = 0;
	if (!buf || !hashes || n == 0)
		return 0;
	if (cap <= hdr_len)
		return 0;

	/* Fill what fits and report how many. A caller that ignores n_written
	 * and assumes the whole batch went would push a partial rule set and
	 * commit it -- enforcing less than the controller believes. */
	fit = (cap - hdr_len) / sizeof(struct afpush_rule_wire);
	if (fit > n)
		fit = n;
	if (fit == 0)
		return 0;
	if (fit > 0xFFFF)
		fit = 0xFFFF; /* count is 16-bit on the wire */

	off = put_hdr(buf, cap, AFPUSH_RULE_ADD, (uint16_t)fit,
	              (uint32_t)(fit * sizeof(struct afpush_rule_wire)));
	if (off == 0)
		return 0;

	for (i = 0; i < fit; i++) {
		struct afpush_rule_wire r;

		memset(&r, 0, sizeof(r));
		r.name_hash = hashes[i];
		r.per_subject = (per_subject && per_subject[i]) ? 1 : 0;
		if (r.per_subject && macs)
			memcpy(r.mac, macs[i], AFPUSH_MAC_LEN);
		memcpy(buf + off, &r, sizeof(r));
		off += sizeof(r);
	}

	if (n_written)
		*n_written = fit;
	return off;
}

size_t afpush_build_subjects(uint8_t *buf, size_t cap,
                             const uint8_t (*macs)[AFPUSH_MAC_LEN], size_t n,
                             size_t *n_written)
{
	size_t hdr_len = sizeof(struct afpush_hdr);
	size_t fit, i, off;

	if (n_written)
		*n_written = 0;
	if (!buf || !macs || n == 0 || cap <= hdr_len)
		return 0;

	fit = (cap - hdr_len) / sizeof(struct afpush_subject_wire);
	if (fit > n)
		fit = n;
	if (fit == 0)
		return 0;

	off = put_hdr(buf, cap, AFPUSH_SUBJECT_ADD, (uint16_t)fit,
	              (uint32_t)(fit * sizeof(struct afpush_subject_wire)));
	if (off == 0)
		return 0;

	for (i = 0; i < fit; i++) {
		struct afpush_subject_wire s;

		memset(&s, 0, sizeof(s));
		memcpy(s.mac, macs[i], AFPUSH_MAC_LEN);
		memcpy(buf + off, &s, sizeof(s));
		off += sizeof(s);
	}

	if (n_written)
		*n_written = fit;
	return off;
}

long afpush_compile(const struct pol_db *pol, const struct sig_db *sigs,
                    uint64_t *out, size_t out_cap, size_t *n_collisions)
{
	size_t n = 0;
	size_t i, j;

	if (n_collisions)
		*n_collisions = 0;
	if (!pol || !sigs || !out || out_cap == 0)
		return -1;

	for (i = 0; i < pol->n_rules; i++) {
		const struct pol_rule *pr = &pol->rules[i];
		const struct sig_app *app;
		size_t app_idx;

		/* Only BLOCK rules produce kernel state. An ALLOW rule is the
		 * absence of a hash, not the presence of one -- the module has
		 * no concept of "allow" and must not be taught one. */
		if (pr->action != POL_BLOCK)
			continue;
		if (pr->target != POL_TARGET_APP)
			continue; /* category rules are resolved before this */

		app = sig_db_by_tag(sigs, pr->tag);
		if (!app)
			continue; /* refused at authoring time; see pol_add_rule */
		app_idx = (size_t)(app - sigs->apps);

		for (j = 0; j < sigs->n_rules; j++) {
			uint64_t h;
			size_t k;
			bool dup = false;

			if (sigs->rules[j].app_index != app_idx)
				continue;
			if (sigs->rules[j].host[0] == '\0')
				continue; /* port-only rule: no name to hash */

			h = afpush_hash_name(sigs->rules[j].host,
			                     strlen(sigs->rules[j].host));
			for (k = 0; k < n; k++) {
				if (out[k] == h) {
					dup = true;
					break;
				}
			}
			if (dup) {
				if (n_collisions)
					(*n_collisions)++;
				continue;
			}
			if (n >= out_cap)
				return (long)n; /* caller sees a short result */
			out[n++] = h;
		}
	}
	return (long)n;
}

bool afpush_open(struct afpush_conn *c)
{
	struct sockaddr_nl sa;

	if (!c)
		return false;
	memset(c, 0, sizeof(*c));
	c->fd = socket(AF_NETLINK, SOCK_RAW, AFPUSH_NETLINK_UNIT);
	if (c->fd < 0)
		return false;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_pid = 0; /* let the kernel assign */
	if (bind(c->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		close(c->fd);
		c->fd = -1;
		return false;
	}
	return true;
}

void afpush_close(struct afpush_conn *c)
{
	if (c && c->fd >= 0) {
		close(c->fd);
		c->fd = -1;
	}
}

bool afpush_send(struct afpush_conn *c, const uint8_t *msg, size_t len)
{
	struct sockaddr_nl dst;
	struct nlmsghdr *nlh;
	struct iovec iov;
	struct msghdr mh;
	uint8_t buf[AFPUSH_MAX_MSG + NLMSG_HDRLEN];
	ssize_t sent;

	if (!c || c->fd < 0 || !msg || len == 0)
		return false;
	if (len + NLMSG_HDRLEN > sizeof(buf))
		return false;

	memset(buf, 0, NLMSG_HDRLEN);
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (uint32_t)NLMSG_LENGTH(len);
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_seq = 0;
	nlh->nlmsg_pid = 0;
	memcpy(NLMSG_DATA(nlh), msg, len);

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	dst.nl_pid = 0; /* kernel */

	iov.iov_base = buf;
	iov.iov_len = nlh->nlmsg_len;
	memset(&mh, 0, sizeof(mh));
	mh.msg_name = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	do {
		sent = sendmsg(c->fd, &mh, 0);
	} while (sent < 0 && errno == EINTR);

	return sent > 0;
}
