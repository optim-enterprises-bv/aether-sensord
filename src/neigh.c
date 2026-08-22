/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 */

#include "neigh.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <sys/socket.h>

struct neigh_entry {
	struct obs_addr ip;
	uint8_t mac[NEIGH_MAC_LEN];
	bool used;
};

struct neigh_table {
	struct neigh_entry *e;
	size_t cap;
	size_t used;
	struct neigh_stats st;
};

/* ---- validity ----------------------------------------------------------- */

bool neigh_mac_usable(const uint8_t mac[NEIGH_MAC_LEN])
{
	int i, zero = 1, ones = 1;

	if (!mac)
		return false;
	for (i = 0; i < NEIGH_MAC_LEN; i++) {
		if (mac[i] != 0x00)
			zero = 0;
		if (mac[i] != 0xff)
			ones = 0;
	}
	if (zero)
		return false; /* incomplete entry rendered as 00:00:00:00:00:00 */
	if (ones)
		return false; /* broadcast is not a device */
	if (mac[0] & 0x01)
		return false; /* multicast bit: a group, not a subject */
	return true;
}

/* ---- /proc/net/arp ------------------------------------------------------ */

bool neigh_parse_arp_line(const char *line, struct obs_addr *ip,
                          uint8_t mac[NEIGH_MAC_LEN])
{
	char ipbuf[64], macbuf[32], dev[32];
	unsigned hwtype = 0, flags = 0;
	unsigned m[NEIGH_MAC_LEN];
	int i;

	if (!line || !ip || !mac)
		return false;
	/* The header line begins with "IP address" and will not scan. */
	if (sscanf(line, "%63s 0x%x 0x%x %31s %*s %31s", ipbuf, &hwtype, &flags,
	           macbuf, dev) != 5)
		return false;

	/*
	 * ATF_COM (0x02) means the entry is complete. Anything else is a
	 * pending or stale lookup, and acting on it would attribute a flow to
	 * whatever used to hold that address.
	 */
	if (!(flags & 0x02))
		return false;

	if (sscanf(macbuf, "%2x:%2x:%2x:%2x:%2x:%2x", &m[0], &m[1], &m[2],
	           &m[3], &m[4], &m[5]) != 6)
		return false;
	for (i = 0; i < NEIGH_MAC_LEN; i++) {
		if (m[i] > 0xff)
			return false;
		mac[i] = (uint8_t)m[i];
	}
	if (!neigh_mac_usable(mac))
		return false;
	if (!obs_addr_parse(ip, ipbuf))
		return false;
	return true;
}

static void table_put(struct neigh_table *t, const struct obs_addr *ip,
                      const uint8_t mac[NEIGH_MAC_LEN])
{
	size_t i;

	for (i = 0; i < t->cap; i++) {
		if (t->e[i].used && obs_addr_eq(&t->e[i].ip, ip)) {
			memcpy(t->e[i].mac, mac, NEIGH_MAC_LEN);
			return;
		}
	}
	if (t->used >= t->cap)
		return; /* bounded; a full table simply stops learning */
	for (i = 0; i < t->cap; i++) {
		if (!t->e[i].used) {
			t->e[i].used = true;
			t->e[i].ip = *ip;
			memcpy(t->e[i].mac, mac, NEIGH_MAC_LEN);
			t->used++;
			return;
		}
	}
}

static long load_arp(struct neigh_table *t)
{
	FILE *fp = fopen("/proc/net/arp", "r");
	char line[512];
	long n = 0;

	if (!fp)
		return -1;
	while (fgets(line, sizeof(line), fp)) {
		struct obs_addr ip;
		uint8_t mac[NEIGH_MAC_LEN];

		if (!neigh_parse_arp_line(line, &ip, mac))
			continue;
		table_put(t, &ip, mac);
		n++;
	}
	fclose(fp);
	return n;
}

/* ---- IPv6 via RTM_GETNEIGH ---------------------------------------------- */

/*
 * There is no /proc/net equivalent for IPv6 neighbours, so this dumps them
 * over netlink directly rather than linking libnl for one call.
 */
static long load_neigh6(struct neigh_table *t)
{
	int fd;
	struct sockaddr_nl sa;
	struct {
		struct nlmsghdr nh;
		struct ndmsg nd;
	} req;
	uint8_t buf[16384];
	long n = 0;
	bool done = false;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0)
		return -1;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		close(fd);
		return -1;
	}

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.nh.nlmsg_type = RTM_GETNEIGH;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nh.nlmsg_seq = 1;
	req.nd.ndm_family = AF_INET6;

	if (send(fd, &req, req.nh.nlmsg_len, 0) < 0) {
		close(fd);
		return -1;
	}

	while (!done) {
		ssize_t len = recv(fd, buf, sizeof(buf), 0);
		struct nlmsghdr *nh;

		if (len <= 0)
			break;
		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (unsigned)len);
		     nh = NLMSG_NEXT(nh, len)) {
			struct ndmsg *nd;
			struct rtattr *rta;
			int rlen;
			struct obs_addr ip;
			uint8_t mac[NEIGH_MAC_LEN];
			bool have_ip = false, have_mac = false;

			if (nh->nlmsg_type == NLMSG_DONE) {
				done = true;
				break;
			}
			if (nh->nlmsg_type == NLMSG_ERROR) {
				done = true;
				break;
			}
			if (nh->nlmsg_type != RTM_NEWNEIGH)
				continue;

			nd = NLMSG_DATA(nh);
			if (nd->ndm_family != AF_INET6)
				continue;
			/*
			 * Only states where the kernel believes the mapping is
			 * usable. STALE and INCOMPLETE are cached guesses.
			 */
			if (!(nd->ndm_state &
			      (NUD_REACHABLE | NUD_PERMANENT | NUD_DELAY |
			       NUD_PROBE)))
				continue;

			rta = (struct rtattr *)((char *)nd + NLMSG_ALIGN(sizeof(*nd)));
			rlen = (int)(nh->nlmsg_len - NLMSG_LENGTH(sizeof(*nd)));
			for (; RTA_OK(rta, rlen); rta = RTA_NEXT(rta, rlen)) {
				if (rta->rta_type == NDA_DST &&
				    RTA_PAYLOAD(rta) == 16) {
					if (obs_addr_from_v6(&ip, RTA_DATA(rta)))
						have_ip = true;
				} else if (rta->rta_type == NDA_LLADDR &&
				           RTA_PAYLOAD(rta) == NEIGH_MAC_LEN) {
					memcpy(mac, RTA_DATA(rta), NEIGH_MAC_LEN);
					have_mac = neigh_mac_usable(mac);
				}
			}
			if (have_ip && have_mac) {
				table_put(t, &ip, mac);
				n++;
			}
		}
	}
	close(fd);
	return n;
}

/* ---- lifecycle ---------------------------------------------------------- */

struct neigh_table *neigh_new(size_t max)
{
	struct neigh_table *t;

	if (max == 0 || max > (1u << 16))
		return NULL;
	t = calloc(1, sizeof(*t));
	if (!t)
		return NULL;
	t->e = calloc(max, sizeof(*t->e));
	if (!t->e) {
		free(t);
		return NULL;
	}
	t->cap = max;
	return t;
}

void neigh_free(struct neigh_table *t)
{
	if (!t)
		return;
	free(t->e);
	free(t);
}

long neigh_refresh(struct neigh_table *t)
{
	long a, b, total = 0;
	bool any = false;

	if (!t)
		return -1;
	/* Rebuild rather than accumulate: a device that changed address must
	 * not keep resolving through a stale entry. */
	memset(t->e, 0, t->cap * sizeof(*t->e));
	t->used = 0;

	a = load_arp(t);
	if (a >= 0) {
		total += a;
		any = true;
	}
	b = load_neigh6(t);
	if (b >= 0) {
		total += b;
		any = true;
	}

	if (!any) {
		t->st.refresh_failed++;
		return -1;
	}
	t->st.refresh_ok++;
	return total;
}

bool neigh_lookup(struct neigh_table *t, const struct obs_addr *ip,
                  uint8_t out[NEIGH_MAC_LEN])
{
	size_t i;

	if (!t || !ip || !out)
		return false;
	t->st.lookups++;

	/*
	 * A public address is a peer by definition. Looking it up would at
	 * best find the router's own MAC and attribute every flow on the
	 * network to one "device".
	 */
	if (!obs_addr_is_private(ip)) {
		t->st.miss_not_private++;
		return false;
	}

	for (i = 0; i < t->cap; i++) {
		if (!t->e[i].used)
			continue;
		if (!obs_addr_eq(&t->e[i].ip, ip))
			continue;
		memcpy(out, t->e[i].mac, NEIGH_MAC_LEN);
		t->st.hits++;
		return true;
	}
	t->st.miss_not_found++;
	return false;
}

void neigh_get_stats(const struct neigh_table *t, struct neigh_stats *out)
{
	if (!t || !out)
		return;
	*out = t->st;
}
