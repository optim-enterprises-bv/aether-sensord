/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Attributing a flow to a device.
 *
 * Policy is per-subject and subjects are MAC addresses, but a packet carries
 * IP addresses. Something has to bridge the two, and getting it wrong is not a
 * cosmetic error: attributing a flow to the wrong device applies one household
 * member's rules to another's traffic. A parent's phone inherits a child's
 * bedtime, or worse, the child's does not.
 *
 * So this refuses far more readily than it guesses:
 *
 *   - only addresses on the LAN side are looked up at all; a public address is
 *     a peer, never a subject
 *   - only neighbour entries the kernel considers usable are accepted. A stale
 *     or incomplete entry is a cached guess, and this is not the place to bet
 *     on one
 *   - a MAC of all zeroes, or a multicast/broadcast MAC, is refused
 *
 * IPv4 comes from /proc/net/arp, which is a stable, documented text interface.
 * IPv6 has no /proc equivalent and needs an RTM_GETNEIGH netlink dump; that is
 * implemented here too, over a plain socket, because the alternative is
 * linking libnl (LGPL, and a dependency this package does not otherwise need).
 */

#ifndef AETHER_SENSORD_NEIGH_H
#define AETHER_SENSORD_NEIGH_H

#include "observe.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NEIGH_MAC_LEN 6

struct neigh_stats {
	uint64_t lookups;
	uint64_t hits;
	uint64_t miss_not_found;   /* no neighbour entry at all */
	uint64_t miss_incomplete;  /* entry exists but is not usable */
	uint64_t miss_not_private; /* asked about a public address */
	uint64_t refresh_ok;
	uint64_t refresh_failed;
};

struct neigh_table;

/* `max` bounds the cache. Zero or an absurd value is refused. */
struct neigh_table *neigh_new(size_t max);
void neigh_free(struct neigh_table *t);

/*
 * Reload from the kernel. Returns entries loaded, or -1 if nothing could be
 * read at all -- which is distinct from "the table is legitimately empty".
 */
long neigh_refresh(struct neigh_table *t);

/*
 * Resolve an address to a MAC.
 *
 * Returns false unless the address is private AND has a usable neighbour
 * entry. `out` is untouched on failure, so a caller that ignores the return
 * value cannot silently enforce against zeroes.
 */
bool neigh_lookup(struct neigh_table *t, const struct obs_addr *ip,
                  uint8_t out[NEIGH_MAC_LEN]);

void neigh_get_stats(const struct neigh_table *t, struct neigh_stats *out);

/*
 * Parse one /proc/net/arp line. Exposed for testing: byte-offset parsing of a
 * kernel text interface is exactly the code that should not be trusted to a
 * single integration test.
 *
 * Returns false for the header line, malformed lines, and entries whose flags
 * say the entry is not complete.
 */
bool neigh_parse_arp_line(const char *line, struct obs_addr *ip,
                          uint8_t mac[NEIGH_MAC_LEN]);

/* True if `mac` is a plausible unicast device address. */
bool neigh_mac_usable(const uint8_t mac[NEIGH_MAC_LEN]);

#endif /* AETHER_SENSORD_NEIGH_H */
