/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Tests for device attribution.
 *
 * Getting attribution wrong applies one household member's rules to another's
 * traffic. That is worse than not enforcing at all, so nearly every test here
 * asserts a REFUSAL.
 */

#include "../src/neigh.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;
#define CHECK(cond, msg)                                                       \
	do {                                                                   \
		checks++;                                                      \
		if (!(cond)) {                                                 \
			failures++;                                            \
			printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);  \
		}                                                              \
	} while (0)

static void test_mac_validity(void)
{
	uint8_t ok[6]   = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	uint8_t zero[6] = { 0, 0, 0, 0, 0, 0 };
	uint8_t bcast[6]= { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	uint8_t mcast[6]= { 0x01, 0x00, 0x5e, 0x01, 0x02, 0x03 };

	CHECK(neigh_mac_usable(ok), "a normal unicast MAC is usable");
	CHECK(!neigh_mac_usable(zero),
	      "all-zero is an incomplete entry, not a device");
	CHECK(!neigh_mac_usable(bcast), "broadcast is not a device");
	CHECK(!neigh_mac_usable(mcast),
	      "a multicast MAC is a group, never a subject");
	CHECK(!neigh_mac_usable(NULL), "NULL is refused");
}

static void test_arp_line_parsing(void)
{
	struct obs_addr ip;
	uint8_t mac[6];
	uint8_t expect[6] = { 0xea, 0x5e, 0xca, 0xcf, 0x3f, 0x18 };

	/* The header must not parse as an entry. */
	CHECK(!neigh_parse_arp_line(
	              "IP address       HW type     Flags       HW address"
	              "            Mask     Device\n", &ip, mac),
	      "the /proc/net/arp header is not an entry");

	/* A complete entry: flags 0x2 = ATF_COM. */
	CHECK(neigh_parse_arp_line(
	              "192.168.1.1      0x1         0x2         "
	              "ea:5e:ca:cf:3f:18     *        enp0s31f6\n", &ip, mac),
	      "a complete entry parses");
	CHECK(memcmp(mac, expect, 6) == 0, "MAC extracted correctly");
	{
		char buf[64] = "";

		obs_addr_str(&ip, buf, sizeof(buf));
		CHECK(strcmp(buf, "192.168.1.1") == 0, "address extracted");
	}

	/*
	 * Flags 0x0 means the lookup is incomplete. Acting on it would
	 * attribute the flow to whatever previously held that address.
	 */
	CHECK(!neigh_parse_arp_line(
	              "192.168.1.7      0x1         0x0         "
	              "00:00:00:00:00:00     *        br-lan\n", &ip, mac),
	      "an incomplete entry is refused, not cached as zeroes");

	/* Complete flag but a zero MAC is still not a device. */
	CHECK(!neigh_parse_arp_line(
	              "192.168.1.8      0x1         0x2         "
	              "00:00:00:00:00:00     *        br-lan\n", &ip, mac),
	      "a zero MAC is refused even when flagged complete");

	/* Multicast MAC. */
	CHECK(!neigh_parse_arp_line(
	              "192.168.1.9      0x1         0x2         "
	              "01:00:5e:00:00:01     *        br-lan\n", &ip, mac),
	      "a multicast MAC is refused");

	/* Malformed lines. */
	CHECK(!neigh_parse_arp_line("", &ip, mac), "empty line");
	CHECK(!neigh_parse_arp_line("garbage\n", &ip, mac), "garbage line");
	CHECK(!neigh_parse_arp_line("192.168.1.1 0x1\n", &ip, mac),
	      "a truncated line is refused");
	CHECK(!neigh_parse_arp_line(NULL, &ip, mac), "NULL line");
	CHECK(!neigh_parse_arp_line("x", NULL, mac), "NULL ip out");
	CHECK(!neigh_parse_arp_line("x", &ip, NULL), "NULL mac out");

	/* A bad MAC field. */
	CHECK(!neigh_parse_arp_line(
	              "192.168.1.5      0x1         0x2         "
	              "not-a-mac             *        br-lan\n", &ip, mac),
	      "an unparseable MAC is refused");
}

static void test_bounds(void)
{
	CHECK(neigh_new(0) == NULL, "a zero-sized table is refused");
	CHECK(neigh_new((size_t)1 << 24) == NULL, "an absurd table is refused");
	{
		struct neigh_table *t = neigh_new(4);

		CHECK(t != NULL, "a sane table is created");
		neigh_free(t);
		neigh_free(NULL); /* must not crash */
	}
}

/* A public address must never resolve to a subject. */
static void test_public_addresses_never_resolve(void)
{
	struct neigh_table *t = neigh_new(64);
	struct obs_addr a;
	uint8_t mac[6];
	struct neigh_stats st;

	if (!t)
		return;
	neigh_refresh(t); /* whatever this host has */

	CHECK(obs_addr_parse(&a, "93.184.216.34"), "parsed a public address");
	CHECK(!neigh_lookup(t, &a, mac),
	      "a public address is a peer and never resolves to a subject");

	CHECK(obs_addr_parse(&a, "2606:4700::1111"), "parsed a public v6");
	CHECK(!neigh_lookup(t, &a, mac), "public v6 likewise refused");

	neigh_get_stats(t, &st);
	CHECK(st.miss_not_private >= 2,
	      "public lookups are counted in their own bucket, not as misses");

	neigh_free(t);
}

static void test_lookup_guards(void)
{
	struct neigh_table *t = neigh_new(8);
	struct obs_addr a;
	uint8_t mac[6];

	if (!t)
		return;
	memset(mac, 0xAB, sizeof(mac));
	obs_addr_parse(&a, "192.168.222.222"); /* private, but not present */
	CHECK(!neigh_lookup(t, &a, mac), "an absent private address misses");
	CHECK(mac[0] == 0xAB,
	      "the output is untouched on failure, so a caller that ignores "
	      "the return value cannot enforce against garbage");

	CHECK(!neigh_lookup(NULL, &a, mac), "NULL table");
	CHECK(!neigh_lookup(t, NULL, mac), "NULL address");
	CHECK(!neigh_lookup(t, &a, NULL), "NULL output");
	neigh_free(t);
}

/* Refresh must REPLACE, not accumulate: a device that changes address must not
 * keep resolving through a stale entry. */
static void test_refresh_replaces(void)
{
	struct neigh_table *t = neigh_new(64);
	long a, b;

	if (!t)
		return;
	a = neigh_refresh(t);
	b = neigh_refresh(t);
	CHECK(a == b,
	      "refreshing twice yields the same count, so entries are replaced "
	      "rather than accumulated");
	CHECK(neigh_refresh(NULL) == -1, "NULL table refresh is an error");
	neigh_free(t);
}

int main(void)
{
	test_mac_validity();
	test_arp_line_parsing();
	test_bounds();
	test_public_addresses_never_resolve();
	test_lookup_guards();
	test_refresh_replaces();
	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
