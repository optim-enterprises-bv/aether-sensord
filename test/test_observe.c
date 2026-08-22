/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Host-side unit tests for the aggregation logic. Builds with plain gcc --
 * no netlink, no OpenWrt toolchain, no device:
 *
 *     make -C net/aether-sensord/test
 */

#include "../src/observe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond, msg)                                                       \
	do {                                                                   \
		checks++;                                                      \
		if (!(cond)) {                                                 \
			failures++;                                            \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__,          \
			        __LINE__, (msg));                              \
		}                                                              \
	} while (0)

static struct obs_addr addr(const char *s)
{
	struct obs_addr a;
	if (!obs_addr_parse(&a, s)) {
		fprintf(stderr, "test bug: unparseable address %s\n", s);
		exit(2);
	}
	return a;
}

static void test_addr_roundtrip(void)
{
	char buf[46];
	struct obs_addr a = addr("45.155.205.233");
	CHECK(a.len == 4, "v4 length");
	CHECK(obs_addr_str(&a, buf, sizeof(buf)), "v4 to string");
	CHECK(strcmp(buf, "45.155.205.233") == 0, "v4 round-trip");

	struct obs_addr b = addr("2001:db8::1");
	CHECK(b.len == 16, "v6 length");
	CHECK(obs_addr_str(&b, buf, sizeof(buf)), "v6 to string");
	CHECK(strcmp(buf, "2001:db8::1") == 0, "v6 round-trip");

	CHECK(!obs_addr_eq(&a, &b), "families are not equal");
	struct obs_addr a2 = addr("45.155.205.233");
	CHECK(obs_addr_eq(&a, &a2), "same address is equal");
}

static void test_private_ranges_refused(void)
{
	/* A mis-scoped firewall rule must not turn this into a sensor that
	 * reports the subscriber's own network. */
	const char *priv[] = { "10.1.2.3",    "192.168.1.1", "172.16.0.1",
	                       "172.31.255.1", "127.0.0.1",  "169.254.1.1",
	                       "100.64.0.1",  "203.0.113.5", "198.51.100.9",
	                       "192.0.2.4",   "224.0.0.1",   "::1",
	                       "fe80::1",     "fd00::1",
	                       /* v6 gaps found in review: the two branches must
	                        * refuse the same classes of address. */
	                       "::",          /* unspecified -- was falling through */
	                       "2001:db8::1", /* documentation */
	                       "ff02::1",     /* multicast */
	                       "::ffff:10.1.2.3", /* RFC1918 in a v6 coat */
	                       NULL };
	for (int i = 0; priv[i]; i++) {
		struct obs_addr a = addr(priv[i]);
		CHECK(obs_addr_is_private(&a), priv[i]);
	}

	const char *pub[] = { "45.155.205.233", "1.19.0.1", "8.8.8.8",
	                      "172.32.0.1", /* just outside RFC 1918 */
	                      "100.128.0.1", /* just outside CGNAT */
	                      /* A genuinely routable v6 address. 2001:db8::1 used
	                       * to sit here and was wrong -- it is the RFC 3849
	                       * documentation prefix, and is now refused. */
	                      "2606:4700::1111",
	                      "2a00:1450:4001::1", NULL };
	for (int i = 0; pub[i]; i++) {
		struct obs_addr a = addr(pub[i]);
		CHECK(!obs_addr_is_private(&a), pub[i]);
	}
}

static void test_records_and_aggregates(void)
{
	struct obs_table t;
	CHECK(obs_table_init(&t, 64, 8), "init");

	struct obs_addr a = addr("45.155.205.233");
	CHECK(obs_record(&t, &a, 22, 1000), "first record");
	CHECK(obs_record(&t, &a, 22, 1005), "same port again");
	CHECK(obs_record(&t, &a, 23, 1010), "second port");

	CHECK(t.used == 1, "one source aggregated");
	const struct obs_entry *e = NULL;
	for (size_t i = 0; i < t.capacity; i++) {
		if (t.entries[i].used) {
			e = &t.entries[i];
			break;
		}
	}
	CHECK(e != NULL, "entry found");
	CHECK(e->hits == 3, "three hits");
	CHECK(e->ports_seen == 2, "two distinct ports");
	CHECK(e->first_seen == 1000, "first_seen is the earliest");
	CHECK(e->last_seen == 1010, "last_seen is the latest");

	obs_table_free(&t);
}

static void test_private_source_is_counted_not_recorded(void)
{
	struct obs_table t;
	obs_table_init(&t, 64, 8);
	struct obs_addr lan = addr("192.168.1.50");
	CHECK(!obs_record(&t, &lan, 80, 1000), "LAN source refused");
	CHECK(t.used == 0, "nothing recorded");
	/* Non-zero here is the signal that the nft rule is mis-scoped. */
	CHECK(t.dropped_private == 1, "refusal is counted, not silent");
	obs_table_free(&t);
}

static void test_scan_classification(void)
{
	struct obs_table t;
	obs_table_init(&t, 64, 8); /* threshold: 8 distinct ports */

	struct obs_addr quiet = addr("45.155.205.233");
	for (uint16_t p = 1; p <= 3; p++)
		obs_record(&t, &quiet, p, 1000);

	struct obs_addr scanner = addr("45.155.205.234");
	for (uint16_t p = 1; p <= 20; p++)
		obs_record(&t, &scanner, p, 1000);

	for (size_t i = 0; i < t.capacity; i++) {
		const struct obs_entry *e = &t.entries[i];
		if (!e->used)
			continue;
		if (obs_addr_eq(&e->src, &quiet))
			CHECK(obs_classify(&t, e) == OBS_BLOCKED_CONNECT,
			      "three ports is not a scan");
		if (obs_addr_eq(&e->src, &scanner))
			CHECK(obs_classify(&t, e) == OBS_PORT_SCAN,
			      "twenty ports is a scan");
	}
	obs_table_free(&t);
}

static void test_distinct_port_count_survives_the_storage_cap(void)
{
	/* Storage is capped at OBS_MAX_PORTS, but a scanner hitting thousands
	 * of ports must still read as a scan rather than being blunted by the
	 * memory bound. */
	struct obs_table t;
	obs_table_init(&t, 8, 8);
	struct obs_addr s = addr("45.155.205.234");
	for (uint16_t p = 1; p <= 1000; p++)
		obs_record(&t, &s, p, 1000);

	const struct obs_entry *e = NULL;
	for (size_t i = 0; i < t.capacity; i++)
		if (t.entries[i].used)
			e = &t.entries[i];

	CHECK(e && e->n_ports == OBS_MAX_PORTS, "stored ports are capped");
	/* Past the cap the count is a FLOOR, not a claim. Dedup can only scan
	 * what is stored, so continuing to increment reported 1032 for 33
	 * distinct ports in an earlier version -- a number the comment claimed
	 * was exact. */
	CHECK(e && e->ports_seen == OBS_MAX_PORTS, "count stops at the cap");
	CHECK(e && e->ports_truncated, "and says it is truncated");
	CHECK(e && obs_classify(&t, e) == OBS_PORT_SCAN,
	      "still a scan -- threshold 8 is reached long before the cap");
	obs_table_free(&t);
}

static void test_full_table_drops_are_counted(void)
{
	struct obs_table t;
	obs_table_init(&t, 4, 8);
	char buf[32];
	/* Fill beyond capacity with distinct public sources. */
	for (int i = 1; i <= 10; i++) {
		snprintf(buf, sizeof(buf), "45.155.205.%d", i);
		struct obs_addr a = addr(buf);
		obs_record(&t, &a, 22, 1000);
	}
	CHECK(t.used == 4, "table filled to capacity");
	CHECK(t.dropped_full == 6, "overflow is counted, not silently lost");
	obs_table_free(&t);
}

static void test_ndjson_output(void)
{
	struct obs_table t;
	obs_table_init(&t, 16, 8);
	struct obs_addr a = addr("45.155.205.233");
	obs_record(&t, &a, 22, 1000);
	obs_record(&t, &a, 23, 1001);

	char *buf = NULL;
	size_t len = 0;
	FILE *f = open_memstream(&buf, &len);
	CHECK(f != NULL, "memstream");
	long n = obs_write_ndjson(&t, f);
	fclose(f);

	CHECK(n == 1, "one record written");
	CHECK(strstr(buf, "\"src\":\"45.155.205.233\"") != NULL, "source present");
	CHECK(strstr(buf, "\"kind\":\"blocked_connect\"") != NULL, "kind present");
	CHECK(strstr(buf, "\"hits\":2") != NULL, "hit count present");
	CHECK(strstr(buf, "\"ports_seen\":2") != NULL, "port count present");
	CHECK(buf[len - 1] == '\n', "NDJSON line is terminated");

	free(buf);
	obs_table_free(&t);
}

static void test_reset_clears_counters(void)
{
	struct obs_table t;
	obs_table_init(&t, 16, 8);
	struct obs_addr a = addr("45.155.205.233");
	struct obs_addr lan = addr("10.0.0.1");
	obs_record(&t, &a, 22, 1000);
	obs_record(&t, &lan, 22, 1000);

	obs_table_reset(&t);
	CHECK(t.used == 0, "entries cleared");
	CHECK(t.dropped_private == 0, "private counter cleared");
	CHECK(t.dropped_full == 0, "full counter cleared");
	/* Threshold is configuration, not state -- it must survive a flush. */
	CHECK(t.scan_port_threshold == 8, "threshold retained across reset");
	obs_table_free(&t);
}


/* A real IPv4 TCP SYN header, byte for byte: 45.155.205.233 -> port 22.
 * IHL=5, proto=6 (TCP), no fragmentation. */
static const unsigned char PKT_V4_TCP[] = {
	0x45, 0x00, 0x00, 0x3c,  /* ver/ihl, tos, total len */
	0xab, 0xcd, 0x40, 0x00,  /* id, flags=DF, frag off = 0 */
	0x40, 0x06, 0x00, 0x00,  /* ttl, proto=TCP, checksum */
	0x2d, 0x9b, 0xcd, 0xe9,  /* src 45.155.205.233 */
	0xc0, 0xa8, 0x01, 0x01,  /* dst 192.168.1.1 */
	0xd4, 0x31, 0x00, 0x16,  /* sport 54321, dport 22 */
	0x00, 0x00, 0x00, 0x00,  /* seq */
};

/* Same source, UDP to port 53. proto=17. */
static const unsigned char PKT_V4_UDP[] = {
	0x45, 0x00, 0x00, 0x20,
	0xab, 0xce, 0x00, 0x00,
	0x40, 0x11, 0x00, 0x00,  /* proto=UDP */
	0x2d, 0x9b, 0xcd, 0xe9,
	0xc0, 0xa8, 0x01, 0x01,
	0xd4, 0x31, 0x00, 0x35,  /* sport 54321, dport 53 */
};

/* Non-first fragment: frag offset non-zero, so there is no L4 header even
 * though proto still reads TCP. Must yield port 0, not garbage. */
static const unsigned char PKT_V4_FRAG[] = {
	0x45, 0x00, 0x00, 0x3c,
	0xab, 0xcd, 0x00, 0xb9,  /* frag offset = 185 */
	0x40, 0x06, 0x00, 0x00,
	0x2d, 0x9b, 0xcd, 0xe9,
	0xc0, 0xa8, 0x01, 0x01,
	0xde, 0xad, 0xbe, 0xef,  /* payload, NOT a TCP header */
};

/* IPv4 with options: IHL=6 (24 bytes), so the L4 header starts 4 bytes later.
 * Getting this wrong is the classic byte-offset bug. */
static const unsigned char PKT_V4_OPTS[] = {
	0x46, 0x00, 0x00, 0x40,  /* IHL = 6 */
	0xab, 0xcd, 0x40, 0x00,
	0x40, 0x06, 0x00, 0x00,
	0x2d, 0x9b, 0xcd, 0xe9,
	0xc0, 0xa8, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x00,  /* 4 bytes of IP options */
	0xd4, 0x31, 0x01, 0xbb,  /* sport 54321, dport 443 */
};

/* IPv6 TCP: 2001:db8::1 -> port 443, next header = 6. */
static const unsigned char PKT_V6_TCP[] = {
	0x60, 0x00, 0x00, 0x00,
	0x00, 0x14, 0x06, 0x40,  /* payload len, next hdr = TCP, hop limit */
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,  /* src 2001:db8::1 */
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,  /* dst */
	0xd4, 0x31, 0x01, 0xbb,  /* sport 54321, dport 443 */
};

static void test_decode_v4_tcp(void)
{
	struct obs_addr src;
	uint16_t port = 0xffff;
	CHECK(obs_decode(PKT_V4_TCP, sizeof(PKT_V4_TCP), &src, &port) == 0, "v4 tcp decodes");
	struct obs_addr want = addr("45.155.205.233");
	CHECK(obs_addr_eq(&src, &want), "v4 source address");
	CHECK(port == 22, "v4 tcp dport");
}

static void test_decode_v4_udp(void)
{
	struct obs_addr src;
	uint16_t port = 0;
	CHECK(obs_decode(PKT_V4_UDP, sizeof(PKT_V4_UDP), &src, &port) == 0, "v4 udp decodes");
	CHECK(port == 53, "v4 udp dport");
}

static void test_decode_v4_with_options(void)
{
	/* The L4 header is at IHL*4, not at a fixed 20. */
	struct obs_addr src;
	uint16_t port = 0;
	CHECK(obs_decode(PKT_V4_OPTS, sizeof(PKT_V4_OPTS), &src, &port) == 0, "v4 opts decodes");
	CHECK(port == 443, "dport read past IP options");
}

static void test_decode_fragment_yields_no_port(void)
{
	struct obs_addr src;
	uint16_t port = 0xffff;
	CHECK(obs_decode(PKT_V4_FRAG, sizeof(PKT_V4_FRAG), &src, &port) == 0, "fragment decodes");
	struct obs_addr want = addr("45.155.205.233");
	CHECK(obs_addr_eq(&src, &want), "fragment source still read");
	CHECK(port == 0, "non-first fragment must not read payload as a port");
}

static void test_decode_v6_tcp(void)
{
	struct obs_addr src;
	uint16_t port = 0;
	CHECK(obs_decode(PKT_V6_TCP, sizeof(PKT_V6_TCP), &src, &port) == 0, "v6 tcp decodes");
	struct obs_addr want = addr("2001:db8::1");
	CHECK(obs_addr_eq(&src, &want), "v6 source address");
	CHECK(port == 443, "v6 tcp dport");
}

static void test_decode_rejects_malformed(void)
{
	struct obs_addr src;
	uint16_t port = 0;
	/* Truncated. */
	CHECK(obs_decode(PKT_V4_TCP, 8, &src, &port) != 0, "truncated v4 refused");
	CHECK(obs_decode(PKT_V6_TCP, 8, &src, &port) != 0, "truncated v6 refused");
	CHECK(obs_decode(PKT_V4_TCP, 0, &src, &port) != 0, "empty refused");
	/* Version 7 is neither v4 nor v6. */
	unsigned char bogus[24];
	memcpy(bogus, PKT_V4_TCP, sizeof(bogus));
	bogus[0] = 0x75;
	CHECK(obs_decode(bogus, sizeof(bogus), &src, &port) != 0, "bad version refused");
	/* IHL smaller than the minimum header. */
	memcpy(bogus, PKT_V4_TCP, sizeof(bogus));
	bogus[0] = 0x42;
	CHECK(obs_decode(bogus, sizeof(bogus), &src, &port) != 0, "short IHL refused");
}

static void test_decode_truncated_l4_gives_no_port(void)
{
	/* Header copy is capped at 96 bytes; a packet cut right after the IP
	 * header must yield port 0 rather than reading past the buffer. */
	struct obs_addr src;
	uint16_t port = 0xffff;
	CHECK(obs_decode(PKT_V4_TCP, 20, &src, &port) == 0, "ip-only decodes");
	CHECK(port == 0, "no L4 bytes means no port");
}

static void test_unreachable_scan_threshold_is_refused(void)
{
	/* ports_seen cannot exceed the store, so a threshold above it can never
	 * be reached and scan detection would be silently off. Refusing to
	 * start is the correct failure. */
	struct obs_table t;
	CHECK(!obs_table_init(&t, 64, OBS_MAX_PORTS + 1),
	      "threshold above the port store is refused");
	CHECK(obs_table_init(&t, 64, OBS_MAX_PORTS),
	      "threshold exactly at the cap is allowed");
	obs_table_free(&t);
	CHECK(obs_table_init(&t, 64, 8), "the default is well within it");
	obs_table_free(&t);
}

int main(void)
{
	test_addr_roundtrip();
	test_private_ranges_refused();
	test_records_and_aggregates();
	test_private_source_is_counted_not_recorded();
	test_scan_classification();
	test_distinct_port_count_survives_the_storage_cap();
	test_full_table_drops_are_counted();
	test_ndjson_output();
	test_reset_clears_counters();
	test_unreachable_scan_threshold_is_refused();
	test_decode_v4_tcp();
	test_decode_v4_udp();
	test_decode_v4_with_options();
	test_decode_fragment_yields_no_port();
	test_decode_v6_tcp();
	test_decode_rejects_malformed();
	test_decode_truncated_l4_gives_no_port();

	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
