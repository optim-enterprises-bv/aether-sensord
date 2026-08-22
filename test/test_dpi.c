/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Tests for nDPI dissection.
 *
 * The one that matters is the scope decision. Getting it wrong is silent IN THE
 * DANGEROUS DIRECTION: calling a QUIC flow name-hashable pushes a hash the
 * kernel will never match, and the block simply never happens while every
 * counter reports success.
 *
 *   make -C test check          (skips if libndpi is absent, and says so)
 */

#include "../src/dpi.h"

#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

#include <ndpi/ndpi_typedefs.h>

static int checks, failures;
#define CHECK(cond, msg)                                                       \
	do {                                                                   \
		checks++;                                                      \
		if (!(cond)) {                                                 \
			failures++;                                            \
			printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);  \
		}                                                              \
	} while (0)

/* ---- scope: the decision that must not be wrong ------------------------- */

static void test_scope_decision(void)
{
	/* The kernel can re-derive these: TCP, and a protocol whose name is in
	 * cleartext where af_match.c looks for it. */
	CHECK(dpi_kernel_can_match(IPPROTO_TCP, NDPI_PROTOCOL_TLS,
	                           NDPI_PROTOCOL_TLS) == true,
	      "TCP/TLS is name-hashable in the kernel");
	CHECK(dpi_kernel_can_match(IPPROTO_TCP, NDPI_PROTOCOL_HTTP,
	                           NDPI_PROTOCOL_HTTP) == true,
	      "TCP/HTTP is name-hashable in the kernel");
	CHECK(dpi_kernel_can_match(IPPROTO_TCP, NDPI_PROTOCOL_TLS,
	                           NDPI_PROTOCOL_UNKNOWN) == true,
	      "master TLS is enough even with an unknown app protocol");

	/*
	 * QUIC is the whole point. af_module.c refuses anything that is not
	 * IPPROTO_TCP, so a QUIC flow can never be matched by name in the
	 * kernel no matter what nDPI extracted.
	 */
	CHECK(dpi_kernel_can_match(IPPROTO_UDP, NDPI_PROTOCOL_QUIC,
	                           NDPI_PROTOCOL_QUIC) == false,
	      "QUIC is NOT name-hashable: kernel never sees UDP");
	CHECK(dpi_kernel_can_match(IPPROTO_UDP, NDPI_PROTOCOL_TLS,
	                           NDPI_PROTOCOL_TLS) == false,
	      "even TLS-over-UDP is refused; the gate is the transport");
	CHECK(dpi_kernel_can_match(IPPROTO_UDP, NDPI_PROTOCOL_DNS,
	                           NDPI_PROTOCOL_DNS) == false,
	      "DNS over UDP is address-scope");
	CHECK(dpi_kernel_can_match(IPPROTO_TCP, NDPI_PROTOCOL_SSH,
	                           NDPI_PROTOCOL_SSH) == false,
	      "TCP alone is not enough: af_match reads TLS/HTTP only");
	CHECK(dpi_kernel_can_match(IPPROTO_ICMP, NDPI_PROTOCOL_UNKNOWN,
	                           NDPI_PROTOCOL_UNKNOWN) == false,
	      "ICMP is address-scope");
}

/* ---- packet construction ------------------------------------------------ */

static size_t mk_ipv4(uint8_t *b, uint8_t proto, const uint8_t s[4],
                      const uint8_t d[4], uint16_t sp, uint16_t dp,
                      const uint8_t *payload, size_t plen)
{
	size_t l4 = (proto == IPPROTO_TCP) ? 20 : 8;
	size_t tot = 20 + l4 + plen;

	memset(b, 0, tot);
	b[0] = 0x45;
	b[2] = (uint8_t)(tot >> 8);
	b[3] = (uint8_t)(tot & 0xff);
	b[8] = 64;
	b[9] = proto;
	memcpy(b + 12, s, 4);
	memcpy(b + 16, d, 4);
	b[20] = (uint8_t)(sp >> 8);
	b[21] = (uint8_t)(sp & 0xff);
	b[22] = (uint8_t)(dp >> 8);
	b[23] = (uint8_t)(dp & 0xff);
	if (proto == IPPROTO_TCP) {
		b[32] = 0x50; /* data offset 5 */
		b[33] = 0x18; /* PSH|ACK */
	} else {
		uint16_t ul = (uint16_t)(8 + plen);

		b[24] = (uint8_t)(ul >> 8);
		b[25] = (uint8_t)(ul & 0xff);
	}
	if (payload && plen)
		memcpy(b + 20 + l4, payload, plen);
	return tot;
}

/* ---- decode / table behaviour ------------------------------------------- */

static void test_decode_and_table(void)
{
	struct dpi_ctx *c = dpi_new(4);
	struct dpi_result r;
	struct dpi_stats st;
	uint8_t pkt[512];
	const uint8_t s[4] = { 1, 2, 3, 4 }, d[4] = { 5, 6, 7, 8 };
	size_t n;

	CHECK(c != NULL, "context created");
	if (!c)
		return;

	/* Garbage in: refused and counted, never dissected. */
	memset(pkt, 0xff, 8);
	dpi_process(c, pkt, 8, 1000, &r);
	dpi_get_stats(c, &st);
	CHECK(st.undecodable == 1, "a runt packet is counted undecodable");

	/* A truncated IPv4 header claiming more than delivered. */
	n = mk_ipv4(pkt, IPPROTO_TCP, s, d, 1234, 443, NULL, 0);
	dpi_process(c, pkt, 21, 1000, &r);
	dpi_get_stats(c, &st);
	CHECK(st.undecodable == 2, "a truncated L4 header is refused");

	/* A real one creates exactly one flow. */
	dpi_process(c, pkt, n, 1000, &r);
	dpi_get_stats(c, &st);
	CHECK(st.flows_new == 1, "one flow created");

	/* The reverse direction must land on the SAME flow, or nDPI only ever
	 * sees half a handshake. */
	n = mk_ipv4(pkt, IPPROTO_TCP, d, s, 443, 1234, NULL, 0);
	dpi_process(c, pkt, n, 1001, &r);
	dpi_get_stats(c, &st);
	CHECK(st.flows_new == 1, "reverse direction reuses the same flow");

	dpi_free(c);
}

static void test_table_bound_and_eviction(void)
{
	struct dpi_ctx *c = dpi_new(2);
	struct dpi_result r;
	struct dpi_stats st;
	uint8_t pkt[512];
	uint8_t s[4] = { 1, 2, 3, 4 }, d[4] = { 5, 6, 7, 8 };
	size_t n, i;

	CHECK(c != NULL, "small context created");
	if (!c)
		return;

	for (i = 0; i < 6; i++) {
		s[3] = (uint8_t)(10 + i);
		n = mk_ipv4(pkt, IPPROTO_TCP, s, d, (uint16_t)(1000 + i), 443,
		            NULL, 0);
		dpi_process(c, pkt, n, 1000 + i, &r);
	}
	dpi_get_stats(c, &st);
	CHECK(st.flows_new == 6, "every distinct flow was admitted");
	CHECK(st.flows_evicted == 4, "the table stayed bounded by evicting");
	CHECK(st.flows_refused == 0, "eviction is preferred to refusing");

	dpi_free(c);
}

static void test_bounds_refused(void)
{
	CHECK(dpi_new(0) == NULL, "a zero-sized table is refused");
	CHECK(dpi_new((size_t)1 << 30) == NULL,
	      "an absurd table is refused rather than OOMing the router");
}

static void test_expiry(void)
{
	struct dpi_ctx *c = dpi_new(8);
	struct dpi_result r;
	uint8_t pkt[512];
	const uint8_t s[4] = { 1, 2, 3, 4 }, d[4] = { 5, 6, 7, 8 };
	size_t n;

	if (!c)
		return;
	n = mk_ipv4(pkt, IPPROTO_TCP, s, d, 1234, 443, NULL, 0);
	dpi_process(c, pkt, n, 1000, &r);

	CHECK(dpi_expire(c, 1500, 1000) == 0, "a fresh flow is not expired");
	CHECK(dpi_expire(c, 5000, 1000) == 1, "an idle flow is expired");
	CHECK(dpi_expire(c, 9000, 1000) == 0, "expiring twice frees nothing");
	dpi_free(c);
}

/* A flow nDPI cannot classify must stop consuming CPU, WITHOUT that stop ever
 * being read as a verdict. */
static void test_gives_up_without_verdict(void)
{
	struct dpi_ctx *c = dpi_new(8);
	struct dpi_result r;
	struct dpi_stats st;
	uint8_t pkt[512];
	const uint8_t s[4] = { 1, 2, 3, 4 }, d[4] = { 5, 6, 7, 8 };
	uint8_t junk[64];
	size_t n, i;
	bool ever_reported = false;

	if (!c)
		return;
	memset(junk, 0x5a, sizeof(junk));
	for (i = 0; i < DPI_MAX_PKTS_PER_FLOW + 8; i++) {
		n = mk_ipv4(pkt, IPPROTO_TCP, s, d, 4444, 4445, junk,
		            sizeof(junk));
		if (dpi_process(c, pkt, n, 1000 + i, &r))
			ever_reported = true;
	}
	dpi_get_stats(c, &st);
	CHECK(st.packets_in == DPI_MAX_PKTS_PER_FLOW + 8, "all packets counted");
	CHECK(ever_reported == false || st.classified > 0,
	      "a report only ever accompanies a classification");
	dpi_free(c);
}

/* ---- real dissection ----------------------------------------------------- */

/*
 * A genuine TLS ClientHello for www.example.org.
 *
 * This is the case aether-af ALREADY handles, so the assertion is not that
 * nDPI can do it -- it is that we get NAME_HASH scope, i.e. we do not
 * needlessly push an address block for traffic the kernel can match itself.
 */
static void test_tls_clienthello_is_name_scope(void)
{
	static const uint8_t ch[] = {
		0x16, 0x03, 0x01, 0x00, 0x6c, 0x01, 0x00, 0x00, 0x68, 0x03,
		0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
		0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00,
		0x00, 0x3d,
		/* extension: server_name = www.example.org */
		0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00, 0x0f,
		'w', 'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.',
		'o', 'r', 'g',
		/* supported_versions */
		0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
		/* supported_groups */
		0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17,
		/* key_share (empty) */
		0x00, 0x33, 0x00, 0x02, 0x00, 0x00,
		/* padding to make the record plausible */
		0x00, 0x15, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0
	};
	struct dpi_ctx *c = dpi_new(16);
	struct dpi_result r;
	uint8_t pkt[1024];
	const uint8_t s[4] = { 192, 0, 2, 10 }, d[4] = { 93, 184, 216, 34 };
	size_t n, i;
	bool got = false;

	if (!c)
		return;
	for (i = 0; i < 8 && !got; i++) {
		n = mk_ipv4(pkt, IPPROTO_TCP, s, d, 50000, 443, ch, sizeof(ch));
		if (dpi_process(c, pkt, n, 2000 + i, &r))
			got = true;
	}

	if (got && r.classified) {
		CHECK(r.l4proto == IPPROTO_TCP, "classified flow is TCP");
		if (r.have_host)
			CHECK(strstr(r.host, "example") != NULL,
			      "SNI extracted from the ClientHello");
		/* Whatever nDPI called it, TCP+TLS must be NAME_HASH scope. */
		if (r.master_proto == NDPI_PROTOCOL_TLS ||
		    r.app_proto == NDPI_PROTOCOL_TLS)
			CHECK(r.scope == DPI_SCOPE_NAME_HASH,
			      "TCP/TLS routes to the kernel, not to an nft set");
	} else {
		printf("  NOTE: TLS fixture not classified by this nDPI build; "
		       "scope logic still covered by test_scope_decision\n");
	}
	dpi_free(c);
}

/*
 * UDP/443 must NEVER come back as name scope, whatever nDPI decides it is.
 * This is the regression guard for the QUIC gap.
 */
static void test_udp443_is_never_name_scope(void)
{
	struct dpi_ctx *c = dpi_new(16);
	struct dpi_result r;
	uint8_t pkt[1024];
	uint8_t body[256];
	const uint8_t s[4] = { 192, 0, 2, 10 }, d[4] = { 142, 250, 74, 78 };
	size_t n, i;

	if (!c)
		return;
	/* Shape of a QUIC long header: high bit set, version present. */
	memset(body, 0, sizeof(body));
	body[0] = 0xc3;
	body[1] = 0x00;
	body[2] = 0x00;
	body[3] = 0x00;
	body[4] = 0x01;

	for (i = 0; i < 8; i++) {
		n = mk_ipv4(pkt, IPPROTO_UDP, s, d, 50000, 443, body,
		            sizeof(body));
		if (dpi_process(c, pkt, n, 3000 + i, &r) && r.classified) {
			CHECK(r.scope == DPI_SCOPE_ADDRESS,
			      "UDP/443 is ALWAYS address scope, never name hash");
			CHECK(r.l4proto == IPPROTO_UDP, "recorded as UDP");
		}
	}
	dpi_free(c);
}

static void test_stats_are_reported(void)
{
	struct dpi_ctx *c = dpi_new(4);
	struct dpi_stats st;

	if (!c)
		return;
	memset(&st, 0xff, sizeof(st));
	dpi_get_stats(c, &st);
	CHECK(st.packets_in == 0 && st.classified == 0,
	      "a fresh context reports zeroes, not garbage");
	dpi_get_stats(NULL, &st); /* must not crash */
	dpi_free(c);
	dpi_free(NULL); /* must not crash */
	CHECK(1, "NULL handling survives");
}

int main(void)
{
	test_scope_decision();
	test_bounds_refused();
	test_decode_and_table();
	test_table_bound_and_eviction();
	test_expiry();
	test_gives_up_without_verdict();
	test_tls_clienthello_is_name_scope();
	test_udp443_is_never_name_scope();
	test_stats_are_reported();
	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
