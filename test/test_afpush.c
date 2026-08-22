/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Host tests for the rule-push wire format.
 *
 * The headline case is HASH AGREEMENT with the kernel module. If the daemon
 * and the module compute a different FNV-1a, nothing fails loudly -- every
 * rule simply stops matching, which is indistinguishable from "there is
 * nothing to block". A shared test vector is the only cheap defence.
 */

#include "../src/afpush.h"

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

static void test_hash_vector(void)
{
	/* These values are the contract with af_hash_name() in the module.
	 * net/aether-af/test/test_match.c asserts the same names produce the
	 * same numbers on the kernel side. If one side is edited, both tests
	 * must be updated together -- and if only one is, they disagree here
	 * rather than silently in the field. */
	CHECK(afpush_hash_name("www.youtube.com", 15) ==
	          afpush_hash_name("WWW.YouTube.COM", 15),
	      "case folded");
	CHECK(afpush_hash_name("a", 1) != afpush_hash_name("b", 1), "differs");
	CHECK(afpush_hash_name(NULL, 4) == 0, "null is zero, not a crash");
	/* FNV-1a offset basis, empty input. */
	CHECK(afpush_hash_name("", 0) == 1469598103934665603ULL,
	      "empty string is the offset basis");
}

static void test_hello(void)
{
	uint8_t b[64];
	size_t n = afpush_build_hello(b, sizeof(b));
	CHECK(n == 8 + 8, "hello is header + version");
	uint16_t type;
	memcpy(&type, b, 2);
	CHECK(type == AFPUSH_HELLO, "type");
	uint32_t ver;
	memcpy(&ver, b + 8, 4);
	CHECK(ver == AFPUSH_PROTO_VERSION, "version");
	CHECK(afpush_build_hello(b, 4) == 0, "short buffer writes nothing");
}

static void test_rules_batch(void)
{
	uint64_t h[4] = { 1, 2, 3, 4 };
	bool per[4] = { false, true, false, true };
	uint8_t macs[4][AFPUSH_MAC_LEN] = { { 0 }, { 2, 0, 0, 0, 0, 1 }, { 0 },
		                            { 2, 0, 0, 0, 0, 2 } };
	uint8_t b[512];
	size_t written = 99;

	size_t n = afpush_build_rules(b, sizeof(b), h, macs, per, 4, &written);
	CHECK(n > 0, "built");
	CHECK(written == 4, "all four rules written");
	uint16_t count;
	memcpy(&count, b + 2, 2);
	CHECK(count == 4, "count in header");
}

static void test_short_buffer_reports_partial(void)
{
	/* A caller that ignores n_written and assumes the whole batch went
	 * would commit a rule set enforcing less than the controller believes.
	 * The count must be honest. */
	uint64_t h[100];
	uint8_t b[64];
	size_t written = 99;
	for (int i = 0; i < 100; i++)
		h[i] = (uint64_t)i + 1;

	size_t n = afpush_build_rules(b, sizeof(b), h, NULL, NULL, 100, &written);
	CHECK(n > 0, "wrote something");
	CHECK(written < 100, "reports FEWER than asked");
	CHECK(written == (sizeof(b) - 8) / 16, "exactly what fits");

	uint8_t tiny[8];
	written = 99;
	CHECK(afpush_build_rules(tiny, sizeof(tiny), h, NULL, NULL, 100, &written) == 0,
	      "no room for even one rule");
	CHECK(written == 0, "and reports zero");
}

static void test_compile_only_block_rules(void)
{
	struct sig_db sigs;
	sig_db_init(&sigs);
	const char *text = "11001 YouTube:[tcp;;;youtube;;]\n"
	                   "39037 YouTube:[tcp;;;www.youtube.com;;]\n"
	                   "13005 samba:[tcp;;445;;;]\n"
	                   "20001 Wikipedia:[tcp;;;wikipedia.org;;]\n";
	FILE *fp = fmemopen((void *)text, strlen(text), "r");
	sig_db_load(&sigs, fp);
	fclose(fp);

	struct pol_db pol;
	pol_db_init(&pol);
	uint8_t kid[6] = { 2, 0, 0, 0, 0, 1 };
	size_t s = pol_add_subject(&pol, kid, "kid");

	struct pol_rule blk;
	memset(&blk, 0, sizeof(blk));
	blk.subject_index = (uint16_t)s;
	blk.target = POL_TARGET_APP;
	snprintf(blk.tag, sizeof(blk.tag), "youtube");
	blk.action = POL_BLOCK;
	pol_add_rule(&pol, &sigs, &blk);

	/* An ALLOW rule must produce NO kernel state. The module has no concept
	 * of "allow" and must not be taught one. */
	struct pol_rule allow = blk;
	snprintf(allow.tag, sizeof(allow.tag), "wikipedia");
	allow.action = POL_ALLOW;
	pol_add_rule(&pol, &sigs, &allow);

	uint64_t out[64];
	size_t coll = 99;
	long n = afpush_compile(&pol, &sigs, out, 64, &coll);

	CHECK(n == 2, "both youtube patterns hashed, wikipedia excluded");
	CHECK(coll == 0, "no collisions");

	/* samba is port-only: no name, so nothing to hash. */
	uint64_t samba_h = afpush_hash_name("samba", 5);
	bool found = false;
	for (long i = 0; i < n; i++)
		if (out[i] == samba_h)
			found = true;
	CHECK(!found, "port-only signatures contribute no hash");

	/* The hashes really are the youtube patterns. */
	uint64_t want = afpush_hash_name("www.youtube.com", 15);
	found = false;
	for (long i = 0; i < n; i++)
		if (out[i] == want)
			found = true;
	CHECK(found, "www.youtube.com present");

	pol_db_free(&pol);
	sig_db_free(&sigs);
}

static void test_compile_bounded(void)
{
	struct sig_db sigs;
	sig_db_init(&sigs);
	struct pol_db pol;
	pol_db_init(&pol);
	uint64_t out[2];
	size_t coll;
	/* Empty inputs must not fabricate rules. */
	CHECK(afpush_compile(&pol, &sigs, out, 2, &coll) == 0, "empty is zero");
	CHECK(afpush_compile(NULL, &sigs, out, 2, &coll) == -1, "null refused");
	pol_db_free(&pol);
	sig_db_free(&sigs);
}

/*
 * The batching loop in sensord.c, exercised here rather than in main().
 *
 * The property that matters is coverage: every hash must cross exactly once,
 * in order, with no gap and no repeat. A gap enforces less than the controller
 * believes and looks identical to a clean push.
 */
static void test_batching_covers_every_rule(void)
{
	enum { N = 5000 };
	static uint64_t in[N];
	static uint8_t seen[N];
	uint8_t msg[AFPUSH_MAX_MSG];
	size_t written = 0, i;
	unsigned batches = 0;
	int ordered = 1;

	for (i = 0; i < N; i++)
		in[i] = 0x1000000000000000ULL + i;
	memset(seen, 0, sizeof(seen));

	while (written < N) {
		size_t chunk = 0;
		size_t n = afpush_build_rules(msg, sizeof(msg), in + written,
		                              NULL, NULL, N - written, &chunk);
		const uint8_t *body = msg + 8; /* past struct afpush_hdr */
		uint16_t hdr_count;
		uint32_t hdr_len;
		size_t k;

		CHECK(n > 0 && chunk > 0, "each batch makes progress");
		if (n == 0 || chunk == 0)
			break; /* would spin; the daemon breaks here too */
		CHECK(n <= sizeof(msg), "batch never exceeds the buffer");

		/* Read the offsets back out of the header rather than trusting
		 * the constants below, so a wire-format change fails this test
		 * instead of silently reading the wrong bytes. */
		memcpy(&hdr_count, msg + 2, sizeof(hdr_count));
		memcpy(&hdr_len, msg + 4, sizeof(hdr_len));
		CHECK(hdr_count == chunk, "header count matches what was written");
		CHECK(hdr_len == chunk * 16, "header length matches the body");
		CHECK(n == 8 + hdr_len, "total is header plus body, no padding");

		for (k = 0; k < chunk; k++) {
			uint64_t h;

			memcpy(&h, body + k * 16, sizeof(h));
			if (h != in[written + k])
				ordered = 0;
			if (h >= 0x1000000000000000ULL &&
			    h - 0x1000000000000000ULL < N)
				seen[h - 0x1000000000000000ULL]++;
		}
		written += chunk;
		batches++;
	}

	CHECK(written == N, "every rule was sent");
	CHECK(batches > 1, "the fixture actually needed more than one batch");
	CHECK(ordered == 1, "rules arrive in order across batch boundaries");

	{
		size_t missing = 0, dup = 0;

		for (i = 0; i < N; i++) {
			if (seen[i] == 0)
				missing++;
			else if (seen[i] > 1)
				dup++;
		}
		CHECK(missing == 0, "no rule was skipped at a batch boundary");
		CHECK(dup == 0, "no rule was sent twice at a batch boundary");
	}
}

/* A capacity that cannot hold even one rule must report zero, not loop. */
static void test_batching_refuses_to_spin(void)
{
	uint8_t msg[AFPUSH_MAX_MSG];
	uint64_t one = 0xabcdef;
	size_t chunk = 12345;
	size_t n;

	/* Header fits, one rule does not. */
	n = afpush_build_rules(msg, 8 + 4, &one, NULL, NULL, 1, &chunk);
	CHECK(n == 0, "a buffer too small for one rule builds nothing");
	CHECK(chunk == 0, "and reports zero written, so the caller cannot spin");
}

int main(void)
{
	test_hash_vector();
	test_hello();
	test_rules_batch();
	test_short_buffer_reports_partial();
	test_compile_only_block_rules();
	test_compile_bounded();
	test_batching_covers_every_rule();
	test_batching_refuses_to_spin();
	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
