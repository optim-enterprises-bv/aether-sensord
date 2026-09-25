/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Tests for the enforcement bridge, driven through a FAKE pfctl.
 *
 * WHY A FAKE. The questions that matter here are not "does pfctl work" -- that
 * is tested live elsewhere -- but "what does this code do when pfctl SAYS it
 * worked and it did not". Those are the failure modes that produce a report of
 * ENFORCED for traffic that is flowing, and they cannot be produced by a real
 * pfctl, which by definition does not lie in the way under test.
 *
 * So the fake is scripted to lie in specific ways and the assertions are about
 * whether the code believes it.
 */

#include "../src/local_enforce.h"

#include "../src/apply_pf.h"
#include "../src/local_decide.h"
#include "../src/pf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks;
static int failures;

#define CHECK(cond, ...)                                                      \
	do {                                                                  \
		checks++;                                                     \
		if (cond) {                                                   \
			printf("  ok: ");                                     \
		} else {                                                      \
			failures++;                                           \
			printf("  FAIL (line %d): ", __LINE__);               \
		}                                                             \
		printf(__VA_ARGS__);                                          \
		printf("\n");                                                 \
	} while (0)

/* ------------------------------------------------------------- fake pfctl */

/*
 * A scriptable pfctl.
 *
 * `mode` selects the lie. The default is an honest one: adds are recorded and
 * `-T show` returns them, and `-s rules` mentions the table, so the full
 * verification path can succeed.
 */
enum fake_mode {
	FAKE_HONEST,       /* adds land, table readable, rule references it */
	FAKE_SILENT_DROP,  /* accepts every add, stores NOTHING, exits 0 */
	FAKE_NO_RULE,      /* elements land, but NO rule references the table */
	FAKE_TABLE_GONE,   /* -T show fails: the table does not exist */
	FAKE_FLUSH_NOOP,   /* flush exits 0 and removes nothing */
	FAKE_ADD_FAIL      /* add exits non-zero */
};

static enum fake_mode fake_mode;
static char fake_table[4096];      /* what "the table" contains */
static int fake_exec_calls;
static char fake_last_argv[2048];

/*
 * Parse the argv shape apply_pf.c actually builds, WITHOUT touching argv[-1].
 *
 * The shape (confirmed by reading apply_pf.c's run_table_op and by the
 * backtrace that found an out-of-bounds read in an earlier version of this
 * helper) is:
 *
 *     argv[0] = program name ("/sbin/pfctl")
 *     argv[1] = "-t"          argv[2] = table
 *     argv[3] = "-T" | "-s"   argv[4] = "add" | "show" | "flush" | "rules"
 *     argv[5..] = elements, one per slot
 *
 * Scanning forward from index 1 for the verb, rather than looking BACK from a
 * candidate element, removes the whole class of off-by-one indexing here.
 */
static const char *fake_verb(const char *const *argv, int *verb_idx)
{
	int i;

	for (i = 1; argv[i]; i++) {
		if (strcmp(argv[i], "add") == 0 || strcmp(argv[i], "show") == 0 ||
		    strcmp(argv[i], "flush") == 0 ||
		    strcmp(argv[i], "rules") == 0) {
			if (verb_idx)
				*verb_idx = i;
			return argv[i];
		}
	}
	if (verb_idx)
		*verb_idx = -1;
	return NULL;
}

static int fake_exec(const char *argv0, const char *const *argv, char *out,
                     size_t out_len, void *user)
{
	const char *verb;
	int vi = -1;
	int i;

	(void)argv0;
	(void)user;
	fake_exec_calls++;

	/* record the argv for assertions about how it was invoked */
	fake_last_argv[0] = '\0';
	for (i = 0; argv[i]; i++) {
		if (strlen(fake_last_argv) + strlen(argv[i]) + 2 >=
		    sizeof fake_last_argv)
			break;
		if (i)
			strcat(fake_last_argv, " ");
		strcat(fake_last_argv, argv[i]);
	}

	verb = fake_verb(argv, &vi);

	/* pfctl -T show -t <table> : read the table */
	if (verb && strcmp(verb, "show") == 0) {
		if (fake_mode == FAKE_TABLE_GONE) {
			snprintf(out, out_len, "pfctl: Table does not exist.");
			return 1;
		}
		snprintf(out, out_len, "%s", fake_table);
		return 0;
	}

	/* pfctl -s rules : the main ruleset */
	if (verb && strcmp(verb, "rules") == 0) {
		if (fake_mode == FAKE_NO_RULE) {
			snprintf(out, out_len,
			         "pass in all\nblock drop out quick on em0 from "
			         "any to any\n");
			return 0;
		}
		snprintf(out, out_len,
		         "block drop in quick on em0 from any to "
		         "<aisense_local4>\npass in all\n");
		return 0;
	}

	/* pfctl -T add -t <table> [addrs...] */
	if (verb && strcmp(verb, "add") == 0) {
		if (fake_mode == FAKE_ADD_FAIL) {
			snprintf(out, out_len,
			         "pfctl: DIOCADDRULENV: Device busy");
			return 1;
		}
		/*
		 * THE DANGEROUS CASE. Exit 0, claim success, record nothing. A
		 * caller that trusts the exit code reports enforcement for
		 * traffic that is not blocked.
		 */
		if (fake_mode == FAKE_SILENT_DROP) {
			snprintf(out, out_len, "1 addresses added.");
			return 0;
		}
		/* honest: append every element handed to us, from the verb on */
		for (i = vi + 1; argv[i]; i++) {
			if (strlen(fake_table) + strlen(argv[i]) + 2 >=
			    sizeof fake_table)
				break;
			if (fake_table[0])
				strcat(fake_table, "\n");
			strcat(fake_table, argv[i]);
		}
		snprintf(out, out_len, "%d addresses added.", i - (vi + 1));
		return 0;
	}

	/* pfctl -T flush -t <table> */
	if (verb && strcmp(verb, "flush") == 0) {
		if (fake_mode != FAKE_FLUSH_NOOP)
			fake_table[0] = '\0';
		snprintf(out, out_len, "0 addresses deleted.");
		return 0;
	}

	if (out_len > 0)
		out[0] = '\0';
	return 0;
}

/* ------------------------------------------------------------- scaffolding */

static struct pf_apply_ctx ctx;

static struct locdec_block mk_block(const char *addr)
{
	struct locdec_block b;
	struct pf_elem e;

	memset(&b, 0, sizeof b);
	if (pf_elem_parse(addr, 0, &e) != PF_OK) {
		fprintf(stderr, "test bug: bad addr %s\n", addr);
		exit(2);
	}
	b.elem = e;
	snprintf(b.app_tag, sizeof b.app_tag, "youtube");
	snprintf(b.host_snip, sizeof b.host_snip, "youtube.com");
	return b;
}

int main(void)
{
	struct locef_stats st;
	char line[256];
	struct locdec_block blk[4];
	size_t n;

	printf("=== enforcement bridge: does pf actually hold it? ===\n\n");

	pf_apply_ctx_init(&ctx, fake_exec, NULL);

	/* ---------- the honest path confirms ---------- */
	{
		fake_mode = FAKE_HONEST;
		fake_table[0] = '\0';
		fake_exec_calls = 0;

		blk[0] = mk_block("203.0.113.10/32");
		blk[1] = mk_block("203.0.113.20/32");

		CHECK(locef_apply(&ctx, "aisense_local4", blk, 2, true, true,
		                  &st) == true,
		      "an honest pf: the batch is applied and confirmed");
		CHECK(st.attempted == 2 && st.confirmed == 2 && st.failed == 0,
		      "attempted=2 confirmed=2 failed=0 (got %u/%u/%u)",
		      st.attempted, st.confirmed, st.failed);

		locef_stats_line(&st, line, sizeof line);
		CHECK(strstr(line, "ENFORCING") != NULL,
		      "and the stats line says ENFORCING: %s", line);
	}

	/* ---------- A SILENT DROP MUST NOT BE REPORTED AS ENFORCED ---------- */
	{
		fake_mode = FAKE_SILENT_DROP;
		fake_table[0] = '\0';
		fake_exec_calls = 0;

		blk[0] = mk_block("203.0.113.99/32");

		/*
		 * pfctl exits 0 and prints "1 addresses added." while the table
		 * stays empty. This is the exact shape of the bug this module
		 * exists to catch.
		 */
		CHECK(locef_apply(&ctx, "aisense_local4", blk, 1, true, true,
		                  &st) == false,
		      "a pfctl that exits 0 but stores NOTHING is reported as "
		      "FAILED, not as success");
		CHECK(st.confirmed == 0,
		      "confirmed stays 0 (got %u) -- the exit code alone would "
		      "have said 1", st.confirmed);
		CHECK(st.failed == 1,
		      "and the element is counted as failed");

		locef_stats_line(&st, line, sizeof line);
		CHECK(strstr(line, "ENFORCING") == NULL,
		      "the stats line does NOT claim enforcement: %s", line);
		/*
		 * The state word must not CONTAIN "ENFORCING", or the routine
		 * operator check (grep for enforcement) answers yes for a
		 * firewall that is blocking nothing.
		 */
		CHECK(strstr(line, "DEGRADED") != NULL,
		      "it says DEGRADED, which is the honest reading");
		CHECK(fake_exec_calls >= 2,
		      "and it took the read-back to find that out (%d calls)",
		      fake_exec_calls);
	}

	/* ---------- elements present but NO rule reads the table ---------- */
	{
		fake_mode = FAKE_NO_RULE;
		fake_table[0] = '\0';
		fake_exec_calls = 0;

		blk[0] = mk_block("203.0.113.30/32");

		/*
		 * The table is populated. The elements are all there. And
		 * nothing blocks, because no rule references the table.
		 *
		 * This is the most dangerous false positive available: every
		 * obvious check (`-T show` lists the address; pfctl exit 0)
		 * says success, and an operator who ran
		 * `pfctl -s rules | grep -c '<aisense_local4>'` would find 0.
		 */
		CHECK(locef_apply(&ctx, "aisense_local4", blk, 1, true, true,
		                  &st) == false,
		      "elements in an UNREFERENCED table is FAILED -- a listed "
		      "address is not a blocked address");
		CHECK(st.confirmed == 0,
		      "confirmed=0 (got %u) even though the element is present "
		      "in the table", st.confirmed);
	}

	/* ---------- the table disappeared under us ---------- */
	{
		fake_mode = FAKE_TABLE_GONE;
		fake_table[0] = '\0';

		blk[0] = mk_block("203.0.113.40/32");

		CHECK(locef_apply(&ctx, "aisense_local4", blk, 1, true, true,
		                  &st) == false,
		      "an unreadable/nonexistent table is FAILED, not assumed "
		      "fine");
		CHECK(st.confirmed == 0, "confirmed=0");
	}

	/* ---------- an add that fails outright ---------- */
	{
		fake_mode = FAKE_ADD_FAIL;
		fake_table[0] = '\0';

		blk[0] = mk_block("203.0.113.50/32");

		CHECK(locef_apply(&ctx, "aisense_local4", blk, 1, true, true,
		                  &st) == false,
		      "a non-zero pfctl is FAILED");
		CHECK(st.failed == 1 && st.confirmed == 0,
		      "counted as failed, not confirmed");
	}

	/* ---------- OBSERVE MODE MUST NOT RUN pfctl AT ALL ---------- */
	{
		fake_mode = FAKE_HONEST;
		fake_table[0] = '\0';
		fake_exec_calls = 0;

		blk[0] = mk_block("203.0.113.60/32");

		CHECK(locef_apply(&ctx, "aisense_local4", blk, 1, false, true,
		                  &st) == true,
		      "observe mode returns true (declining to act is correct)");
		CHECK(fake_exec_calls == 0,
		      "and executed NO pfctl command whatsoever (%d calls)",
		      fake_exec_calls);
		CHECK(st.attempted == 0 && st.confirmed == 0,
		      "with attempted/confirmed both 0, so no enforcement claim "
		      "can be built from it");
		CHECK(fake_table[0] == '\0', "and the table is untouched");
	}

	/* ---------- the weak (unverified) path never claims confirmation --- */
	{
		fake_mode = FAKE_HONEST;
		fake_table[0] = '\0';

		blk[0] = mk_block("203.0.113.70/32");

		CHECK(locef_apply(&ctx, "aisense_local4", blk, 1, true, false,
		                  &st) == true,
		      "an unverified apply reports success from the exit code");
		CHECK(st.attempted == 1, "attempted=1");
		CHECK(st.confirmed == 0,
		      "but confirmed is 0 (got %u) -- an unverified apply can "
		      "NEVER be read as verified", st.confirmed);
		locef_stats_line(&st, line, sizeof line);
		CHECK(strstr(line, "ENFORCING") == NULL,
		      "so it does not say ENFORCING either: %s", line);
	}

	/* ---------- flush, confirmed by reading back ---------- */
	{
		fake_mode = FAKE_HONEST;
		snprintf(fake_table, sizeof fake_table, "203.0.113.1\n203.0.113.2");

		CHECK(locef_flush(&ctx, "aisense_local4", &st) == true,
		      "a real flush is confirmed");
		CHECK(st.flushed == 1 && st.flush_failed == 0,
		      "and reported as flushed");
		CHECK(fake_table[0] == '\0', "the table really is empty");
	}

	/* ---------- a flush that does nothing must NOT be reported as done -- */
	{
		fake_mode = FAKE_FLUSH_NOOP;
		snprintf(fake_table, sizeof fake_table, "203.0.113.1\n203.0.113.2");

		/*
		 * `pfctl -T flush` exits 0 and leaves the table intact. This is
		 * the shape of the measured `pfctl -F tables` trap (which fails
		 * outright) generalised to any no-op flush: the only way to know
		 * is to read the table afterwards.
		 */
		CHECK(locef_flush(&ctx, "aisense_local4", &st) == false,
		      "a flush that removed NOTHING is reported as failed");
		CHECK(st.flush_failed == 1 && st.flushed == 0,
		      "flush_failed=1 flushed=0");
		CHECK(fake_table[0] != '\0',
		      "the table still has content, which is why it was caught");
	}

	/* ---------- argument validation ---------- */
	{
		CHECK(locef_apply(NULL, "t", blk, 1, true, true, &st) == false,
		      "a NULL ctx is refused");
		CHECK(locef_apply(&ctx, NULL, blk, 1, true, true, &st) == false,
		      "a NULL table is refused");
		CHECK(locef_apply(&ctx, "t", NULL, 1, true, true, &st) == false,
		      "a NULL block array is refused");
		CHECK(locef_apply(&ctx, "t", blk, 1, true, true, NULL) == false,
		      "a NULL stats output is refused");
		CHECK(locef_flush(&ctx, NULL, &st) == false,
		      "flush refuses a NULL table");
	}

	/* ---------- an empty batch is not a failure ---------- */
	{
		fake_mode = FAKE_HONEST;
		n = 0;
		CHECK(locef_apply(&ctx, "aisense_local4", blk, n, true, true,
		                  &st) == true,
		      "an empty batch returns true and attempts nothing");
		CHECK(st.attempted == 0, "attempted=0");
		locef_stats_line(&st, line, sizeof line);
		CHECK(strstr(line, "idle") != NULL,
		      "and reads as idle rather than as enforcement: %s", line);
	}

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
