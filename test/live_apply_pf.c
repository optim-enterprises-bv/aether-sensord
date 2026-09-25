/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Live integration test for pf application + verification, against a real pf.
 *
 * The host tests inject a fake exec so they can simulate a write that lies. This
 * runs the REAL exec (pf_apply_exec_posix) against the real pfctl, because the
 * two things a fake cannot establish are: (1) that argv is built correctly enough
 * for pfctl to accept, and (2) that the membership check matches what pfctl
 * actually prints -- which was measured wrong once already.
 *
 * FreeBSD-only: exits 0 with a clear message elsewhere so a Linux run does not
 * report a false failure.
 *
 * Usage: live_apply_pf <table>
 */

#include "../src/apply_pf.h"

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

int main(int argc, char **argv)
{
	const char *table = argc > 1 ? argv[1] : "aisense_rep4";
	struct pf_apply_ctx c;
	struct pf_elem elems[3];
	char err[512];
	char listing[8192];

#if !defined(__FreeBSD__)
	printf("skipped: pfctl is FreeBSD-only\n");
	return 0;
#else
	pf_apply_ctx_init(&c, pf_apply_exec_posix, NULL);

	CHECK(pf_elem_parse("192.0.2.0/24", 0, &elems[0]) == PF_OK, "p1");
	CHECK(pf_elem_parse("198.51.100.0/24", 0, &elems[1]) == PF_OK, "p2");
	CHECK(pf_elem_parse("203.0.113.128/25", 0, &elems[2]) == PF_OK, "p3");

	/* The table auto-creates, so this is APPLY_OK -- which is exactly why the
	 * caller cannot rely on the write to tell it the declaration is missing.
	 * The comment documents the measured behaviour rather than asserting a
	 * verdict we would like to be true. */
	{
		enum pf_apply_result ra = pf_apply_add(&c, "aisense_live_nonexistent",
		                                      elems, 1, err, sizeof(err));
		printf("  undeclared table add -> %s (pfctl: %s)\n",
		       pf_apply_result_str(ra), err[0] ? err : "no message");
		CHECK(ra == PF_APPLY_OK,
		      "pfctl CREATES an undeclared table, so the write reports OK");
	}

	/* And THIS is where the missing declaration is caught: the elements will
	 * be in the table and no rule will reference it. */
	{
		char err2[512];
		CHECK(!pf_apply_and_verify(&c, "aisense_live_nonexistent", elems, 1,
		                           err2, sizeof(err2)),
		      "verification catches the undeclared table the write accepted");
		printf("  verify says: %s\n", err2);
		CHECK(c.unreferenced_tables == 1, "counted as unreferenced");
	}

	/* Now the real thing. */
	if (pf_apply_and_verify(&c, table, elems, 3, err, sizeof(err))) {
		printf("  applied and verified 3 elements into %s\n", table);
	} else {
		printf("  apply/verify FAILED: %s\n", err);
	}
	/*
	 * Counted rather than asserted exactly: the number of accepted writes
	 * depends on how many adds this test performs, and pinning a literal here
	 * turns a change in the test into a failure that looks like a bug in the
	 * code under test. What matters is that writes were accepted AND the
	 * undeclared one was caught by verification rather than by the write.
	 */
	CHECK(c.applied_batches >= 1, "writes were accepted");
	CHECK(c.missing_table == 0,
	      "no write failed on a missing table -- pfctl creates it, which is "
	      "the whole reason verification must check the ruleset");
	CHECK(c.verify_mismatches == 0, "no verification mismatches");

	/* Read back independently of the apply path, and print it, so the format
	 * the membership check depends on is visible in the output. */
	if (pf_apply_show(&c, table, listing, sizeof(listing)) >= 0) {
		printf("  table now contains:\n");
		for (const char *p = listing; *p; ) {
			const char *nl = strchr(p, '\n');
			if (!nl)
				break;
			printf("    %.*s\n", (int)(nl - p), p);
			p = nl + 1;
		}
	} else {
		printf("  table unreadable\n");
	}

	/* Every element must be findable by the membership check. */
	for (size_t i = 0; i < 3; i++) {
		char text[PF_ELEM_TEXT_MAX];
		pf_elem_render(&elems[i], text, sizeof(text));
		CHECK(pf_table_lists_elem(listing, &elems[i]),
		      "element is present in the live table");
		printf("  found %s\n", text);
	}

	/* Deleting works through the same path. */
	CHECK(pf_apply_del(&c, table, &elems[0], 1, err, sizeof(err)) == PF_APPLY_OK,
	      "delete succeeds");
	if (pf_apply_show(&c, table, listing, sizeof(listing)) >= 0) {
		CHECK(!pf_table_lists_elem(listing, &elems[0]),
		      "the deleted element is gone");
		printf("  delete verified\n");
	}

	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
#endif
}
