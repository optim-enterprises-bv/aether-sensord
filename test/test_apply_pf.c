/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Host tests for pf application and verification.
 *
 * The headline case is the one ADR-017 names: a write that returns 0 while the
 * element is not in the table. `pfctl -T add` exiting 0 means pfctl parsed an
 * argument list. Every test here that matters is about not confusing that with
 * enforcement.
 *
 * The exec seam is injected, so all of it runs without pf, root or a firewall --
 * and a fake that ACKNOWLEDGES a write while not performing it is trivially
 * expressible, which is precisely how the real failure looks.
 */

#include "../src/apply_pf.h"
#include "../src/feed_pf.h"

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

/* ---------------------------------------------------------- fake pfctl --- */

/*
 * A fake pfctl that records the argv it was handed and can be told to lie: it
 * returns success without holding the elements. That is the exact behaviour the
 * verification step has to catch.
 */
struct fake {
	/* What the next call returns. */
	int status;
	/* What `-T show` prints, when the fake is not tracking adds. */
	const char *show_output;
	/* When true, an `add` reports success but does not change the contents:
	 * "it said it worked". */
	bool add_is_a_noop;
	/* Set once an add has been recorded, so `show` reads the live contents
	 * rather than the initial string. */
	bool mutable_show;
	char buf[4096];
	size_t buf_used;
	/* The MAIN ruleset, as `pfctl -s rules` prints it. Verification requires
	 * a `<table>` reference here, because `-T add` silently creates an
	 * undeclared table -- so a populated table alone proves nothing. */
	const char *ruleset;
	int ruleset_status;
	/* Captured argv, to prove elements arrive as separate arguments. */
	char seen[32][128];
	size_t n_seen;
	size_t last_argc;
};

static int fake_exec(const char *argv0, const char *const *argv, char *out,
                     size_t out_len, void *ctx)
{
	struct fake *f = ctx;
	size_t argc = 0;
	const char *verb = NULL;

	(void)argv0;
	f->n_seen = 0;
	for (size_t i = 0; argv[i]; i++) {
		argc++;
		if (i < 32 && f->n_seen < 32) {
			snprintf(f->seen[f->n_seen], sizeof(f->seen[0]), "%s",
			         argv[i]);
			f->n_seen++;
		}
	}
	f->last_argc = argc;

	/* argv[4] is the verb in our layout: pfctl -t T -T <verb> ... */
	if (argc >= 5)
		verb = argv[4];

	if (out && out_len)
		out[0] = '\0';

	/* `pfctl -s rules`: argv is { pfctl, -s, rules }. */
	if (argc == 3 && strcmp(argv[1], "-s") == 0 &&
	    strcmp(argv[2], "rules") == 0) {
		if (out && out_len && f->ruleset)
			snprintf(out, out_len, "%s", f->ruleset);
		return f->ruleset_status;
	}

	if (verb && strcmp(verb, "show") == 0) {
		if (f->mutable_show && f->buf_used < sizeof(f->buf) - 1) {
			f->buf[f->buf_used] = '\0';
			if (out && out_len)
				snprintf(out, out_len, "%s", f->buf);
		} else if (out && out_len) {
			snprintf(out, out_len, "%s", f->show_output);
		}
		return f->status == -1 ? -1 : f->status;
	}

	if (verb && strcmp(verb, "add") == 0 && !f->add_is_a_noop &&
	    f->status == 0) {
		/* A working pf: append what was added to the mutable buffer. */
		f->mutable_show = true;
		for (size_t i = 5; argv[i]; i++) {
			size_t need = strlen(argv[i]) + 1;
			if (f->buf_used + need >= sizeof(f->buf))
				break;
			memcpy(f->buf + f->buf_used, argv[i], strlen(argv[i]));
			f->buf_used += strlen(argv[i]);
			f->buf[f->buf_used++] = '\n';
		}
	}

	if (out && out_len && f->status != 0)
		snprintf(out, out_len, "%s", f->show_output);

	return f->status;
}

static void fake_init(struct fake *f)
{
	memset(f, 0, sizeof(*f));
	f->status = 0;
	f->show_output = "";
	f->add_is_a_noop = false;
	/*
	 * A ruleset that REFERENCES the table, because that is the normal state a
	 * correct deployment is in and the default must not make every test fail.
	 * Tests that care about the unreferenced case set this themselves.
	 */
	f->ruleset = "block drop quick from <aisense_rep4> to any\npass all\n";
	f->ruleset_status = 0;
}

/* -------------------------------------------------------- table names --- */

static void test_table_name_validation(void)
{
	CHECK(pf_table_name_ok("aisense_rep4"), "a normal name is fine");
	CHECK(pf_table_name_ok("a"), "single character");
	CHECK(pf_table_name_ok("A_9"), "upper, digit, underscore");

	CHECK(!pf_table_name_ok(NULL), "NULL");
	CHECK(!pf_table_name_ok(""), "empty");
	CHECK(!pf_table_name_ok("-T"), "leading dash would be read as an option");
	CHECK(!pf_table_name_ok("-t"), "lowercase flag form");
	CHECK(!pf_table_name_ok("a b"), "space");
	CHECK(!pf_table_name_ok("a;b"), "semicolon");
	CHECK(!pf_table_name_ok("a\nb"), "newline");
	CHECK(!pf_table_name_ok("a/b"), "slash");
	CHECK(!pf_table_name_ok("a$(id)"), "command substitution");
	CHECK(!pf_table_name_ok("../../etc/passwd"), "path traversal");

	{
		char long_name[200];
		memset(long_name, 'a', sizeof(long_name) - 1);
		long_name[sizeof(long_name) - 1] = '\0';
		CHECK(!pf_table_name_ok(long_name), "over-long name");
	}
}

/* ------------------------------------------------------- argv plumbing --- */

static void test_elements_arrive_as_separate_argv_entries(void)
{
	/*
	 * The structural protection. If elements were ever concatenated into one
	 * argument, a crafted prefix could inject additional pfctl arguments.
	 * Assert that each element occupies its own argv slot.
	 */
	struct fake f;
	struct pf_apply_ctx c;
	struct pf_elem e[3];
	char err[256];

	fake_init(&f);
	pf_apply_ctx_init(&c, fake_exec, &f);

	CHECK(pf_elem_parse("192.0.2.0/24", 0, &e[0]) == PF_OK, "p1");
	CHECK(pf_elem_parse("198.51.100.0/24", 0, &e[1]) == PF_OK, "p2");
	CHECK(pf_elem_parse("203.0.113.0/24", 0, &e[2]) == PF_OK, "p3");

	CHECK(pf_apply_add(&c, "aisense_rep4", e, 3, err, sizeof(err)) == PF_APPLY_OK,
	      "add succeeds");
	/* 5 fixed + 3 elements. */
	CHECK(f.last_argc == 8, "argc is 5 fixed + 3 elements");
	CHECK(strcmp(f.seen[0], PF_APPLY_DEFAULT_PATH) == 0, "argv0 is pfctl");
	CHECK(strcmp(f.seen[1], "-t") == 0, "argv1 is -t");
	CHECK(strcmp(f.seen[2], "aisense_rep4") == 0, "argv2 is the table");
	CHECK(strcmp(f.seen[3], "-T") == 0, "argv3 is -T");
	CHECK(strcmp(f.seen[4], "add") == 0, "argv4 is the verb");
	CHECK(strcmp(f.seen[5], "192.0.2.0/24") == 0, "argv5 is element 1");
	CHECK(strcmp(f.seen[6], "198.51.100.0/24") == 0, "argv6 is element 2");
	CHECK(strcmp(f.seen[7], "203.0.113.0/24") == 0, "argv7 is element 3");
}

static void test_delete_uses_the_delete_verb(void)
{
	struct fake f;
	struct pf_apply_ctx c;
	struct pf_elem e;
	char err[256];

	fake_init(&f);
	pf_apply_ctx_init(&c, fake_exec, &f);
	CHECK(pf_elem_parse("192.0.2.0/24", 0, &e) == PF_OK, "p");
	CHECK(pf_apply_del(&c, "aisense_rep4", &e, 1, err, sizeof(err)) == PF_APPLY_OK,
	      "delete succeeds");
	CHECK(strcmp(f.seen[4], "delete") == 0, "verb is delete");
}

/* -------------------------------------------------- the critical case --- */

static void test_auto_created_table_is_not_enforcement(void)
{
	/*
	 * THE DISCOVERY. Measured on FreeBSD 16.0: `pfctl -t <undeclared> -T add`
	 * does not fail -- it CREATES the table and returns success ("1 table
	 * created.").
	 *
	 * So a batch can succeed, every element can be present, membership can
	 * all pass, and NO RULE REFERENCES THE TABLE, so not one packet will be
	 * dropped. A verification that stopped at "the elements are there" would
	 * report enforcement here. That is the silent-degradation shape this
	 * whole project exists to catch, and it is reachable through the normal
	 * write path rather than by a mistake.
	 */
	struct fake f;
	struct pf_apply_ctx c;
	struct pf_elem e;
	char err[512];

	fake_init(&f);
	f.status = 0;              /* the add succeeds... */
	f.add_is_a_noop = false;   /* ...and the element really lands */
	f.ruleset = "pass all\npass quick on lo0\n"; /* but nothing refers to it */

	pf_apply_ctx_init(&c, fake_exec, &f);
	CHECK(pf_elem_parse("192.0.2.0/24", 0, &e) == PF_OK, "p");

	CHECK(!pf_apply_and_verify(&c, "aisense_rep4", &e, 1, err, sizeof(err)),
	      "a populated but unreferenced table must NOT verify");
	CHECK(c.unreferenced_tables == 1, "counted as unreferenced, not as a mismatch");
	CHECK(c.verify_mismatches == 0, "the element DID land -- that is not the fault");
	CHECK(strstr(err, "NO RULE") != NULL, "the error names the real problem");
	CHECK(strstr(err, "static alias") != NULL,
	      "and tells the operator the actual fix");
}

static void test_an_unreadable_ruleset_is_not_a_pass(void)
{
	/* "I could not check" must never read as "it works". */
	struct fake f;
	struct pf_apply_ctx c;
	struct pf_elem e;
	char err[256];

	fake_init(&f);
	f.ruleset_status = 1; /* pfctl -s rules fails */

	pf_apply_ctx_init(&c, fake_exec, &f);
	CHECK(pf_elem_parse("192.0.2.0/24", 0, &e) == PF_OK, "p");

	CHECK(!pf_apply_and_verify(&c, "aisense_rep4", &e, 1, err, sizeof(err)),
	      "an unreadable ruleset is not a pass");
	CHECK(strstr(err, "cannot read") != NULL, "the error says why");
}

static void test_ruleset_reference_matching(void)
{
	CHECK(pf_apply_ruleset_references(
	          "block drop quick from <aisense_rep4> to any\n", "aisense_rep4"),
	      "a referenced table is detected");
	CHECK(!pf_apply_ruleset_references("pass all\n", "aisense_rep4"),
	      "an unreferenced table is not detected");
	CHECK(!pf_apply_ruleset_references("anchor \"aisense\" all\n",
	                                   "aisense_rep4"),
	      "an anchor CALL is not a table reference");
	CHECK(!pf_apply_ruleset_references(
	          "block drop from <aisense_rep4_backup> to any\n", "aisense_rep4"),
	      "a longer name does not satisfy a shorter search");
	CHECK(pf_apply_ruleset_references(
	          "block drop from <aisense_rep4> to any\n", "aisense_rep4"),
	      "exact match with a trailing space");
	CHECK(pf_apply_ruleset_references("from <aisense_rep4>, <x>\n", "aisense_rep4"),
	      "followed by a comma");
	CHECK(pf_apply_ruleset_references("from <aisense_rep4>", "aisense_rep4"),
	      "at end of string");
	CHECK(!pf_apply_ruleset_references(NULL, "aisense_rep4"), "NULL ruleset");
	CHECK(!pf_apply_ruleset_references("pass all\n", NULL), "NULL table");
	CHECK(!pf_apply_ruleset_references("pass all\n", ""), "empty table");
}

static void test_apply_that_lies_is_caught(void)
{
	/*
	 * The whole point. pfctl returns success and the element is NOT in the
	 * table. A caller that trusted the exit status would report enforcement;
	 * verification must fail.
	 */
	struct fake f;
	struct pf_apply_ctx c;
	struct pf_elem e;
	char err[256];

	fake_init(&f);
	f.status = 0;              /* success */
	f.add_is_a_noop = true;    /* but nothing is added */
	f.show_output = "";        /* table stays empty */
	pf_apply_ctx_init(&c, fake_exec, &f);

	CHECK(pf_elem_parse("192.0.2.0/24", 0, &e) == PF_OK, "p");

	CHECK(pf_apply_add(&c, "aisense_rep4", &e, 1, err, sizeof(err)) ==
	      PF_APPLY_OK,
	      "the write itself reports success -- that is the trap");

	CHECK(!pf_apply_and_verify(&c, "aisense_rep4", &e, 1, err, sizeof(err)),
	      "verification must FAIL when the element did not land");
	CHECK(c.verify_mismatches == 1, "the mismatch is counted");
	CHECK(strstr(err, "not present") != NULL, "the error names the element");
}

static void test_verify_passes_only_when_the_element_is_present(void)
{
	struct fake f;
	struct pf_apply_ctx c;
	struct pf_elem e;
	char err[256];

	fake_init(&f);
	f.status = 0;
	pf_apply_ctx_init(&c, fake_exec, &f);
	CHECK(pf_elem_parse("192.0.2.0/24", 0, &e) == PF_OK, "p");

	CHECK(pf_apply_and_verify(&c, "aisense_rep4", &e, 1, err, sizeof(err)),
	      "verify passes when the element landed");
	CHECK(strstr(f.buf, "192.0.2.0/24") != NULL, "the fake recorded it");
	CHECK(c.applied_batches == 1, "batch counted");
	CHECK(c.verify_mismatches == 0, "no mismatch");
}

static void test_verify_checks_the_RIGHT_address_not_just_a_count(void)
{
	/*
	 * The reason membership is checked rather than a count. The table holds
	 * ONE entry, so any count-based check passes -- but it is a different
	 * address. Count is right, content is wrong, and only membership can
	 * tell them apart.
	 */
	struct fake f;
	struct pf_apply_ctx c;
	struct pf_elem e;
	char err[256];

	fake_init(&f);
	f.status = 0;
	f.add_is_a_noop = true;              /* the write does not take effect */
	f.show_output = "198.51.100.0/24\n"; /* the table holds a different entry */
	pf_apply_ctx_init(&c, fake_exec, &f);
	CHECK(pf_elem_parse("192.0.2.0/24", 0, &e) == PF_OK, "p");

	CHECK(!pf_apply_and_verify(&c, "aisense_rep4", &e, 1, err, sizeof(err)),
	      "a same-sized table with the wrong address must not verify");
}

static void test_missing_table_is_unavailable_not_a_retry(void)
{
	/*
	 * `pfctl -t <undeclared> -T add` fails with "Table does not exist". That
	 * is not a transient failure and not a malformed feed entry -- it means
	 * the OPNsense static alias was never registered, so it is reported
	 * distinctly and counted separately.
	 */
	struct fake f;
	struct pf_apply_ctx c;
	struct pf_elem e;
	char err[256];

	fake_init(&f);
	f.status = 3;
	f.show_output = "pfctl: Table does not exist.\n";
	pf_apply_ctx_init(&c, fake_exec, &f);
	CHECK(pf_elem_parse("192.0.2.0/24", 0, &e) == PF_OK, "p");

	CHECK(pf_apply_add(&c, "aisense_rep4", &e, 1, err, sizeof(err)) ==
	      PF_APPLY_UNAVAILABLE, "missing table is UNAVAILABLE");
	CHECK(c.missing_table == 1, "counted separately from other failures");
}

static void test_pfctl_absent_is_unavailable(void)
{
	struct fake f;
	struct pf_apply_ctx c;
	struct pf_elem e;
	char err[256];

	fake_init(&f);
	f.status = -1; /* could not be run at all */
	f.show_output = "no such file";
	pf_apply_ctx_init(&c, fake_exec, &f);
	CHECK(pf_elem_parse("192.0.2.0/24", 0, &e) == PF_OK, "p");

	CHECK(pf_apply_add(&c, "aisense_rep4", &e, 1, err, sizeof(err)) ==
	      PF_APPLY_UNAVAILABLE,
	      "an unrunnable pfctl is UNAVAILABLE, not a rejection");
}

static void test_a_rejection_is_a_rejection(void)
{
	struct fake f;
	struct pf_apply_ctx c;
	struct pf_elem e;
	char err[256];

	fake_init(&f);
	f.status = 1;
	f.show_output = "pfctl: syntax error\n";
	pf_apply_ctx_init(&c, fake_exec, &f);
	CHECK(pf_elem_parse("192.0.2.0/24", 0, &e) == PF_OK, "p");

	CHECK(pf_apply_add(&c, "aisense_rep4", &e, 1, err, sizeof(err)) ==
	      PF_APPLY_REJECTED, "a genuine refusal is REJECTED");
	CHECK(strstr(err, "syntax error") != NULL, "pfctl output is surfaced");
}

static void test_bad_table_name_never_reaches_pfctl(void)
{
	struct fake f;
	struct pf_apply_ctx c;
	struct pf_elem e;
	char err[256];

	fake_init(&f);
	pf_apply_ctx_init(&c, fake_exec, &f);
	CHECK(pf_elem_parse("192.0.2.0/24", 0, &e) == PF_OK, "p");

	CHECK(pf_apply_add(&c, "-T", &e, 1, err, sizeof(err)) == PF_APPLY_BAD_TABLE,
	      "an option-shaped table name is refused");
	CHECK(f.last_argc == 0, "pfctl was never invoked");
}

static void test_show_signals_an_absent_table(void)
{
	struct fake f;
	struct pf_apply_ctx c;
	char buf[256];

	fake_init(&f);
	f.status = 3;
	f.show_output = "pfctl: Table does not exist.\n";
	pf_apply_ctx_init(&c, fake_exec, &f);

	CHECK(pf_apply_show(&c, "aisense_rep4", buf, sizeof(buf)) == -1,
	      "reading an absent table is -1, not an empty listing");

	fake_init(&f);
	f.status = 0;
	f.show_output = "";
	pf_apply_ctx_init(&c, fake_exec, &f);
	CHECK(pf_apply_show(&c, "aisense_rep4", buf, sizeof(buf)) == 0,
	      "an empty EXISTING table is 0 bytes, not -1");
}

/* ----------------------------------------------------- membership --- */

static void test_membership_matching(void)
{
	struct pf_elem e, other;

	CHECK(pf_elem_parse("192.0.2.0/24", 0, &e) == PF_OK, "p");
	CHECK(pf_elem_parse("198.51.100.0/24", 0, &other) == PF_OK, "p2");

	CHECK(pf_table_lists_elem("192.0.2.0/24\n", &e), "single line");
	CHECK(pf_table_lists_elem("198.51.100.0/24\n192.0.2.0/24\n", &e),
	      "among several lines");
	CHECK(pf_table_lists_elem("  192.0.2.0/24  \n", &e), "surrounded by space");
	CHECK(!pf_table_lists_elem("198.51.100.0/24\n", &e), "absent");
	CHECK(!pf_table_lists_elem("", &e), "empty listing");
	CHECK(!pf_table_lists_elem(NULL, &e), "NULL listing");

	/* Same address, different prefix, must NOT match: /24 and /25 cover
	 * different address sets and treating them as equal would verify a
	 * policy the operator did not ask for. */
	CHECK(!pf_table_lists_elem("192.0.2.0/25\n", &e), "prefix must match");

	/*
	 * pf prints plain CIDR (measured on FreeBSD 16.0), so the address+prefix
	 * form is what verification must match.
	 */
	CHECK(pf_table_lists_elem("192.0.2.0/24\n", &e),
	      "the CIDR form pf actually prints is recognised");

	/*
	 * The `start - end` form is accepted as well even though pf does not
	 * emit it: it costs nothing, and if a future pf or an OPNsense wrapper
	 * prints ranges, verification keeps working instead of silently
	 * reporting every prefix as missing.
	 *
	 * Tested with a HOST element, which a range's start matches exactly.
	 * The range form does not make a CIDR element findable: matching
	 * `192.0.2.0/24` inside `192.0.2.0 - 192.0.2.255` would need prefix
	 * containment, which pf never requires of a caller because it never
	 * prints that form. Asserting containment here would be testing a
	 * capability nothing uses.
	 */
	{
		struct pf_elem host;
		CHECK(pf_elem_parse("192.0.2.0", 0, &host) == PF_OK, "host parse");
		CHECK(pf_table_lists_elem("192.0.2.0 - 192.0.2.255\n", &host),
		      "a host at a range's start is recognised");
	}
}

static void test_membership_does_not_confuse_v4_and_v6(void)
{
	struct pf_elem v4, v6;
	CHECK(pf_elem_parse("192.0.2.0/24", 0, &v4) == PF_OK, "v4");
	CHECK(pf_elem_parse("2001:db8::/48", 0, &v6) == PF_OK, "v6");

	CHECK(!pf_table_lists_elem("2001:db8::/48\n", &v4),
	      "a v6 entry does not satisfy a v4 lookup");
	CHECK(!pf_table_lists_elem("192.0.2.0/24\n", &v6),
	      "a v4 entry does not satisfy a v6 lookup");
	CHECK(pf_table_lists_elem("192.0.2.0/24\n2001:db8::/48\n", &v6),
	      "matching v6 among mixed entries");
}

/* --------------------------------------------------- the pf adapter --- */

static void test_pf_adapter_admits_the_element_and_records_the_gap(void)
{
	/*
	 * The capability difference must not become a loss of function. If the
	 * adapter rejected every element that carries a timeout, the firewall
	 * would block nothing while looking correctly configured.
	 */
	struct pf_elem e;
	CHECK(pf_elem_parse("192.0.2.0/24", 0, &e) == PF_OK, "parse");
	CHECK(feed_elem_set_timeout(&e, FEED_ELEM_TIMEOUT) == 0,
	      "the element is admitted, not refused");
	CHECK(e.timeout_sec == FEED_ELEM_TIMEOUT, "the timeout is carried");
	CHECK(e.timeout_unrepresentable,
	      "and pf is said plainly not to be able to honour per-element decay");

	/* With no timeout there is no gap to report. */
	CHECK(pf_elem_parse("192.0.2.0/24", 0, &e) == PF_OK, "parse");
	CHECK(feed_elem_set_timeout(&e, 0) == 0, "zero timeout is fine");
	CHECK(!e.timeout_unrepresentable, "zero means nothing to represent");
}

static void test_degenerate_inputs(void)
{
	struct fake f;
	struct pf_apply_ctx c;
	struct pf_elem e;
	char err[64];

	fake_init(&f);
	pf_apply_ctx_init(&c, fake_exec, &f);

	CHECK(pf_elem_parse("192.0.2.0/24", 0, &e) == PF_OK, "p");
	CHECK(pf_apply_add(NULL, "t", &e, 1, err, sizeof(err)) == PF_APPLY_UNAVAILABLE,
	      "NULL ctx");
	CHECK(pf_apply_add(&c, "t", NULL, 1, err, sizeof(err)) == PF_APPLY_REJECTED,
	      "NULL elements");

	/* An exec seam that was never installed must not be called, and must
	 * report as unavailable rather than as a rejection. */
	{
		struct pf_apply_ctx noc;
		pf_apply_ctx_init(&noc, NULL, NULL);
		CHECK(pf_apply_add(&noc, "t", &e, 1, err, sizeof(err)) ==
		      PF_APPLY_UNAVAILABLE, "NULL exec");
	}

	CHECK(pf_table_lists_elem("x", NULL) == false, "NULL elem");
	CHECK(pf_table_lists_elem(NULL, &e) == false, "NULL listing");
}

int main(void)
{
	test_table_name_validation();
	test_elements_arrive_as_separate_argv_entries();
	test_delete_uses_the_delete_verb();
	test_auto_created_table_is_not_enforcement();
	test_an_unreadable_ruleset_is_not_a_pass();
	test_ruleset_reference_matching();
	test_apply_that_lies_is_caught();
	test_verify_passes_only_when_the_element_is_present();
	test_verify_checks_the_RIGHT_address_not_just_a_count();
	test_missing_table_is_unavailable_not_a_retry();
	test_pfctl_absent_is_unavailable();
	test_a_rejection_is_a_rejection();
	test_bad_table_name_never_reaches_pfctl();
	test_show_signals_an_absent_table();
	test_membership_matching();
	test_membership_does_not_confuse_v4_and_v6();
	test_pf_adapter_admits_the_element_and_records_the_gap();
	test_degenerate_inputs();

	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
