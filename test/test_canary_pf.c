/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Host tests for the pf enforcement canary (FreeBSD/OPNsense port).
 *
 * The headline case is NOT_ENFORCED: a table that exists, holds the canary, and
 * that no rule refers to -- so nothing is ever dropped. That is the state this
 * whole mechanism exists to catch, it is what an anchor-based OPNsense plugin
 * produces by construction, and it is indistinguishable from success by every
 * signal except this one.
 *
 * The second theme is the pf-specific probe correction. On Linux the original
 * could read EPERM from sendto() as proof of a drop. pf does not report drops to
 * a sender at all (measured: sends=10 refused=0 against an enforcing table), so a
 * test asserts that a SILENT send is never taken as a verdict -- otherwise the
 * canary would libel a working firewall and the verdict would lose all meaning.
 *
 * Because pf_canary_classify() and pf_canary_table_referenced() are pure
 * functions, the whole taxonomy and the counter parsing are testable here with
 * no root, no pf and no firewall -- which the nftables original could not do,
 * and which is exactly the gap its comments blame for 624 passing tests over a
 * dead datapath.
 */

#include "../src/canary_pf.h"

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

static struct pf_canary_obs obs(bool exists, bool added, bool held,
                                bool probe, bool referenced, bool cleanup)
{
	struct pf_canary_obs o;
	o.table_exists = exists;
	o.add_accepted = added;
	o.held_in_table = held;
	o.probe_ran = probe;
	o.referenced_by_rule = referenced;
	o.cleanup_ok = cleanup;
	return o;
}

static void test_happy_path_is_the_only_pass(void)
{
	struct pf_canary_obs o = obs(true, true, true, true, true, true);
	CHECK(pf_canary_classify(&o) == PF_CANARY_ENFORCED, "enforced");
	CHECK(pf_canary_passed(PF_CANARY_ENFORCED), "enforced passes");
}

static void test_not_enforced_is_detected(void)
{
	/* THE case: table exists, holds the canary, probe ran -- and no rule
	 * refers to the table. Nothing errored. Every counter agrees. */
	struct pf_canary_obs o = obs(true, true, true, true, false, true);
	CHECK(pf_canary_classify(&o) == PF_CANARY_NOT_ENFORCED,
	      "held but unreferenced is NOT_ENFORCED");
	CHECK(!pf_canary_passed(PF_CANARY_NOT_ENFORCED),
	      "NOT_ENFORCED must not pass");
}

static void test_a_silent_send_is_never_a_verdict(void)
{
	/*
	 * The pf correction. A sent datagram that was silently discarded is the
	 * NORMAL case on pf, so it must not change the verdict in either
	 * direction: the same observation set yields enforced / not-enforced
	 * purely from the table-reference read.
	 */
	struct pf_canary_obs enforced = obs(true, true, true, true, true, true);
	struct pf_canary_obs dead = obs(true, true, true, true, false, true);
	CHECK(pf_canary_classify(&enforced) == PF_CANARY_ENFORCED,
	      "silent send + referenced table = enforced");
	CHECK(pf_canary_classify(&dead) == PF_CANARY_NOT_ENFORCED,
	      "silent send + unreferenced table = not enforced");
}

static void test_first_fault_wins(void)
{
	/* A missing table also makes everything after it fail; reporting the
	 * later symptom would send an operator to the wrong place. */
	struct pf_canary_obs a = obs(false, false, false, false, false, true);
	struct pf_canary_obs b = obs(true, false, false, false, false, true);
	struct pf_canary_obs c = obs(true, true, false, false, false, true);
	CHECK(pf_canary_classify(&a) == PF_CANARY_TABLE_MISSING,
	      "missing table reported first");
	CHECK(pf_canary_classify(&b) == PF_CANARY_ADD_REJECTED,
	      "add refused before the table listing");
	CHECK(pf_canary_classify(&c) == PF_CANARY_NOT_HELD,
	      "accepted but absent is NOT_HELD");
}

static void test_inconclusive_is_never_a_pass(void)
{
	/* A probe that could not run must not read as "it works". */
	struct pf_canary_obs o = obs(true, true, true, false, false, true);
	CHECK(pf_canary_classify(&o) == PF_CANARY_INCONCLUSIVE, "dead probe");
	CHECK(!pf_canary_passed(PF_CANARY_INCONCLUSIVE),
	      "INCONCLUSIVE must not pass");

	CHECK(pf_canary_classify(NULL) == PF_CANARY_INCONCLUSIVE, "NULL obs");
	CHECK(!pf_canary_passed(PF_CANARY_TABLE_MISSING), "missing not a pass");
	CHECK(!pf_canary_passed(PF_CANARY_ADD_REJECTED), "add rejected not a pass");
	CHECK(!pf_canary_passed(PF_CANARY_NOT_HELD), "not held not a pass");
	CHECK(!pf_canary_passed(PF_CANARY_CLEANUP_FAILED),
	      "cleanup failed not a pass");
}

static void test_cleanup_failure_is_reported_not_hidden(void)
{
	/* Enforcement genuinely worked, but the canary is still in a production
	 * table. Saying ENFORCED here would hide a real leak. */
	struct pf_canary_obs o = obs(true, true, true, true, true, false);
	CHECK(pf_canary_classify(&o) == PF_CANARY_CLEANUP_FAILED,
	      "leftover canary reported");
	CHECK(!pf_canary_passed(PF_CANARY_CLEANUP_FAILED),
	      "a leftover canary is not a clean pass");
}

/* ------------------------------------------- main ruleset references --- */

static void test_ruleset_reference_detection(void)
{
	/* The shape pf renders when a rule references a table. */
	static const char *enforcing =
		"block drop quick from <aisense_rep4> to any\npass all\n";
	static const char *not_enforcing =
		"pass all\npass quick on lo0\n";

	CHECK(pf_canary_ruleset_references(enforcing, "aisense_rep4"),
	      "a referenced table is detected");
	CHECK(!pf_canary_ruleset_references(not_enforcing, "aisense_rep4"),
	      "an unreferenced table is not detected");
	CHECK(!pf_canary_ruleset_references(enforcing, "other_table"),
	      "a different name is not detected");

	/* A rule that only mentions the name in a comment or as a bare word is
	 * not a reference: pf renders references in angle brackets. */
	CHECK(!pf_canary_ruleset_references("# see aisense_rep4 notes\npass all\n",
	                                    "aisense_rep4"),
	      "a bare name outside angle brackets is not a reference");
}

static void test_ruleset_scan_does_not_match_a_longer_name(void)
{
	/* `<aisense_rep4_backup>` must not satisfy a search for
	 * `aisense_rep4`, or a rule protecting a different table would be
	 * credited to ours. */
	static const char *longer =
		"block drop quick from <aisense_rep4_backup> to any\n";
	CHECK(!pf_canary_ruleset_references(longer, "aisense_rep4"),
	      "a longer table name does not satisfy a shorter search");
	CHECK(pf_canary_ruleset_references(longer, "aisense_rep4_backup"),
	      "the exact longer name does match");

	/* And the trailing-character discipline: separators pf uses. */
	CHECK(pf_canary_ruleset_references("from <aisense_rep4> to any\n", "aisense_rep4"),
	      "followed by a space");
	CHECK(pf_canary_ruleset_references("from <aisense_rep4>, <other>\n", "aisense_rep4"),
	      "followed by a comma");
	CHECK(pf_canary_ruleset_references("from <aisense_rep4>}\n", "aisense_rep4"),
	      "followed by a brace");
	CHECK(pf_canary_ruleset_references("from <aisense_rep4>", "aisense_rep4"),
	      "at end of string");
}

static void test_the_false_positive_this_guards_against(void)
{
	/*
	 * Reproduces the measured trap. `pfctl -vvsT` reported
	 *
	 *     References: [ Anchors: 1   Rules: 2 ]
	 *
	 * for a table that the MAIN ruleset referenced ZERO times -- the 2
	 * counted a rule inside an anchor nothing called. A canary reading that
	 * count would say ENFORCED on a firewall that blocks nothing, which is
	 * the worst possible error: fabricated protection.
	 *
	 * The main-ruleset text for that exact state:
	 */
	static const char *main_rules_with_stale_anchor =
		"anchor \"aisense\" all\n"   /* <- calls an anchor... */
		;

	/* Note: even the anchor CALL is not a table reference, so a table that
	 * lives only inside an anchor is correctly reported as unreferenced. */
	CHECK(!pf_canary_ruleset_references(main_rules_with_stale_anchor,
	                                    "aisense_rep4"),
	      "a table referenced only inside an anchor is NOT enforced");
	CHECK(!pf_canary_ruleset_references("pass all\n", "aisense_rep4"),
	      "measured dead state reports unreferenced");
}

static void test_ruleset_scan_handles_degenerate_input(void)
{
	CHECK(!pf_canary_ruleset_references(NULL, "aisense_rep4"), "NULL rules");
	CHECK(!pf_canary_ruleset_references("pass all\n", NULL), "NULL table");
	CHECK(!pf_canary_ruleset_references("pass all\n", ""), "empty table");
	CHECK(!pf_canary_ruleset_references("<> something\n", "aisense_rep4"),
	      "empty angle brackets");
}

static void test_tokens_match_the_controller_contract(void)
{
	/*
	 * These exact strings must stay in step with enum Verdict in
	 * aether-aegis::proof. There is no shared header to enforce it, so the
	 * contract is asserted here instead. A controller that received a novel
	 * token would treat the verdict as unusable and the whole fleet would
	 * read as "never reported".
	 */
	CHECK(strcmp(pf_canary_token(PF_CANARY_ENFORCED), "enforced") == 0, "enforced");
	CHECK(strcmp(pf_canary_token(PF_CANARY_TABLE_MISSING), "set_missing") == 0,
	      "set_missing (kept for wire compatibility)");
	CHECK(strcmp(pf_canary_token(PF_CANARY_ADD_REJECTED), "add_rejected") == 0,
	      "add_rejected");
	CHECK(strcmp(pf_canary_token(PF_CANARY_NOT_HELD), "not_held") == 0, "not_held");
	CHECK(strcmp(pf_canary_token(PF_CANARY_NOT_ENFORCED), "not_enforced") == 0,
	      "not_enforced");
	CHECK(strcmp(pf_canary_token(PF_CANARY_CLEANUP_FAILED), "cleanup_failed") == 0,
	      "cleanup_failed");
	CHECK(strcmp(pf_canary_token(PF_CANARY_INCONCLUSIVE), "inconclusive") == 0,
	      "inconclusive");
}

static void test_canary_address_is_documentation_space(void)
{
	/* A leftover canary must never block traffic a subscriber would miss. */
	CHECK(strcmp(pf_canary_addr(false), PF_CANARY_V4) == 0, "v4 canary");
	CHECK(strcmp(pf_canary_addr(true), PF_CANARY_V6) == 0, "v6 canary");
	CHECK(strncmp(pf_canary_addr(false), "192.0.2.", 8) == 0,
	      "v4 canary is TEST-NET-1");
	CHECK(strncmp(pf_canary_addr(true), "2001:db8:", 9) == 0,
	      "v6 canary is the documentation prefix");
}

static void test_probe_failure_is_not_a_false_security_verdict(void)
{
	/* An unusable address must report -1 ("could not check"), never a
	 * datagram count that could be mistaken for a verdict. */
	CHECK(pf_canary_probe_blocked(NULL, false) == -1, "NULL addr");
	CHECK(pf_canary_probe_blocked("not-an-address", false) == -1,
	      "unparseable addr");
	CHECK(pf_canary_probe_blocked("2001:db8::1", false) == -1,
	      "v6 literal in the v4 path");
}

int main(void)
{
	test_happy_path_is_the_only_pass();
	test_not_enforced_is_detected();
	test_a_silent_send_is_never_a_verdict();
	test_first_fault_wins();
	test_inconclusive_is_never_a_pass();
	test_cleanup_failure_is_reported_not_hidden();
	test_ruleset_reference_detection();
	test_ruleset_scan_does_not_match_a_longer_name();
	test_the_false_positive_this_guards_against();
	test_ruleset_scan_handles_degenerate_input();
	test_tokens_match_the_controller_contract();
	test_canary_address_is_documentation_space();
	test_probe_failure_is_not_a_false_security_verdict();

	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
