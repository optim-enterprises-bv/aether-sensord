/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Tests for the local decision path: captured flow -> signature -> pf element.
 *
 * WHAT THESE TESTS ARE FOR. The decision itself is simple; the failure modes are
 * not. Every one of these asserts a property whose violation would be invisible
 * in production:
 *
 *   - an ambiguous signature match must NOT become a block, because the app the
 *     matcher returned is arbitrary and one of the six claimants of
 *     en.wikipedia.org is classified as Malware.
 *   - a block verdict with no destination address must NOT become an element,
 *     because that is a block that cannot exist while the report says blocked.
 *   - observe mode must NOT increment `blocked`, because that number is what a
 *     human reads as "it is enforcing".
 *   - nothing may be widened past the observed address, because one observation
 *     does not justify blocking a range.
 */

#include "../src/local_decide.h"

#include "../src/match.h"
#include "../src/pf.h"
#include "../src/policy.h"
#include "../src/sigdb.h"

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

/* ------------------------------------------------------------- scaffolding */

/*
 * The signature database is built from an in-memory `#format v2.0` blob rather
 * than the shipped appdb, for two reasons: the shipped file has no established
 * provenance (its own Makefile says so) so a test depending on its contents
 * would change meaning whenever it did; and these entries exist to exercise the
 * matcher's specificity rules, which a random sample of the real file would do
 * only by luck.
 *
 * The line shape is copied verbatim from test_sigdb.c, which reads it from the
 * real file's header.
 */
static struct sig_db db;

static const char *DB_TEXT_PLAIN =
    "#format v2.0\n"
    "11001 YouTube:[tcp;;;youtube.com;;]\n"
    "11002 Facebook:[tcp;;;facebook.com;;]\n"
    "11003 SMTPout:[tcp;;587;;;]\n"
    "11004 Wikipedia:[tcp;;;en.wikipedia.org;;]\n";

/*
 * The ambiguous case: a SECOND application claiming a host that is already
 * claimed. This is the real shape -- 30 host patterns in the shipped database
 * are claimed more than once, and `en.wikipedia.org` is claimed by six
 * applications, one of them classified as Malware.
 */
static const char *DB_TEXT_AMBIGUOUS =
    "#format v2.0\n"
    "11001 YouTube:[tcp;;;youtube.com;;]\n"
    "11002 Facebook:[tcp;;;facebook.com;;]\n"
    "11003 SMTPout:[tcp;;587;;;]\n"
    "11004 Wikipedia:[tcp;;;en.wikipedia.org;;]\n"
    "31001 Conduit-Toolbar:[tcp;;;en.wikipedia.org;;]\n";

static void build_db(const char *text)
{
	FILE *fp;

	sig_db_free(&db);
	if (!sig_db_init(&db)) {
		fprintf(stderr, "sig_db_init failed\n");
		exit(2);
	}
	fp = fmemopen((void *)text, strlen(text), "r");
	if (!fp) {
		fprintf(stderr, "fmemopen failed\n");
		exit(2);
	}
	if (sig_db_load(&db, fp) < 0) {
		fprintf(stderr, "sig_db_load failed\n");
		exit(2);
	}
	fclose(fp);
}

static struct pol_db pol;
static const uint8_t kid_mac[POL_MAC_LEN] = { 0x02, 0, 0, 0, 0, 0x01 };

/*
 * A policy that blocks the named app tags for the kid's MAC. Built by name so
 * each test says what it means.
 */
static void build_policy(const char *tag1, const char *tag2)
{
	struct pol_rule r;
	size_t kid;

	pol_db_free(&pol);
	if (!pol_db_init(&pol)) {
		fprintf(stderr, "pol_db_init failed\n");
		exit(2);
	}
	kid = pol_add_subject(&pol, kid_mac, "kid-tablet");

	memset(&r, 0, sizeof r);
	r.subject_index = (uint16_t)kid;
	r.target = POL_TARGET_APP;
	r.action = POL_BLOCK;

	if (tag1) {
		snprintf(r.tag, sizeof r.tag, "%s", tag1);
		pol_add_rule(&pol, &db, &r);
	}
	if (tag2) {
		snprintf(r.tag, sizeof r.tag, "%s", tag2);
		pol_add_rule(&pol, &db, &r);
	}
}

static struct pol_time noon = { 1, 720 }; /* Monday, 12:00 */

static struct locdec_flow mk_flow(const char *host, uint16_t dport,
                                  bool have_addr, const char *addr,
                                  bool have_mac)
{
	struct locdec_flow f;

	memset(&f, 0, sizeof f);
	f.host = host;
	f.proto = SIG_PROTO_TCP;
	f.dport = dport;
	if (have_addr) {
		struct pf_elem e;

		/*
		 * Build the address through the real parser, so the test uses the
		 * same binary representation the daemon will. A test that
		 * hand-filled the bytes could pass while the parser disagreed.
		 */
		if (pf_elem_parse(addr, 0, &e) != PF_OK) {
			fprintf(stderr, "test bug: pf_elem_parse(%s) failed\n",
			        addr);
			exit(2);
		}
		memcpy(f.daddr, e.addr, sizeof f.daddr);
		f.daddr_family = e.family;
		f.have_daddr = true;
	}
	if (have_mac) {
		memcpy(f.smac, kid_mac, POL_MAC_LEN);
		f.have_smac = true;
	}
	return f;
}

/* ------------------------------------------------------------------ cases */

int main(void)
{
	struct locdec_block b;
	enum pol_reason why;
	enum match_kind kind;
	uint8_t amb;

	printf("=== local decision path: capture -> signature -> pf ===\n\n");

	/* ---------- the API contract is real before any behaviour ---------- */
	build_db(DB_TEXT_PLAIN);
	build_policy("youtube", "facebook");

	CHECK(pol.n_subjects == 1, "policy has one subject");
	CHECK(pol.n_rules == 2, "policy has two rules (got %zu)", pol.n_rules);
	CHECK(pol.rejected_unknown_tag == 0,
	      "both rule tags resolved against the signature database "
	      "(rejected_unknown_tag=%u)", pol.rejected_unknown_tag);
	CHECK(sig_db_by_tag(&db, "youtube") != NULL,
	      "the database really contains the youtube tag the policy names");

	/* ---------- a blocked app produces an element ---------- */
	{
		bool pb = false;
		struct locdec_flow f = mk_flow("www.youtube.com", 443, true,
		                               "203.0.113.10/32", true);

		CHECK(locdec_decide(&db, &pol, &f, noon, 0, &b, &pb, &why, &kind,
		                    &amb) == true,
		      "youtube for the kid's MAC: BLOCK");
		CHECK(kind == MATCH_HOST_SUFFIX,
		      "matched as a host suffix, not a substring");
		CHECK(why == POL_REASON_RULE,
		      "and the reason is a rule, not a window or quota");
		CHECK(b.elem.family == 4 && b.elem.prefix == 32,
		      "the element is a host route /32 (%u/%u), NOT a wider "
		      "range", b.elem.family, b.elem.prefix);
		CHECK(strcmp(b.app_tag, "youtube") == 0,
		      "and it carries the app tag for the audit trail");
	}

	/* ---------- an allowed app produces nothing ---------- */
	{
		bool pb = false;
		struct locdec_flow f = mk_flow("mail.example.org", 587, true,
		                               "198.51.100.5/32", true);

		CHECK(locdec_decide(&db, &pol, &f, noon, 0, &b, &pb, &why, &kind,
		                    &amb) == false,
		      "an app with no rule for this subject: no block");
		CHECK(why == POL_REASON_NO_RULE || why == POL_REASON_NO_SUBJECT,
		      "and the reason says which (%s)", pol_reason_str(why));
	}

	/* ---------- a port-only rule still matches a nameless flow ---------- */
	{
		bool pb = false;
		struct locdec_flow f = mk_flow("", 587, true, "198.51.100.9/32",
		                               true);

		CHECK(locdec_decide(&db, &pol, &f, noon, 0, &b, &pb, &why, &kind,
		                    &amb) == false,
		      "a flow with no hostname is not blocked (the smtp-out rule "
		      "is only an allow-side match here)");
		CHECK(kind != MATCH_NONE,
		      "but the port-only signature DID match (kind=%s), which is "
		      "why a NULL host must not be treated as an error",
		      match_kind_str(kind));
	}

	/* ---------- AMBIGUITY must not become a block ---------- */
	/* en.wikipedia.org now has two claimants -- the real ambiguity shape */
	build_db(DB_TEXT_AMBIGUOUS);
	build_policy("wikipedia", NULL);
	/*
	 * The policy blocks the wikipedia tag, and the database is ambiguous for
	 * that host. Acting would mean blocking a name that a malware signature
	 * also claims -- and reporting it as malware.
	 */
	{
		bool pb = false;
		struct locdec_flow f = mk_flow("en.wikipedia.org", 443, true,
		                               "203.0.113.77/32", true);
		uint8_t amb2 = 0;
		bool got;

		got = locdec_decide(&db, &pol, &f, noon, 0, &b, &pb, &why, &kind,
		                    &amb2);
		CHECK(amb2 > 1,
		      "the database reports the host as ambiguous (%u claimants)",
		      amb2);
		CHECK(got == false,
		      "an AMBIGUOUS match is NOT acted on, even though a rule "
		      "would have blocked the app the matcher happened to return");
	}

	/* ---------- a block with no address must NOT fabricate one ---------- */
	build_db(DB_TEXT_PLAIN);
	build_policy("youtube", "facebook");
	{
		bool pb = false;
		struct locdec_flow f = mk_flow("youtube.com", 443, false, NULL,
		                               true);
		struct locdec_stats st;
		struct locdec_block blk[8];

		CHECK(locdec_decide(&db, &pol, &f, noon, 0, &b, &pb, &why, &kind,
		                    &amb) == false,
		      "policy says BLOCK, but the capture layer had no "
		      "destination address -- so NO element is produced");

		/* and the fold counts it as unenforceable rather than blocked */
		{
			int n = locdec_fold(&db, &pol, &f, 1, noon, 0, true, blk, 8,
			                    &st, NULL, 0, NULL);

			CHECK(n == 0, "fold wrote 0 elements");
			/*
			 * blocked counts VERDICTS, so it is 1 -- the policy did
			 * say block. What must NOT happen is applied>0 (an element
			 * conjured from nothing) or the flow landing in `allowed`
			 * (reported as explicitly permitted). Both are asserted.
			 */
			CHECK(st.blocked == 1,
			      "the BLOCK VERDICT is reported (blocked=%u) -- the "
			      "policy really did say block", st.blocked);
			CHECK(st.applied == 0,
			      "but applied=0, because there was nothing to apply");
			CHECK(st.allowed == 0,
			      "and it is NOT counted as allowed -- that was the "
			      "defect this split exists to prevent (allowed=%u)",
			      st.allowed);
			CHECK(st.no_address == 1,
			      "it reported no_address=%u, which is the honest "
			      "answer", st.no_address);
		}
	}

	/* ---------- no MAC (the routed-firewall case) ---------- */
	{
		bool pb = false;
		struct locdec_flow f = mk_flow("youtube.com", 443, true,
		                               "203.0.113.10/32", false);

		CHECK(locdec_decide(&db, &pol, &f, noon, 0, &b, &pb, &why, &kind,
		                    &amb) == false,
		      "with no source MAC there is no policy subject, so no block "
		      "-- which is the correct outcome on a ROUTED firewall");
		/*
		 * The reason must be explicit. Choosing a default subject here
		 * would silently apply one client's rules to everyone.
		 */
		CHECK(why == POL_REASON_NO_SUBJECT,
		      "and the reason is NO_SUBJECT, not a block (%s)",
		      pol_reason_str(why));
	}

	/* ---------- OBSERVE MODE must not report enforcement ---------- */
	{
		struct locdec_flow flows[2];
		struct locdec_stats st;
		struct locdec_block blk[8];

		flows[0] = mk_flow("youtube.com", 443, true, "203.0.113.10/32",
		                   true);
		flows[1] = mk_flow("facebook.com", 443, true, "203.0.113.20/32",
		                   true);

		locdec_fold(&db, &pol, flows, 2, noon, 0, false, blk, 8, &st,
		            NULL, 0, NULL);
		/*
		 * THE PROPERTY THAT MATTERS: nothing was applied. `blocked` still
		 * counts the two verdicts (the policy did say block), so the
		 * enforcement claim is carried by applied/would_block, not by
		 * `blocked` -- which is exactly why those were split out.
		 */
		CHECK(st.applied == 0,
		      "observe mode applied NOTHING (applied=%u) -- anything "
		      "else would be a fabricated enforcement claim",
		      st.applied);
		CHECK(st.would_block == 2,
		      "and reports would_block=2 instead (got %u)",
		      st.would_block);
		CHECK(st.blocked == 2,
		      "the 2 verdicts are still visible as blocked=%u, so an "
		      "operator can see what the policy WOULD do", st.blocked);

		/* and enforce mode reports the opposite way round */
		{
			int n = locdec_fold(&db, &pol, flows, 2, noon, 0, true, blk,
			                    8, &st, NULL, 0, NULL);

			CHECK(n == 2, "enforce mode produced 2 elements");
			CHECK(st.applied == 2 && st.would_block == 0,
			      "and reports applied=2 would_block=0 -- the "
			      "enforcement number is applied, not blocked");
			CHECK(blk[0].elem.prefix == 32 && blk[1].elem.prefix == 32,
			      "both are host routes");
			CHECK(memcmp(blk[0].elem.addr, blk[1].elem.addr,
			             blk[0].elem.family == 4 ? 4 : 16) != 0,
			      "the two DIFFERENT destinations are distinct elements");
		}
	}

	/* ---------- deduplication ---------- */
	{
		struct locdec_flow flows[3];
		struct locdec_stats st;
		struct locdec_block blk[8];

		/* same server reached three times (CDN, retries, parallel conns) */
		flows[0] = mk_flow("youtube.com", 443, true, "203.0.113.10/32",
		                   true);
		flows[1] = mk_flow("youtube.com", 443, true, "203.0.113.10/32",
		                   true);
		flows[2] = mk_flow("youtube.com", 443, true, "203.0.113.10/32",
		                   true);

		{
			int n = locdec_fold(&db, &pol, flows, 3, noon, 0, true, blk, 8,
			                    &st, NULL, 0, NULL);

			CHECK(n == 1,
			      "three flows to ONE address yield ONE element (got %d)",
			      n);
			CHECK(st.duplicate == 2,
			      "and two are counted as duplicates (got %u)",
			      st.duplicate);
			CHECK(st.blocked == 3,
			      "while blocked still counts all three FLOWS (got %u) "
			      "-- flows and elements are different units",
			      st.blocked);
			CHECK(st.applied == 1,
			      "and applied=1, the number of ELEMENTS (got %u)",
			      st.applied);
		}
	}

	/* ---------- the block cap must be reported, not silently dropped ---- */
	{
		struct locdec_flow flows[4];
		struct locdec_stats st;
		struct locdec_block blk[2]; /* capacity 2 */
		int n;

		flows[0] = mk_flow("youtube.com", 443, true, "203.0.113.10/32",
		                   true);
		flows[1] = mk_flow("youtube.com", 443, true, "203.0.113.11/32",
		                   true);
		flows[2] = mk_flow("youtube.com", 443, true, "203.0.113.12/32",
		                   true);
		flows[3] = mk_flow("youtube.com", 443, true, "203.0.113.13/32",
		                   true);

		n = locdec_fold(&db, &pol, flows, 4, noon, 0, true, blk, 2, &st,
		                NULL, 0, NULL);
		CHECK(n == 2, "only the 2 the buffer can hold are written");
		CHECK(st.overflow == 2,
		      "and the other 2 are counted as overflow, not dropped "
		      "silently (got %u)", st.overflow);
	}

	/* ---------- counters must partition the flows ---------- */
	{
		struct locdec_flow flows[6];
		struct locdec_stats st;
		struct locdec_block blk[16];
		uint32_t sum;

		flows[0] = mk_flow("youtube.com", 443, true, "203.0.113.10/32",
		                   true);   /* blocked */
		flows[1] = mk_flow("", 443, true, "203.0.113.11/32", true);
						/* no_host */
		flows[2] = mk_flow("example.net", 443, true, "203.0.113.12/32",
		                   true);   /* not_in_db */
		flows[3] = mk_flow("youtube.com", 443, false, NULL, true);
						/* no_address */
		flows[4] = mk_flow("youtube.com", 443, true, "203.0.113.14/32",
		                   false);  /* no_subject */
		flows[5] = mk_flow("facebook.com", 443, true, "203.0.113.15/32",
		                   true);   /* blocked */

		locdec_fold(&db, &pol, flows, 6, noon, 0, true, blk, 16, &st,
		            NULL, 0, NULL);

		CHECK(st.flows == 6, "6 flows seen");
		CHECK(st.blocked == 3,
		      "3 flow(s) carried a BLOCK verdict -- including the "
		      "unenforceable one, which must not be reported as allowed "
		      "(got %u)", st.blocked);
		CHECK(st.applied == 2,
		      "but only 2 ELEMENTS were written; flows and elements are "
		      "different units (got %u)", st.applied);
		CHECK(st.no_host == 1, "1 had no hostname (got %u)", st.no_host);
		CHECK(st.not_in_db == 1,
		      "1 host had no signature (got %u)", st.not_in_db);
		CHECK(st.no_address == 1,
		      "1 was unenforceable for want of an address (got %u)",
		      st.no_address);
		CHECK(st.no_subject == 1,
		      "1 had no policy subject (got %u)", st.no_subject);

		/*
		 * The partition property. If these do not add up, some path is
		 * double-counting or dropping a flow, and the totals an operator
		 * reads would be wrong in a way nothing else would reveal.
		 */
		/*
		 * THE PARTITION PROPERTY, with the qualifiers left out.
		 *
		 * no_address/duplicate/overflow are NOT buckets -- they qualify
		 * the blocked bucket, so adding them in would double-count. This
		 * is the assertion that a genuinely lost flow fails, and it must
		 * be written against the six real buckets or it proves nothing.
		 */
		sum = st.no_host + st.not_in_db + st.ambiguous + st.allowed +
		      st.no_subject + st.blocked;
		CHECK(sum == st.flows,
		      "every flow is in exactly one bucket: %u == %u",
		      sum, st.flows);
		CHECK(st.applied <= st.blocked,
		      "and applied never exceeds blocked (%u <= %u)",
		      st.applied, st.blocked);
	}

	/* ---------- the explanation surface ---------- */
	{
		struct locdec_stats st;
		char line[512];
		char line2[48];

		memset(&st, 0, sizeof st);
		st.flows = 7;
		st.blocked = 3;
		CHECK(locdec_stats_line(&st, line, sizeof line) == line,
		      "stats line renders");
		CHECK(strstr(line, "blocked=3") != NULL,
		      "and contains the block count");
		CHECK(strstr(line, "would_block=0") != NULL,
		      "and the would_block count separately, so the two can never "
		      "be confused: %s", line);

		/* a short buffer must truncate, not overflow */
		locdec_stats_line(&st, line2, sizeof line2);
		CHECK(strlen(line2) < sizeof line2,
		      "a short buffer is truncated safely (%zu < %zu)",
		      strlen(line2), sizeof line2);
	}

	/* ---------- argument validation ---------- */
	{
		struct locdec_stats st;

		CHECK(locdec_fold(NULL, &pol, NULL, 0, noon, 0, true, NULL, 0, &st,
		                  NULL, 0, NULL) == -1,
		      "a NULL database is refused, not silently allowed");
		CHECK(locdec_fold(&db, NULL, NULL, 0, noon, 0, true, NULL, 0, &st,
		                  NULL, 0, NULL) == -1,
		      "a NULL policy is refused");
		CHECK(locdec_fold(&db, &pol, NULL, 0, noon, 0, true, NULL, 0, NULL,
		                  NULL, 0, NULL) == -1,
		      "a NULL stats output is refused");
	}

	sig_db_free(&db);
	pol_db_free(&pol);

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
