/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Host tests for the signature database and matcher.
 *
 * These run against the REAL shipped database
 * (net/open-app-filter/files/feature_en.cfg, 1,347 entries) rather than a
 * fixture, because the defects this code exists to prevent were all
 * properties of the real file's size and contents (ADR-003: real data or an
 * explicit error, never a convenient stand-in).
 *
 *     make -C net/aether-sensord/test check
 */

#include "../src/match.h"
#include "../src/sigdb.h"

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

/*
 * The shipped database lives in a different feed package, so a standalone
 * checkout cannot find it by path. AETHER_SIGDB lets CI and packagers point at
 * one; without it these checks SKIP rather than fail, and say so.
 */
#define REAL_DB_DEFAULT "../../open-app-filter/files/feature_en.cfg"

static const char *real_db_path(void)
{
	const char *env = getenv("AETHER_SIGDB");

	return (env && *env) ? env : REAL_DB_DEFAULT;
}

/* ---------------------------------------------------------------- tags --- */

static void test_tag_normalise(void)
{
	char t[SIG_TAG_LEN];

	sig_tag_normalise("WindowsUpdate", t, sizeof(t));
	CHECK(strcmp(t, "windowsupdate") == 0, "WindowsUpdate");

	sig_tag_normalise("samba", t, sizeof(t));
	CHECK(strcmp(t, "samba") == 0, "samba");

	sig_tag_normalise("Google Play", t, sizeof(t));
	CHECK(strcmp(t, "google-play") == 0, "spaces become one separator");

	sig_tag_normalise("A  B", t, sizeof(t));
	CHECK(strcmp(t, "a-b") == 0, "separator runs collapse");

	sig_tag_normalise("  Trailing  ", t, sizeof(t));
	CHECK(strcmp(t, "trailing") == 0, "edges trimmed, no trailing dash");

	sig_tag_normalise("", t, sizeof(t));
	CHECK(t[0] == '\0', "empty in, empty out");

	sig_tag_normalise("!!!", t, sizeof(t));
	CHECK(t[0] == '\0', "punctuation only yields no tag");

	/* Truncation must not run off the end of a short buffer. */
	char small[6];
	sig_tag_normalise("AbcdefghijK", small, sizeof(small));
	CHECK(strlen(small) < sizeof(small), "bounded output");
}

/* ------------------------------------------------------------ parsing --- */

static void test_parse_synthetic(void)
{
	/* Lines copied verbatim in shape from the real file's header and body. */
	const char *text =
	    "#version v11.08.23\n"
	    "#format v2.0\n"
	    "#id name:[proto;sport;dport;host url;request;dict]\n"
	    "10001 jPush:[tcp;;;docs.jiguang.cn;;],\n"
	    "13005 samba:[tcp;;445;;;]\n"
	    "13003 WindowsUpdate:[tcp;;80;update.microsoft.com;;,tcp;;;windowsupdate.com;;]  \n"
	    "garbage line without structure\n"
	    "0 ZeroId:[tcp;;;zero.example;;]\n";

	FILE *fp = fmemopen((void *)text, strlen(text), "r");
	CHECK(fp != NULL, "fmemopen");

	struct sig_db db;
	CHECK(sig_db_init(&db), "init");
	long n = sig_db_load(&db, fp);
	fclose(fp);

	CHECK(n == 3, "three well-formed apps accepted");
	CHECK(db.rejected_malformed == 2, "garbage line and id=0 both refused");
	CHECK(strcmp(db.format, "v2.0") == 0, "format read from the data file");
	CHECK(strcmp(db.version, "v11.08.23") == 0, "version read from the file");

	const struct sig_app *w = sig_db_by_tag(&db, "windowsupdate");
	CHECK(w != NULL, "tag lookup");
	CHECK(w && w->id == 13003, "id preserved");
	CHECK(w && w->db_class == 13, "class is id/1000");

	/* WindowsUpdate carries TWO rules; a parser that stops at the first
	 * comma silently loses half the signature. */
	int wu_rules = 0;
	for (size_t i = 0; i < db.n_rules; i++)
		if (db.rules[i].app_index == (w ? (uint16_t)(w - db.apps) : 0xffff))
			wu_rules++;
	CHECK(wu_rules == 2, "both rules of a multi-rule app are loaded");

	sig_db_free(&db);
}

static void test_port_only_rule(void)
{
	const char *text = "13005 samba:[tcp;;445;;;]\n";
	FILE *fp = fmemopen((void *)text, strlen(text), "r");
	struct sig_db db;
	sig_db_init(&db);
	sig_db_load(&db, fp);
	fclose(fp);

	CHECK(db.n_rules == 1, "one rule");
	CHECK(db.rules[0].dport == 445, "port parsed");
	CHECK(db.rules[0].host[0] == '\0', "no host pattern");

	/* Matches on port... */
	struct match_result m = match_flow(&db, NULL, SIG_PROTO_TCP, 445);
	CHECK(m.kind == MATCH_PORT, "port-only rule matches by port");
	CHECK(m.app && strcmp(m.app->tag, "samba") == 0, "samba matched");

	/* ...and must never be reached by a hostname lookup on another port. */
	m = match_flow(&db, "www.youtube.com", SIG_PROTO_TCP, 443);
	CHECK(m.kind == MATCH_NONE, "port rule does not match a different port");

	sig_db_free(&db);
}

static void test_rule_with_no_host_and_no_port_is_refused(void)
{
	/* Such a rule matches everything and would shadow the database. */
	const char *text = "12345 Bad:[tcp;;;;;]\n";
	FILE *fp = fmemopen((void *)text, strlen(text), "r");
	struct sig_db db;
	sig_db_init(&db);
	long n = sig_db_load(&db, fp);
	fclose(fp);
	CHECK(n == 1, "app is accepted");
	CHECK(db.n_rules == 0, "but its unbounded rule is refused");
	sig_db_free(&db);
}

static void test_same_app_under_two_ids_merges(void)
{
	/* Verbatim shape of the real YouTube entries: one application, two
	 * numeric ids, two rules. Merging them is the entire point of the tag. */
	const char *text =
	    "11001 YouTube:[tcp;;;youtube;;]\n"
	    "39037 YouTube:[tcp;;;www.youtube.com;;],\n";
	FILE *fp = fmemopen((void *)text, strlen(text), "r");
	struct sig_db db;
	sig_db_init(&db);
	long n = sig_db_load(&db, fp);
	fclose(fp);

	CHECK(n == 1, "one application, not two");
	CHECK(db.merged_by_tag == 1, "the second definition merged, not dropped");
	CHECK(db.n_rules == 2, "BOTH rules retained -- coverage is not lost");

	const struct sig_app *yt = sig_db_by_tag(&db, "youtube");
	CHECK(yt != NULL, "resolvable by tag");

	/* Both patterns must classify, via either id's rule. */
	struct match_result m = match_flow(&db, "www.youtube.com", SIG_PROTO_TCP, 443);
	CHECK(m.app == yt, "the fully-qualified pattern matches");
	m = match_flow(&db, "m.youtube.com", SIG_PROTO_TCP, 443);
	CHECK(m.app == yt, "the bare-token pattern matches as a label");

	/* The bare token is a LABEL-PREFIX match, which is a deliberate trade
	 * documented in match.c. It must recover the real traffic domains these
	 * services actually use... */
	m = match_flow(&db, "youtubei.googleapis.com", SIG_PROTO_TCP, 443);
	CHECK(m.app == yt, "InnerTube API recovered (label prefix)");

	/* ...while still closing the look-alike hole that plain substring
	 * matching would leave open. */
	m = match_flow(&db, "evil-youtube.com", SIG_PROTO_TCP, 443);
	CHECK(m.kind == MATCH_NONE, "look-alike rejected: label does not START with the token");

	/* Accepted cost of the same mechanism: a label that merely starts with
	 * the token matches. This OVER-blocks rather than under-blocks, which is
	 * the safer direction for parental controls, and it is the price of
	 * recovering youtubei/tiktokcdn/tiktokv. Asserted so the trade is a
	 * decision on record, not a surprise. */
	m = match_flow(&db, "youtubefake.com", SIG_PROTO_TCP, 443);
	CHECK(m.app == yt, "label-prefix over-blocks by design");

	/* Inherent to a bare token and not solvable in the matcher: the token is
	 * a whole label here, so it matches. Over-blocks, deliberate. */
	m = match_flow(&db, "youtube.evil.com", SIG_PROTO_TCP, 443);
	CHECK(m.app == yt, "token as a whole label matches wherever it appears");

	sig_db_free(&db);
}

/* ------------------------------------------------------------ matching --- */

static void test_host_pattern_boundaries(void)
{
	enum match_kind k;

	CHECK(match_host_pattern("signal.org", "signal.org", &k), "exact");
	CHECK(k == MATCH_HOST_EXACT, "exact kind");

	CHECK(match_host_pattern("www.signal.org", "signal.org", &k), "suffix");
	CHECK(k == MATCH_HOST_SUFFIX, "suffix kind");

	CHECK(match_host_pattern("SIGNAL.ORG", "signal.org", &k), "case folded");

	CHECK(match_host_pattern("signal.org.", "signal.org", &k),
	      "trailing root dot ignored");

	/* The security-relevant cases: substring matching would pass these. */
	CHECK(!match_host_pattern("notsignal.org", "signal.org", &k),
	      "label boundary respected");
	CHECK(!match_host_pattern("signal.org.attacker.net", "signal.org", &k),
	      "prefix in a longer name must not match");
	CHECK(!match_host_pattern("evil-github.com", "github.com", &k),
	      "hyphenated look-alike must not match");
	CHECK(!match_host_pattern("", "signal.org", &k), "empty host");
	CHECK(!match_host_pattern("signal.org", "", &k), "empty pattern");
}

static void test_longest_pattern_wins(void)
{
	const char *text =
	    "20001 Google:[tcp;;;google.com;;]\n"
	    "20002 GoogleMail:[tcp;;;mail.google.com;;]\n";
	FILE *fp = fmemopen((void *)text, strlen(text), "r");
	struct sig_db db;
	sig_db_init(&db);
	sig_db_load(&db, fp);
	fclose(fp);

	struct match_result m = match_flow(&db, "mail.google.com", SIG_PROTO_TCP, 443);
	CHECK(m.app && strcmp(m.app->tag, "googlemail") == 0,
	      "more specific signature is not shadowed by the broader one");
	CHECK(m.kind == MATCH_HOST_EXACT, "exact beats suffix");

	m = match_flow(&db, "docs.google.com", SIG_PROTO_TCP, 443);
	CHECK(m.app && strcmp(m.app->tag, "google") == 0, "falls back to parent");

	sig_db_free(&db);
}

/* -------------------------------------------------- the real database --- */

static void test_real_database(void)
{
	struct sig_db db;
	CHECK(sig_db_init(&db), "init");

	const char *REAL_DB = real_db_path();
	long n = sig_db_load_path(&db, REAL_DB);
	if (n < 0) {
		fprintf(stderr,
		        "SKIP: real database not found at %s\n"
		        "      (run from net/aether-sensord/test)\n", REAL_DB);
		sig_db_free(&db);
		return;
	}

	printf("  real database: %ld apps, %zu rules, format=%s version=%s\n",
	       n, db.n_rules, db.format, db.version);
	printf("  merged_by_tag=%u  refused: malformed=%u apps_full=%u rules_full=%u\n",
	       db.merged_by_tag, db.rejected_malformed,
	       db.rejected_apps_full, db.rejected_rules_full);

	/* The whole point of the bound: 1,347 entries must load, where the
	 * reference implementation corrupts memory past 1,024. */
	CHECK(n > 1300, "the full shipped database loads");
	CHECK(db.rejected_apps_full == 0, "no app refused for want of capacity");
	CHECK(db.rejected_rules_full == 0, "no rule refused for want of capacity");
	CHECK(strcmp(db.format, "v2.0") == 0, "format declared by the file");

	/* The heart of ADR-020 decision 4, against real data.
	 *
	 * This database defines YouTube under BOTH 11001 and 39037. aether's
	 * OAF_APP_IDS mapped both, which was correct here -- and catastrophic
	 * against upstream's database, where 11001 is Samba. So a numeric id is
	 * not a usable cross-boundary identifier even within one product.
	 *
	 * The tag is. Assert that the tag resolves and that both underlying
	 * patterns classify through it. */
	const struct sig_app *yt = sig_db_by_tag(&db, "youtube");
	CHECK(yt != NULL, "youtube resolvable by tag");
	if (yt)
		printf("  tag 'youtube' -> first id %u, class %u\n", yt->id,
		       yt->db_class);

	struct match_result m = match_flow(&db, "www.youtube.com", SIG_PROTO_TCP, 443);
	CHECK(m.app && strcmp(m.app->tag, "youtube") == 0,
	      "www.youtube.com classifies as youtube");

	/* Samba is a port-only signature and must not be reachable from a
	 * hostname lookup -- the shape of the original mis-block. */
	m = match_flow(&db, "www.youtube.com", SIG_PROTO_TCP, 445);
	CHECK(!(m.app && strcmp(m.app->tag, "samba") == 0 && m.kind != MATCH_PORT),
	      "samba is only ever a port match");

	/* Classes run past 32 in this database, which is why a fixed 32-entry
	 * per-class array is a defect and not a design choice. */
	uint16_t max_class = 0;
	for (size_t i = 0; i < db.n_apps; i++)
		if (db.apps[i].db_class > max_class)
			max_class = db.apps[i].db_class;
	printf("  highest class id: %u\n", max_class);
	CHECK(max_class > 32, "classes exceed 32 -- fixed 32-wide arrays overflow");

	/* Every accepted app must have a usable tag; a blank one would be an
	 * unaddressable signature. */
	int blank = 0;
	for (size_t i = 0; i < db.n_apps; i++)
		if (db.apps[i].tag[0] == '\0')
			blank++;
	CHECK(blank == 0, "every app has a non-empty tag");

	/* Round-trip a real signature through the matcher. */
	const struct sig_app *sig = sig_db_by_tag(&db, "samba");
	if (sig)
		printf("  tag 'samba' -> id %u class %u\n", sig->id, sig->db_class);

	sig_db_free(&db);
}

static void test_capacity_is_enforced_not_exceeded(void)
{
	/* Synthesise more apps than the bound and confirm the loader refuses
	 * rather than writing past the array -- the 21967be defect, inverted. */
	struct sig_db db;
	CHECK(sig_db_init(&db), "init");

	char *buf = malloc(80 * (SIG_MAX_APPS + 100));
	CHECK(buf != NULL, "alloc");
	size_t off = 0;
	for (int i = 0; i < SIG_MAX_APPS + 50; i++)
		off += (size_t)sprintf(buf + off, "%d App%d:[tcp;;;h%d.example;;]\n",
		                       10000 + i, i, i);

	FILE *fp = fmemopen(buf, off, "r");
	long n = sig_db_load(&db, fp);
	fclose(fp);

	CHECK(n == SIG_MAX_APPS, "accepts exactly the bound");
	CHECK(db.n_apps == SIG_MAX_APPS, "table not exceeded");
	CHECK(db.rejected_apps_full == 50, "overflow refused AND counted");

	free(buf);
	sig_db_free(&db);
}

int main(void)
{
	test_tag_normalise();
	test_parse_synthetic();
	test_port_only_rule();
	test_rule_with_no_host_and_no_port_is_refused();
	test_same_app_under_two_ids_merges();
	test_host_pattern_boundaries();
	test_longest_pattern_wins();
	test_capacity_is_enforced_not_exceeded();
	test_real_database();

	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
