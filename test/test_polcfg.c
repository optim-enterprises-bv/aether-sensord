/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Tests for the UCI policy loader.
 *
 * The happy path is the least interesting part. What matters is that every
 * line this cannot use is REFUSED AND COUNTED rather than skipped: a loader
 * that quietly drops a malformed rule produces a device reporting healthy
 * while enforcing less than the file says (ADR-017).
 *
 *   make -C net/aether-sensord/test check
 */

#include "../src/polcfg.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;
#define CHECK(cond, msg)                                                       \
	do {                                                                   \
		checks++;                                                      \
		if (!(cond)) {                                                 \
			failures++;                                            \
			printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);  \
		}                                                              \
	} while (0)

static long load(struct pol_db *db, struct polcfg_stats *st, const char *text)
{
	pol_db_init(db);
	return polcfg_parse(db, NULL, text, strlen(text), st);
}

static void test_basic_subject_and_rule(void)
{
	struct pol_db db;
	struct polcfg_stats st;
	long n;

	n = load(&db, &st,
	         "config subject\n"
	         "\toption mac 'aa:bb:cc:dd:ee:ff'\n"
	         "\toption label 'kid-tablet'\n"
	         "\n"
	         "config rule\n"
	         "\toption subject 'aa:bb:cc:dd:ee:ff'\n"
	         "\toption tag 'youtube'\n"
	         "\toption action 'block'\n");

	CHECK(n == 1, "one rule accepted");
	CHECK(st.subjects_added == 1, "one subject accepted");
	CHECK(st.sections == 2, "two sections seen");
	CHECK(!polcfg_had_refusals(&st), "nothing refused");
	CHECK(db.n_rules == 1, "rule reached the database");
	CHECK(db.n_subjects == 1, "subject reached the database");
	if (db.n_rules == 1) {
		CHECK(db.rules[0].action == POL_BLOCK, "action parsed");
		CHECK(strcmp(db.rules[0].tag, "youtube") == 0, "tag parsed");
		CHECK(db.rules[0].target == POL_TARGET_APP, "app target default");
	}
	if (db.n_subjects == 1)
		CHECK(strcmp(db.subjects[0].label, "kid-tablet") == 0,
		      "label parsed");
	pol_db_free(&db);
}

static void test_quoting_and_comments(void)
{
	struct pol_db db;
	struct polcfg_stats st;

	load(&db, &st,
	     "# a comment line\n"
	     "config subject       # trailing comment\n"
	     "        option mac \"aa:bb:cc:dd:ee:ff\"\n"
	     "        option label 'has space'\n"
	     "\r\n"
	     "config rule\r\n"
	     "        option subject aa:bb:cc:dd:ee:ff\r\n"
	     "        option tag 'youtube'\r\n");

	CHECK(st.subjects_added == 1, "double quotes accepted");
	CHECK(st.rules_added == 1, "unquoted values accepted");
	CHECK(st.bad_syntax == 0, "CRLF and comments are not syntax errors");
	if (db.n_subjects == 1)
		CHECK(strcmp(db.subjects[0].label, "has space") == 0,
		      "quoted value keeps its space");
	pol_db_free(&db);
}

static void test_bad_mac_is_counted_not_skipped(void)
{
	struct pol_db db;
	struct polcfg_stats st;

	load(&db, &st,
	     "config subject\n"
	     "\toption mac 'not-a-mac'\n"
	     "config subject\n"
	     "\toption mac 'aa:bb:cc:dd:ee'\n"       /* too short */
	     "config subject\n"
	     "\toption mac 'aa:bb:cc:dd:ee:ff:00'\n" /* too long */
	     "config subject\n"
	     "\toption mac 'gg:bb:cc:dd:ee:ff'\n");  /* not hex */

	CHECK(st.subjects_added == 0, "no malformed MAC was accepted");
	CHECK(st.bad_mac == 4, "every malformed MAC was counted");
	CHECK(polcfg_had_refusals(&st), "refusals are visible to the caller");
	pol_db_free(&db);
}

static void test_mac_separators(void)
{
	struct pol_db db;
	struct polcfg_stats st;

	load(&db, &st,
	     "config subject\n\toption mac 'aa:bb:cc:dd:ee:ff'\n"
	     "config subject\n\toption mac 'a1-b2-c3-d4-e5-f6'\n");
	CHECK(st.subjects_added == 2, "colon and dash separators both accepted");
	CHECK(st.bad_mac == 0, "neither was refused");
	pol_db_free(&db);
}

static void test_unknown_subject_is_not_invented(void)
{
	struct pol_db db;
	struct polcfg_stats st;

	load(&db, &st,
	     "config rule\n"
	     "\toption subject 'aa:bb:cc:dd:ee:ff'\n"
	     "\toption tag 'youtube'\n");

	CHECK(st.rules_added == 0, "a rule for an undeclared device is refused");
	CHECK(st.unknown_subject == 1, "and counted as such");
	CHECK(st.bad_mac == 0, "not misreported as a malformed MAC");
	pol_db_free(&db);
}

/*
 * The policy engine has no all-devices subject. A house-wide rule must be
 * refused visibly rather than approximated -- see polcfg.c.
 */
static void test_house_wide_rule_is_refused_visibly(void)
{
	struct pol_db db;
	struct polcfg_stats st;

	load(&db, &st, "config rule\n\toption tag 'youtube'\n");
	CHECK(st.rules_added == 0, "a rule naming no subject is not accepted");
	CHECK(st.no_subject == 1, "it is counted in its own category");
	CHECK(polcfg_had_refusals(&st), "and surfaces as a refusal");
	pol_db_free(&db);

	load(&db, &st, "config rule\n\toption subject '*'\n\toption tag 'x'\n");
	CHECK(st.no_subject == 1, "an explicit '*' lands in the same category");
	pol_db_free(&db);
}

static void test_window_parsing(void)
{
	struct pol_db db;
	struct polcfg_stats st;

	load(&db, &st,
	     "config subject\n\toption mac 'aa:bb:cc:dd:ee:ff'\n"
	     "config rule\n"
	     "\toption subject 'aa:bb:cc:dd:ee:ff'\n"
	     "\toption tag 'youtube'\n"
	     "\toption days 'mon-fri'\n"
	     "\toption start '21:30'\n"
	     "\toption stop '07:00'\n");

	CHECK(st.rules_added == 1, "a windowed rule is accepted");
	CHECK(st.bad_window == 0, "the window parsed");
	if (db.n_rules == 1) {
		CHECK(db.rules[0].has_window, "window recorded");
		CHECK(db.rules[0].window.start_min == 21 * 60 + 30,
		      "HH:MM start converted to minutes");
		CHECK(db.rules[0].window.end_min == 7 * 60,
		      "HH:MM end converted to minutes");
		CHECK(db.rules[0].window.days == 0x3e,
		      "mon-fri is Mon..Fri, not Sun");
		CHECK(db.rules[0].window.sense == POL_WINDOW_BLOCK_IN,
		      "default sense is block-inside, the bedtime reading");
	}
	pol_db_free(&db);
}

static void test_window_day_forms(void)
{
	struct pol_db db;
	struct polcfg_stats st;
	const char *prefix =
	        "config subject\n\toption mac 'aa:bb:cc:dd:ee:ff'\n"
	        "config rule\n\toption subject 'aa:bb:cc:dd:ee:ff'\n"
	        "\toption tag 'youtube'\n\toption start '01:00'\n"
	        "\toption stop '02:00'\n\toption days ";
	char buf[512];

	snprintf(buf, sizeof(buf), "%s'all'\n", prefix);
	load(&db, &st, buf);
	CHECK(db.n_rules == 1 && db.rules[0].window.days == 0x7f,
	      "'all' is every day");
	pol_db_free(&db);

	snprintf(buf, sizeof(buf), "%s'sat,sun'\n", prefix);
	load(&db, &st, buf);
	CHECK(db.n_rules == 1 && db.rules[0].window.days == 0x41,
	      "comma list");
	pol_db_free(&db);

	/* A range that wraps the week end. */
	snprintf(buf, sizeof(buf), "%s'fri-mon'\n", prefix);
	load(&db, &st, buf);
	CHECK(db.n_rules == 1 && db.rules[0].window.days == 0x63,
	      "fri-mon wraps to Fri,Sat,Sun,Mon");
	pol_db_free(&db);

	snprintf(buf, sizeof(buf), "%s'1,2,3'\n", prefix);
	load(&db, &st, buf);
	CHECK(db.n_rules == 1 && db.rules[0].window.days == 0x0e,
	      "numeric days, 0 = Sunday");
	pol_db_free(&db);
}

static void test_bad_windows_are_refused(void)
{
	struct pol_db db;
	struct polcfg_stats st;
	const char *sub = "config subject\n\toption mac 'aa:bb:cc:dd:ee:ff'\n";
	char buf[512];
	struct { const char *days, *start, *stop; const char *why; } bad[] = {
		{ "mon", "24:00", "01:00", "hour 24 is out of range" },
		{ "mon", "01:60", "02:00", "minute 60 is out of range" },
		{ "mon", "-5",    "02:00", "negative minute" },
		{ "mon", "1440",  "02:00", "1440 is past the end of the day" },
		{ "xyz", "01:00", "02:00", "unknown day name" },
		{ "",    "01:00", "02:00", "empty day list" },
		{ "mon", "01:00", "01:00", "zero-length window" },
		{ "mon", "1:00x", "02:00", "trailing garbage" },
	};
	size_t i;

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		snprintf(buf, sizeof(buf),
		         "%sconfig rule\n\toption subject 'aa:bb:cc:dd:ee:ff'\n"
		         "\toption tag 'youtube'\n\toption days '%s'\n"
		         "\toption start '%s'\n\toption stop '%s'\n",
		         sub, bad[i].days, bad[i].start, bad[i].stop);
		load(&db, &st, buf);
		CHECK(st.rules_added == 0, bad[i].why);
		CHECK(st.bad_window == 1, "counted as a bad window");
		pol_db_free(&db);
	}
}

static void test_bad_action_is_refused(void)
{
	struct pol_db db;
	struct polcfg_stats st;

	load(&db, &st,
	     "config subject\n\toption mac 'aa:bb:cc:dd:ee:ff'\n"
	     "config rule\n\toption subject 'aa:bb:cc:dd:ee:ff'\n"
	     "\toption tag 'youtube'\n\toption action 'maybe'\n");

	CHECK(st.rules_added == 0, "an unrecognised action is not guessed at");
	CHECK(st.bad_action == 1, "it is counted");
	pol_db_free(&db);
}

static void test_over_long_values_refused_not_truncated(void)
{
	struct pol_db db;
	struct polcfg_stats st;
	char buf[1024];
	char longtag[300];

	memset(longtag, 'a', sizeof(longtag) - 1);
	longtag[sizeof(longtag) - 1] = '\0';

	snprintf(buf, sizeof(buf),
	         "config subject\n\toption mac 'aa:bb:cc:dd:ee:ff'\n"
	         "config rule\n\toption subject 'aa:bb:cc:dd:ee:ff'\n"
	         "\toption tag '%s'\n",
	         longtag);
	load(&db, &st, buf);
	CHECK(st.rules_added == 0, "an over-long tag is refused, not shortened");
	CHECK(polcfg_had_refusals(&st), "and shows up as a refusal");
	pol_db_free(&db);
}

static void test_quota(void)
{
	struct pol_db db;
	struct polcfg_stats st;

	load(&db, &st,
	     "config subject\n\toption mac 'aa:bb:cc:dd:ee:ff'\n"
	     "config rule\n\toption subject 'aa:bb:cc:dd:ee:ff'\n"
	     "\toption tag 'youtube'\n\toption quota '3600'\n");
	CHECK(db.n_rules == 1 && db.rules[0].daily_quota_sec == 3600,
	      "quota parsed");
	pol_db_free(&db);

	load(&db, &st,
	     "config subject\n\toption mac 'aa:bb:cc:dd:ee:ff'\n"
	     "config rule\n\toption subject 'aa:bb:cc:dd:ee:ff'\n"
	     "\toption tag 'youtube'\n\toption quota '90000'\n");
	CHECK(st.rules_added == 0, "a quota longer than a day is refused");
	pol_db_free(&db);
}

static void test_disabled_section_is_not_an_error(void)
{
	struct pol_db db;
	struct polcfg_stats st;

	load(&db, &st,
	     "config subject\n\toption mac 'aa:bb:cc:dd:ee:ff'\n"
	     "config rule\n\toption subject 'aa:bb:cc:dd:ee:ff'\n"
	     "\toption tag 'youtube'\n\toption enabled '0'\n");

	CHECK(st.rules_added == 0, "a disabled rule is not added");
	CHECK(st.bad_syntax == 0 && st.bad_action == 0,
	      "and is not reported as malformed");
	pol_db_free(&db);
}

static void test_unknown_section_and_option(void)
{
	struct pol_db db;
	struct polcfg_stats st;

	load(&db, &st,
	     "config wombat\n\toption colour 'grey'\n"
	     "config subject\n\toption mac 'aa:bb:cc:dd:ee:ff'\n"
	     "\toption favourite_food 'leaves'\n");

	CHECK(st.unknown_section == 1, "an unknown section type is counted");
	CHECK(st.unknown_option == 1, "an unknown option inside a known section too");
	CHECK(st.subjects_added == 1, "the usable part still loaded");
	pol_db_free(&db);
}

static void test_empty_and_degenerate(void)
{
	struct pol_db db;
	struct polcfg_stats st;

	CHECK(load(&db, &st, "") == 0, "an empty file is zero rules, not an error");
	CHECK(!polcfg_had_refusals(&st), "and refuses nothing");
	pol_db_free(&db);

	CHECK(load(&db, &st, "\n\n#only comments\n\n") == 0,
	      "comments only is still zero");
	CHECK(st.bad_syntax == 0, "blank lines are not syntax errors");
	pol_db_free(&db);

	pol_db_init(&db);
	CHECK(polcfg_parse(NULL, NULL, "x", 1, &st) == -1, "NULL db refused");
	CHECK(polcfg_parse(&db, NULL, NULL, 0, &st) == -1, "NULL text refused");
	CHECK(polcfg_parse(&db, NULL, "config subject\n", 14, NULL) == 0,
	      "NULL stats is allowed");
	pol_db_free(&db);
}

static void test_unterminated_quote(void)
{
	struct pol_db db;
	struct polcfg_stats st;

	load(&db, &st, "config subject\n\toption mac 'aa:bb:cc:dd:ee:ff\n");
	CHECK(st.subjects_added == 0, "an unterminated quote does not load");
	pol_db_free(&db);
}

/* A truncated file must not read past its end. */
static void test_truncation_at_every_offset(void)
{
	static const char full[] =
	        "config subject\n\toption mac 'aa:bb:cc:dd:ee:ff'\n"
	        "\toption label 'kid'\n"
	        "config rule\n\toption subject 'aa:bb:cc:dd:ee:ff'\n"
	        "\toption tag 'youtube'\n\toption days 'mon-fri'\n"
	        "\toption start '21:30'\n\toption stop '07:00'\n";
	size_t i;
	int survived = 1;

	for (i = 0; i <= sizeof(full) - 1; i++) {
		struct pol_db db;
		struct polcfg_stats st;

		pol_db_init(&db);
		if (polcfg_parse(&db, NULL, full, i, &st) < 0)
			survived = 0;
		pol_db_free(&db);
	}
	CHECK(survived == 1, "every truncation length parses without crashing");
}

int main(void)
{
	test_basic_subject_and_rule();
	test_quoting_and_comments();
	test_bad_mac_is_counted_not_skipped();
	test_mac_separators();
	test_unknown_subject_is_not_invented();
	test_house_wide_rule_is_refused_visibly();
	test_window_parsing();
	test_window_day_forms();
	test_bad_windows_are_refused();
	test_bad_action_is_refused();
	test_over_long_values_refused_not_truncated();
	test_quota();
	test_disabled_section_is_not_an_error();
	test_unknown_section_and_option();
	test_empty_and_degenerate();
	test_unterminated_quote();
	test_truncation_at_every_offset();
	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
