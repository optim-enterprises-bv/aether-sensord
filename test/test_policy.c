/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Host tests for the policy engine.
 *
 * The two headline cases are the failure modes ADR-017 names as
 * indistinguishable from a successful config push:
 *
 *   - a bedtime schedule that grants internet ONLY at bedtime (polarity)
 *   - a rule that silently applies household-wide (scoping)
 *
 * Both are asserted in both directions. A schedule test that only checks the
 * blocked case passes just as happily when the polarity is inverted.
 */

#include "../src/policy.h"

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

#define MIN(h, m) ((uint16_t)((h) * 60 + (m)))

static const uint8_t KID[6]    = { 0x02, 0, 0, 0, 0, 0x01 };
static const uint8_t PARENT[6] = { 0x02, 0, 0, 0, 0, 0x02 };
static const uint8_t GUEST[6]  = { 0x02, 0, 0, 0, 0, 0x03 };

/* Sunday=0 .. Saturday=6 */
enum { SUN = 0, MON = 1, TUE = 2, WED = 3, THU = 4, FRI = 5, SAT = 6 };

static struct pol_time at(int wday, int h, int m)
{
	struct pol_time t = { wday, MIN(h, m) };
	return t;
}

/* ------------------------------------------------------- polarity --- */

static void test_bedtime_blocks_at_night_not_during_the_day(void)
{
	/* THE failure ADR-017 names: "a bedtime schedule that grants internet
	 * *only* at bedtime". Asserted in both directions so an inverted
	 * polarity cannot pass. */
	struct pol_db db;
	pol_db_init(&db);
	size_t kid = pol_add_subject(&db, KID, "kid-tablet");

	struct pol_rule r;
	memset(&r, 0, sizeof(r));
	r.subject_index = (uint16_t)kid;
	r.target = POL_TARGET_APP;
	snprintf(r.tag, sizeof(r.tag), "youtube");
	r.action = POL_BLOCK;
	r.has_window = true;
	r.window.start_min = MIN(21, 0);
	r.window.end_min = MIN(7, 0);
	r.window.days = POL_ALL_DAYS;
	r.window.sense = POL_WINDOW_BLOCK_IN; /* blocked INSIDE 21:00-07:00 */
	CHECK(pol_add_rule(&db, NULL, &r), "rule added");

	struct pol_verdict v;

	/* Bedtime: blocked. */
	v = pol_evaluate(&db, KID, "youtube", NULL, at(WED, 22, 30), 0);
	CHECK(v.action == POL_BLOCK, "22:30 blocked");
	CHECK(v.reason == POL_REASON_WINDOW, "decided by the window");

	v = pol_evaluate(&db, KID, "youtube", NULL, at(THU, 2, 0), 0);
	CHECK(v.action == POL_BLOCK, "02:00 blocked (window has wrapped)");

	v = pol_evaluate(&db, KID, "youtube", NULL, at(WED, 6, 59), 0);
	CHECK(v.action == POL_BLOCK, "06:59 still blocked");

	/* Daytime: allowed. This is the half that catches an inversion. */
	v = pol_evaluate(&db, KID, "youtube", NULL, at(WED, 7, 0), 0);
	CHECK(v.action == POL_ALLOW, "07:00 allowed -- window is exclusive at end");

	v = pol_evaluate(&db, KID, "youtube", NULL, at(WED, 15, 0), 0);
	CHECK(v.action == POL_ALLOW, "15:00 allowed");

	v = pol_evaluate(&db, KID, "youtube", NULL, at(WED, 20, 59), 0);
	CHECK(v.action == POL_ALLOW, "20:59 allowed");

	pol_db_free(&db);
}

static void test_allow_in_is_the_mirror_image(void)
{
	/* Homework hours: allowed ONLY inside the window. If the two senses
	 * were confused this test and the previous one would disagree. */
	struct pol_db db;
	pol_db_init(&db);
	size_t kid = pol_add_subject(&db, KID, "kid-tablet");

	struct pol_rule r;
	memset(&r, 0, sizeof(r));
	r.subject_index = (uint16_t)kid;
	r.target = POL_TARGET_APP;
	snprintf(r.tag, sizeof(r.tag), "youtube");
	r.has_window = true;
	r.window.start_min = MIN(16, 0);
	r.window.end_min = MIN(18, 0);
	r.window.days = POL_ALL_DAYS;
	r.window.sense = POL_WINDOW_ALLOW_IN;
	pol_add_rule(&db, NULL, &r);

	struct pol_verdict v;
	v = pol_evaluate(&db, KID, "youtube", NULL, at(MON, 17, 0), 0);
	CHECK(v.action == POL_ALLOW, "inside allow-window -> allowed");
	v = pol_evaluate(&db, KID, "youtube", NULL, at(MON, 19, 0), 0);
	CHECK(v.action == POL_BLOCK, "outside allow-window -> blocked");

	pol_db_free(&db);
}

static void test_wrapping_window_belongs_to_the_day_it_opens(void)
{
	/* A Friday-night bedtime must still be in force at 02:00 on Saturday.
	 * If the morning tail were attributed to Saturday's bit, the rule would
	 * stop enforcing exactly when it matters. */
	struct pol_db db;
	pol_db_init(&db);
	size_t kid = pol_add_subject(&db, KID, "kid-tablet");

	struct pol_rule r;
	memset(&r, 0, sizeof(r));
	r.subject_index = (uint16_t)kid;
	r.target = POL_TARGET_APP;
	snprintf(r.tag, sizeof(r.tag), "youtube");
	r.action = POL_BLOCK;
	r.has_window = true;
	r.window.start_min = MIN(21, 0);
	r.window.end_min = MIN(7, 0);
	r.window.days = POL_DAY(FRI); /* Friday only */
	r.window.sense = POL_WINDOW_BLOCK_IN;
	pol_add_rule(&db, NULL, &r);

	struct pol_verdict v;
	v = pol_evaluate(&db, KID, "youtube", NULL, at(FRI, 23, 0), 0);
	CHECK(v.action == POL_BLOCK, "Friday 23:00 blocked");
	v = pol_evaluate(&db, KID, "youtube", NULL, at(SAT, 2, 0), 0);
	CHECK(v.action == POL_BLOCK, "Saturday 02:00 still blocked -- same window");
	v = pol_evaluate(&db, KID, "youtube", NULL, at(SAT, 23, 0), 0);
	CHECK(v.action == POL_ALLOW, "Saturday 23:00 NOT blocked -- Friday only");
	v = pol_evaluate(&db, KID, "youtube", NULL, at(SUN, 2, 0), 0);
	CHECK(v.action == POL_ALLOW, "Sunday 02:00 not blocked");

	pol_db_free(&db);
}

static void test_window_edges(void)
{
	struct pol_window w = { MIN(9, 0), MIN(17, 0), POL_ALL_DAYS,
		                POL_WINDOW_BLOCK_IN };
	CHECK(pol_window_contains(&w, at(MON, 9, 0)), "start is inclusive");
	CHECK(!pol_window_contains(&w, at(MON, 17, 0)), "end is exclusive");
	CHECK(pol_window_contains(&w, at(MON, 16, 59)), "just inside");
	CHECK(!pol_window_contains(&w, at(MON, 8, 59)), "just before");

	struct pol_window empty = { MIN(9, 0), MIN(9, 0), POL_ALL_DAYS,
		                    POL_WINDOW_BLOCK_IN };
	CHECK(!pol_window_contains(&empty, at(MON, 9, 0)),
	      "an empty window covers nothing");
}

/* -------------------------------------------------------- scoping --- */

static void test_a_rule_reaches_exactly_one_subject(void)
{
	/* ADR-017: "the failure mode is a rule that silently applies
	 * household-wide". */
	struct pol_db db;
	pol_db_init(&db);
	size_t kid = pol_add_subject(&db, KID, "kid-tablet");
	pol_add_subject(&db, PARENT, "parent-phone");

	struct pol_rule r;
	memset(&r, 0, sizeof(r));
	r.subject_index = (uint16_t)kid;
	r.target = POL_TARGET_APP;
	snprintf(r.tag, sizeof(r.tag), "youtube");
	r.action = POL_BLOCK;
	pol_add_rule(&db, NULL, &r);

	struct pol_verdict v;
	v = pol_evaluate(&db, KID, "youtube", NULL, at(WED, 15, 0), 0);
	CHECK(v.action == POL_BLOCK, "the targeted device is blocked");

	v = pol_evaluate(&db, PARENT, "youtube", NULL, at(WED, 15, 0), 0);
	CHECK(v.action == POL_ALLOW, "another enrolled device is NOT blocked");
	CHECK(v.reason == POL_REASON_NO_RULE, "and says why");

	v = pol_evaluate(&db, GUEST, "youtube", NULL, at(WED, 15, 0), 0);
	CHECK(v.action == POL_ALLOW, "an unenrolled device is not blocked");
	CHECK(v.reason == POL_REASON_NO_SUBJECT,
	      "unenrolled is explicit, not a fall-through into someone's rules");

	pol_db_free(&db);
}

static void test_default_is_allow(void)
{
	/* Failing closed would take a household off the internet the moment a
	 * rule set failed to load. */
	struct pol_db db;
	pol_db_init(&db);
	struct pol_verdict v =
	    pol_evaluate(&db, KID, "youtube", NULL, at(WED, 15, 0), 0);
	CHECK(v.action == POL_ALLOW, "empty policy allows");
	CHECK(v.reason == POL_REASON_NO_SUBJECT, "with a reason");
	pol_db_free(&db);
}

/* --------------------------------------------------------- quota --- */

static void test_daily_quota(void)
{
	struct pol_db db;
	pol_db_init(&db);
	size_t kid = pol_add_subject(&db, KID, "kid-tablet");

	struct pol_rule r;
	memset(&r, 0, sizeof(r));
	r.subject_index = (uint16_t)kid;
	r.target = POL_TARGET_APP;
	snprintf(r.tag, sizeof(r.tag), "youtube");
	r.action = POL_ALLOW;
	r.daily_quota_sec = 3600;
	pol_add_rule(&db, NULL, &r);

	struct pol_verdict v;
	v = pol_evaluate(&db, KID, "youtube", NULL, at(WED, 15, 0), 0);
	CHECK(v.action == POL_ALLOW, "unused quota allows");

	v = pol_evaluate(&db, KID, "youtube", NULL, at(WED, 15, 0), 3599);
	CHECK(v.action == POL_ALLOW, "just under the allowance");

	v = pol_evaluate(&db, KID, "youtube", NULL, at(WED, 15, 0), 3600);
	CHECK(v.action == POL_BLOCK, "allowance spent");
	CHECK(v.reason == POL_REASON_QUOTA, "reported as quota, not as a rule");

	pol_db_free(&db);
}

static void test_quota_does_not_resurrect_a_blocked_window(void)
{
	/* Unused quota must not override a bedtime block. */
	struct pol_db db;
	pol_db_init(&db);
	size_t kid = pol_add_subject(&db, KID, "kid-tablet");

	struct pol_rule r;
	memset(&r, 0, sizeof(r));
	r.subject_index = (uint16_t)kid;
	r.target = POL_TARGET_APP;
	snprintf(r.tag, sizeof(r.tag), "youtube");
	r.has_window = true;
	r.window.start_min = MIN(21, 0);
	r.window.end_min = MIN(7, 0);
	r.window.days = POL_ALL_DAYS;
	r.window.sense = POL_WINDOW_BLOCK_IN;
	r.daily_quota_sec = 3600;
	pol_add_rule(&db, NULL, &r);

	struct pol_verdict v =
	    pol_evaluate(&db, KID, "youtube", NULL, at(WED, 22, 0), 0);
	CHECK(v.action == POL_BLOCK, "bedtime wins over unspent quota");
	CHECK(v.reason == POL_REASON_WINDOW, "and the reason is the window");

	pol_db_free(&db);
}

/* ------------------------------------------------ specificity --- */

static void test_app_rule_beats_category_rule(void)
{
	/* A subscriber who allows one app inside a blocked category means it. */
	struct pol_db db;
	pol_db_init(&db);
	size_t kid = pol_add_subject(&db, KID, "kid-tablet");

	struct pol_rule cat;
	memset(&cat, 0, sizeof(cat));
	cat.subject_index = (uint16_t)kid;
	cat.target = POL_TARGET_CATEGORY;
	snprintf(cat.tag, sizeof(cat.tag), "streaming");
	cat.action = POL_BLOCK;
	pol_add_rule(&db, NULL, &cat);

	struct pol_rule app;
	memset(&app, 0, sizeof(app));
	app.subject_index = (uint16_t)kid;
	app.target = POL_TARGET_APP;
	snprintf(app.tag, sizeof(app.tag), "youtube");
	app.action = POL_ALLOW;
	pol_add_rule(&db, NULL, &app);

	struct pol_verdict v;
	v = pol_evaluate(&db, KID, "youtube", "streaming", at(WED, 15, 0), 0);
	CHECK(v.action == POL_ALLOW, "the app exception wins");

	v = pol_evaluate(&db, KID, "netflix", "streaming", at(WED, 15, 0), 0);
	CHECK(v.action == POL_BLOCK, "the rest of the category is still blocked");

	pol_db_free(&db);
}

/* -------------------------------------------------- authoring --- */

static void test_unknown_tag_is_refused_not_silently_dead(void)
{
	/* ADR-017: a coverage gap must be visible at authoring time, not a rule
	 * that quietly never fires. */
	struct sig_db sigs;
	sig_db_init(&sigs);
	const char *text = "39037 YouTube:[tcp;;;www.youtube.com;;]\n";
	FILE *fp = fmemopen((void *)text, strlen(text), "r");
	sig_db_load(&sigs, fp);
	fclose(fp);

	struct pol_db db;
	pol_db_init(&db);
	size_t kid = pol_add_subject(&db, KID, "kid-tablet");

	struct pol_rule good;
	memset(&good, 0, sizeof(good));
	good.subject_index = (uint16_t)kid;
	good.target = POL_TARGET_APP;
	snprintf(good.tag, sizeof(good.tag), "youtube");
	good.action = POL_BLOCK;
	CHECK(pol_add_rule(&db, &sigs, &good), "known tag accepted");

	struct pol_rule bad = good;
	snprintf(bad.tag, sizeof(bad.tag), "definitely-not-an-app");
	CHECK(!pol_add_rule(&db, &sigs, &bad), "unknown tag refused");
	CHECK(db.rejected_unknown_tag == 1, "and counted");

	pol_db_free(&db);
	sig_db_free(&sigs);
}

static void test_capacity_refused_and_counted(void)
{
	struct pol_db db;
	pol_db_init(&db);
	size_t kid = pol_add_subject(&db, KID, "kid");

	struct pol_rule r;
	memset(&r, 0, sizeof(r));
	r.subject_index = (uint16_t)kid;
	r.target = POL_TARGET_APP;
	r.action = POL_BLOCK;
	for (int i = 0; i < POL_MAX_RULES + 10; i++) {
		snprintf(r.tag, sizeof(r.tag), "app%d", i);
		pol_add_rule(&db, NULL, &r);
	}
	CHECK(db.n_rules == POL_MAX_RULES, "bounded");
	CHECK(db.rejected_rules_full == 10, "overflow refused AND counted");
	pol_db_free(&db);
}

static void test_quota_day_follows_the_window_not_the_calendar(void)
{
	/* The divergence found in review. Verified empirically before fixing:
	 * BLOCK_IN is immune because the quota only tightens, but ALLOW_IN with
	 * a wrapping window handed out a fresh allowance at midnight inside one
	 * continuous window session. pol_quota_day tells the caller which day's
	 * counter to read so the two halves of a rule agree. */
	struct pol_rule r;
	memset(&r, 0, sizeof(r));
	r.has_window = true;
	r.window.start_min = MIN(21, 0);
	r.window.end_min = MIN(7, 0);
	r.window.days = POL_DAY(FRI);
	r.window.sense = POL_WINDOW_ALLOW_IN;
	r.daily_quota_sec = 3600;

	/* Before midnight: the window opened today, so today's counter. */
	CHECK(pol_quota_day(&r, at(FRI, 23, 0)) == FRI, "Fri 23:00 -> Friday");
	/* After midnight, still inside: the session began YESTERDAY. */
	CHECK(pol_quota_day(&r, at(SAT, 0, 30)) == FRI,
	      "Sat 00:30 -> Friday, so the allowance does not reset mid-session");
	CHECK(pol_quota_day(&r, at(SAT, 6, 59)) == FRI, "Sat 06:59 -> Friday");
	/* Past the window: ordinary calendar day again. */
	CHECK(pol_quota_day(&r, at(SAT, 7, 0)) == SAT, "Sat 07:00 -> Saturday");
	CHECK(pol_quota_day(&r, at(SAT, 12, 0)) == SAT, "Sat midday -> Saturday");

	/* A non-wrapping window never diverges. */
	struct pol_rule day;
	memset(&day, 0, sizeof(day));
	day.has_window = true;
	day.window.start_min = MIN(9, 0);
	day.window.end_min = MIN(17, 0);
	CHECK(pol_quota_day(&day, at(WED, 10, 0)) == WED, "same-day window");

	/* No window at all: plain calendar day. */
	struct pol_rule plain;
	memset(&plain, 0, sizeof(plain));
	CHECK(pol_quota_day(&plain, at(WED, 10, 0)) == WED, "no window");
}

static void test_first_app_rule_wins(void)
{
	/* The comment always claimed first-wins; the loop had no guard, so a
	 * second app rule silently overrode the first. Both orders asserted so
	 * a regression to last-wins cannot pass. */
	struct pol_db db;
	pol_db_init(&db);
	size_t kid = pol_add_subject(&db, KID, "kid");

	struct pol_rule a;
	memset(&a, 0, sizeof(a));
	a.subject_index = (uint16_t)kid;
	a.target = POL_TARGET_APP;
	snprintf(a.tag, sizeof(a.tag), "youtube");
	a.action = POL_BLOCK;
	pol_add_rule(&db, NULL, &a);

	struct pol_rule b = a;
	b.action = POL_ALLOW; /* same subject, same tag, added later */
	pol_add_rule(&db, NULL, &b);

	struct pol_verdict v =
	    pol_evaluate(&db, KID, "youtube", NULL, at(WED, 15, 0), 0);
	CHECK(v.action == POL_BLOCK, "the FIRST app rule decides");
	CHECK(v.rule_index == 0, "and it is rule 0, not the later one");

	pol_db_free(&db);
}

static void test_out_of_range_minute_is_refused(void)
{
	/* A wrapping window tests `min_of_day >= start` first, so garbage above
	 * start would match. Both fields are validated now, not just wday. */
	struct pol_window wrap = { MIN(21, 0), MIN(7, 0), POL_ALL_DAYS,
		                   POL_WINDOW_BLOCK_IN };
	struct pol_time bad = { WED, 9999 };
	CHECK(!pol_window_contains(&wrap, bad),
	      "out-of-range minute refused, not treated as inside");

	struct pol_time bad_day = { 9, MIN(22, 0) };
	CHECK(!pol_window_contains(&wrap, bad_day), "out-of-range weekday refused");

	struct pol_time ok = { WED, 1439 };
	CHECK(pol_window_contains(&wrap, ok), "23:59 is still valid");
}

int main(void)
{
	test_bedtime_blocks_at_night_not_during_the_day();
	test_allow_in_is_the_mirror_image();
	test_wrapping_window_belongs_to_the_day_it_opens();
	test_window_edges();
	test_a_rule_reaches_exactly_one_subject();
	test_default_is_allow();
	test_daily_quota();
	test_quota_does_not_resurrect_a_blocked_window();
	test_app_rule_beats_category_rule();
	test_unknown_tag_is_refused_not_silently_dead();
	test_capacity_refused_and_counted();
	test_quota_day_follows_the_window_not_the_calendar();
	test_first_app_rule_wins();
	test_out_of_range_minute_is_refused();

	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
