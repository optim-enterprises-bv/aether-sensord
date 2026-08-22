/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Policy engine for aether-sensord (ADR-020 decisions 4 and 6).
 *
 * Turns a classification into a verdict: this subject, this application, at
 * this moment, with this much used today -> allow or block, and WHY.
 *
 * Two failure modes drive the design, both named in ADR-017 as items that a
 * successful config push cannot distinguish from correct behaviour:
 *
 *   1. TIME WINDOW POLARITY. ADR-017 flags `time_mode` as the one OAF key
 *      family with no source citation, and states the failure plainly: "a
 *      bedtime schedule that grants internet *only* at bedtime". A window is
 *      therefore ALWAYS explicit about its sense here -- `POL_WINDOW_BLOCK_IN`
 *      versus `POL_WINDOW_ALLOW_IN` -- and never inferred from a mode integer.
 *      Both directions are asserted in tests.
 *
 *   2. PER-SUBJECT SCOPING. "the failure mode is a rule that silently applies
 *      household-wide". A rule reaches exactly one subject; there is no
 *      wildcard subject, and a lookup that finds no subject returns ALLOW with
 *      an explicit reason rather than falling through to some default set.
 *
 * Applications are addressed by stable TAG, never by numeric id (ADR-020
 * decision 4) -- see sigdb.h for why that is not a style preference.
 *
 * Pure: no clock, no sockets, no netlink, no nDPI. Time is passed in, so
 * every schedule case is reachable in a unit test.
 */

#ifndef AETHER_SENSORD_POLICY_H
#define AETHER_SENSORD_POLICY_H

#include "sigdb.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define POL_MAX_SUBJECTS 256
#define POL_MAX_RULES 2048
#define POL_MAC_LEN 6

/* Bit per weekday, bit 0 = Sunday, matching struct tm's tm_wday. */
#define POL_DAY(wday) ((uint8_t)(1u << (wday)))
#define POL_ALL_DAYS 0x7Fu

enum pol_action { POL_ALLOW = 0, POL_BLOCK = 1 };

/*
 * The sense of a window, stated rather than encoded as a mode integer.
 *
 * BLOCK_IN : blocked inside the window, allowed outside  (a bedtime rule)
 * ALLOW_IN : allowed inside the window, blocked outside  (a homework-hour rule)
 */
enum pol_window_sense { POL_WINDOW_BLOCK_IN = 0, POL_WINDOW_ALLOW_IN = 1 };

struct pol_window {
	uint16_t start_min; /* minutes from local midnight, inclusive */
	uint16_t end_min;   /* exclusive; may be < start_min to wrap midnight */
	uint8_t days;       /* POL_DAY bitmask */
	enum pol_window_sense sense;
};

/* What a rule is addressed to. */
enum pol_target { POL_TARGET_APP = 0, POL_TARGET_CATEGORY = 1 };

struct pol_rule {
	uint16_t subject_index;
	enum pol_target target;
	/* App tag, or category tag. Never a numeric id -- see sigdb.h. */
	char tag[SIG_TAG_LEN];
	enum pol_action action;

	bool has_window;
	struct pol_window window;

	/* Seconds of use permitted per day, 0 = unlimited. Enforced against a
	 * caller-supplied figure so this stays pure. */
	uint32_t daily_quota_sec;
};

struct pol_subject {
	uint8_t mac[POL_MAC_LEN];
	char label[32]; /* human name for audit, e.g. "kid-tablet" */
};

struct pol_db {
	struct pol_subject *subjects;
	size_t n_subjects;
	struct pol_rule *rules;
	size_t n_rules;

	/* Refused for want of capacity. Reported, never silently dropped
	 * (ADR-020 decision 8). */
	uint32_t rejected_subjects_full;
	uint32_t rejected_rules_full;
	/* Rules naming a tag absent from the signature database. These are a
	 * CoverageGap surfaced at authoring time, not a silent no-op. */
	uint32_t rejected_unknown_tag;
};

/* Why a verdict came out the way it did. Every block must be explainable. */
enum pol_reason {
	POL_REASON_NO_SUBJECT = 0, /* device is not under any policy */
	POL_REASON_NO_RULE,        /* no rule covers this app */
	POL_REASON_RULE,           /* an unconditional rule matched */
	POL_REASON_WINDOW,         /* a schedule decided it */
	POL_REASON_QUOTA           /* the daily allowance is spent */
};

const char *pol_reason_str(enum pol_reason r);
const char *pol_action_str(enum pol_action a);

struct pol_verdict {
	enum pol_action action;
	enum pol_reason reason;
	/* Index of the deciding rule, or SIZE_MAX when none applied. */
	size_t rule_index;
};

/* Wall-clock context, supplied by the caller so tests can reach every case. */
struct pol_time {
	int wday;         /* 0 = Sunday, as struct tm */
	uint16_t min_of_day; /* 0..1439 */
};

bool pol_db_init(struct pol_db *db);
void pol_db_free(struct pol_db *db);

/* Returns the subject index, or SIZE_MAX if refused. */
size_t pol_add_subject(struct pol_db *db, const uint8_t mac[POL_MAC_LEN],
                       const char *label);
size_t pol_find_subject(const struct pol_db *db, const uint8_t mac[POL_MAC_LEN]);

/*
 * Add a rule. `sigs` may be NULL to skip tag validation; when supplied, a tag
 * that names no application is refused and counted, so an unknown app is a
 * visible CoverageGap rather than a rule that quietly never fires.
 */
bool pol_add_rule(struct pol_db *db, const struct sig_db *sigs,
                  const struct pol_rule *rule);

/* Is `t` inside `w`? Handles windows that wrap past midnight. */
bool pol_window_contains(const struct pol_window *w, struct pol_time t);

/*
 * Which day's usage counter should a quota on this rule be read from?
 *
 * Windows and quotas disagree about what "a day" is, and the disagreement is
 * silent. `pol_window_contains` deliberately attributes 02:00 Saturday to
 * FRIDAY's window -- that is what keeps a Friday bedtime in force past
 * midnight. A calendar-day usage counter, by contrast, resets at local
 * midnight.
 *
 * For a rule with BOTH a wrapping window and a quota, that divergence is a
 * bug. Measured, not assumed:
 *
 *   BLOCK_IN (a bedtime rule)  -- immune. The quota only ever tightens
 *     ALLOW into BLOCK, never the reverse, so a midnight counter reset
 *     cannot reopen a window that is blocking.
 *   ALLOW_IN (an allowance rule) -- affected. Quota spent at Fri 23:00
 *     blocks; at Sat 00:30 the counter has reset and the same window session
 *     allows again. A fresh hour appears inside one continuous window.
 *
 * So the caller must attribute usage to the day the WINDOW OPENED, not to the
 * calendar day. This returns that weekday; feed it to whatever holds the
 * per-day counters and pass the result as `used_today_sec`.
 *
 * Kept as a caller obligation rather than solved inside pol_evaluate because
 * this file owns no clock and no storage, and inventing either here would
 * make every schedule case unreachable in a test.
 */
int pol_quota_day(const struct pol_rule *r, struct pol_time now);

/*
 * Decide. `used_today_sec` is this subject's consumption for the app in
 * question; pass 0 when quotas are not in use.
 *
 * Default is ALLOW: a device under no policy, or an app under no rule, is not
 * blocked. Failing closed here would take a household off the internet the
 * moment a rule set failed to load.
 */
struct pol_verdict pol_evaluate(const struct pol_db *db,
                                const uint8_t mac[POL_MAC_LEN],
                                const char *app_tag, const char *category_tag,
                                struct pol_time now, uint32_t used_today_sec);

#endif /* AETHER_SENSORD_POLICY_H */
