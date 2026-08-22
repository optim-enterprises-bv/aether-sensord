/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 */

#include "policy.h"

#include <stdlib.h>
#include <string.h>

const char *pol_reason_str(enum pol_reason r)
{
	switch (r) {
	case POL_REASON_NO_SUBJECT:
		return "no_subject";
	case POL_REASON_NO_RULE:
		return "no_rule";
	case POL_REASON_RULE:
		return "rule";
	case POL_REASON_WINDOW:
		return "window";
	case POL_REASON_QUOTA:
		return "quota";
	default:
		return "unknown";
	}
}

const char *pol_action_str(enum pol_action a)
{
	return a == POL_BLOCK ? "block" : "allow";
}

bool pol_db_init(struct pol_db *db)
{
	if (!db)
		return false;
	memset(db, 0, sizeof(*db));
	db->subjects = calloc(POL_MAX_SUBJECTS, sizeof(struct pol_subject));
	db->rules = calloc(POL_MAX_RULES, sizeof(struct pol_rule));
	if (!db->subjects || !db->rules) {
		free(db->subjects);
		free(db->rules);
		memset(db, 0, sizeof(*db));
		return false;
	}
	return true;
}

void pol_db_free(struct pol_db *db)
{
	if (!db)
		return;
	free(db->subjects);
	free(db->rules);
	memset(db, 0, sizeof(*db));
}

size_t pol_find_subject(const struct pol_db *db, const uint8_t mac[POL_MAC_LEN])
{
	if (!db || !mac)
		return SIZE_MAX;
	for (size_t i = 0; i < db->n_subjects; i++) {
		if (memcmp(db->subjects[i].mac, mac, POL_MAC_LEN) == 0)
			return i;
	}
	return SIZE_MAX;
}

size_t pol_add_subject(struct pol_db *db, const uint8_t mac[POL_MAC_LEN],
                       const char *label)
{
	if (!db || !db->subjects || !mac)
		return SIZE_MAX;

	size_t existing = pol_find_subject(db, mac);
	if (existing != SIZE_MAX)
		return existing;

	if (db->n_subjects >= POL_MAX_SUBJECTS) {
		db->rejected_subjects_full++;
		return SIZE_MAX;
	}

	struct pol_subject *s = &db->subjects[db->n_subjects];
	memset(s, 0, sizeof(*s));
	memcpy(s->mac, mac, POL_MAC_LEN);
	if (label) {
		size_t n = strlen(label);
		if (n >= sizeof(s->label))
			n = sizeof(s->label) - 1;
		memcpy(s->label, label, n);
		s->label[n] = '\0';
	}
	return db->n_subjects++;
}

bool pol_add_rule(struct pol_db *db, const struct sig_db *sigs,
                  const struct pol_rule *rule)
{
	if (!db || !db->rules || !rule)
		return false;
	if (rule->subject_index >= db->n_subjects)
		return false;
	if (rule->tag[0] == '\0')
		return false;

	/* An app rule naming a tag the database does not define would never
	 * fire. ADR-017 requires that be surfaced at authoring time as a
	 * CoverageGap rather than silently approximated, so refuse and count. */
	if (sigs && rule->target == POL_TARGET_APP &&
	    !sig_db_by_tag(sigs, rule->tag)) {
		db->rejected_unknown_tag++;
		return false;
	}

	if (db->n_rules >= POL_MAX_RULES) {
		db->rejected_rules_full++;
		return false;
	}

	db->rules[db->n_rules++] = *rule;
	return true;
}

bool pol_window_contains(const struct pol_window *w, struct pol_time t)
{
	if (!w)
		return false;
	/* Both fields are validated, not just one. An out-of-range minute
	 * behaves differently in the two branches below -- a same-day window
	 * fails safe, but a WRAPPING window tests `min_of_day >= start` first,
	 * so any garbage above start would match. Same asymmetry as an address
	 * screen that guards one family and not the other: refuse what cannot
	 * be classified. */
	if (t.wday < 0 || t.wday > 6)
		return false;
	if (t.min_of_day > 1439)
		return false;

	uint16_t start = w->start_min;
	uint16_t end = w->end_min;

	if (start == end)
		return false; /* an empty window covers nothing */

	if (start < end) {
		/* Ordinary same-day window. The day bit is the day it starts. */
		if (!(w->days & POL_DAY(t.wday)))
			return false;
		return t.min_of_day >= start && t.min_of_day < end;
	}

	/*
	 * Wrapping window, e.g. 21:00-07:00. The day bit refers to the day the
	 * window OPENS, so the morning tail belongs to the previous day's bit --
	 * a "Friday night" bedtime must still be in force at 02:00 on Saturday.
	 * Getting this backwards is a schedule that stops enforcing exactly when
	 * it matters.
	 */
	if (t.min_of_day >= start)
		return (w->days & POL_DAY(t.wday)) != 0;

	if (t.min_of_day < end) {
		int prev = (t.wday + 6) % 7;
		return (w->days & POL_DAY(prev)) != 0;
	}

	return false;
}

int pol_quota_day(const struct pol_rule *r, struct pol_time now)
{
	if (!r || !r->has_window)
		return now.wday;
	/* Non-wrapping window: opens and closes on the same day. */
	if (r->window.start_min < r->window.end_min)
		return now.wday;
	/* Wrapping window, and we are in its morning tail -- the session began
	 * yesterday, so the counter to consult is yesterday's. */
	if (now.min_of_day < r->window.end_min)
		return (now.wday + 6) % 7;
	return now.wday;
}

/* Does this rule address the app or category we classified? */
static bool rule_targets(const struct pol_rule *r, const char *app_tag,
                         const char *category_tag)
{
	if (r->target == POL_TARGET_APP)
		return app_tag && strcmp(r->tag, app_tag) == 0;
	return category_tag && strcmp(r->tag, category_tag) == 0;
}

struct pol_verdict pol_evaluate(const struct pol_db *db,
                                const uint8_t mac[POL_MAC_LEN],
                                const char *app_tag, const char *category_tag,
                                struct pol_time now, uint32_t used_today_sec)
{
	struct pol_verdict v = { POL_ALLOW, POL_REASON_NO_SUBJECT, SIZE_MAX };

	if (!db || !db->rules || !mac)
		return v;

	size_t subject = pol_find_subject(db, mac);
	if (subject == SIZE_MAX) {
		/* Not under policy. Explicitly allowed, with a reason -- never a
		 * fall-through into another subject's rules. */
		return v;
	}

	v.reason = POL_REASON_NO_RULE;

	/*
	 * Specificity: an app rule outranks a category rule, because a
	 * subscriber who allows one app inside a blocked category means it.
	 * Within the same specificity, the first matching rule wins, which
	 * makes the outcome deterministic for a given rule set.
	 */
	bool decided_by_app = false;
	bool decided_by_category = false;

	for (size_t i = 0; i < db->n_rules; i++) {
		const struct pol_rule *r = &db->rules[i];
		if (r->subject_index != subject)
			continue;
		if (!rule_targets(r, app_tag, category_tag))
			continue;
		/* First match wins WITHIN a target class, which is what the
		 * comment above always claimed. The loop previously had no such
		 * guard for app rules, so a second app rule silently overrode
		 * the first -- deterministic, but the opposite of documented. */
		if (r->target == POL_TARGET_APP && decided_by_app)
			continue;
		if (r->target == POL_TARGET_CATEGORY &&
		    (decided_by_app || decided_by_category))
			continue;

		enum pol_action action = r->action;
		enum pol_reason reason = POL_REASON_RULE;

		if (r->has_window) {
			bool inside = pol_window_contains(&r->window, now);
			/*
			 * The sense is stated by the rule, never inferred. See
			 * policy.h: the failure this prevents is a bedtime
			 * schedule that grants internet only at bedtime.
			 */
			if (r->window.sense == POL_WINDOW_BLOCK_IN)
				action = inside ? POL_BLOCK : POL_ALLOW;
			else
				action = inside ? POL_ALLOW : POL_BLOCK;
			reason = POL_REASON_WINDOW;
		}

		/* A spent quota blocks regardless of what the window said, but
		 * only for a rule that would otherwise have allowed. */
		if (action == POL_ALLOW && r->daily_quota_sec > 0 &&
		    used_today_sec >= r->daily_quota_sec) {
			action = POL_BLOCK;
			reason = POL_REASON_QUOTA;
		}

		v.action = action;
		v.reason = reason;
		v.rule_index = i;

		if (r->target == POL_TARGET_APP)
			decided_by_app = true;
		else
			decided_by_category = true;
	}

	return v;
}
