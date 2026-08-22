/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 */

#include "polcfg.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define PC_MAX_LINE 512
#define PC_MAX_FILE (1u << 20) /* 1 MiB: a policy file is small by nature */

/* ---- tokenising ---------------------------------------------------------
 *
 * UCI's grammar is small: a keyword, then one or two values, each optionally
 * single- or double-quoted with backslash escapes. Everything after an
 * unquoted '#' is a comment.
 */

static const char *pc_skip_ws(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t'))
		p++;
	return p;
}

/*
 * Read one token into `out`.
 *
 * Returns the position after the token, or NULL if the token is malformed --
 * which for our purposes means an unterminated quote. Truncation is also a
 * failure rather than a silent shortening: a tag or MAC cut in half would be
 * refused later anyway, but as the wrong error.
 */
static const char *pc_token(const char *p, const char *end, char *out,
                            size_t out_cap, bool *ok)
{
	size_t n = 0;
	char quote = 0;
	bool closed = false;

	*ok = false;
	p = pc_skip_ws(p, end);
	if (p >= end)
		return p;

	if (*p == '\'' || *p == '"') {
		quote = *p;
		p++;
	}

	while (p < end) {
		char c = *p;

		if (quote) {
			if (c == quote) {
				p++;
				closed = true;
				break;
			}
			/* Backslash escapes the next byte, whatever it is. */
			if (c == '\\' && p + 1 < end) {
				p++;
				c = *p;
			}
		} else {
			if (c == ' ' || c == '\t' || c == '#')
				break;
		}
		if (n + 1 >= out_cap)
			return NULL; /* would truncate: refuse rather than shorten */
		out[n++] = c;
		p++;
	}

	/*
	 * An opened quote must close on the same line.
	 *
	 * Reading to end-of-line instead would accept 'aa:bb:cc:dd:ee:ff with
	 * no closing quote as a perfectly good MAC -- a typo that silently
	 * loads a rule nobody wrote. Refuse it as the syntax error it is.
	 */
	if (quote && !closed)
		return NULL;

	out[n] = '\0';
	*ok = true;
	return p;
}

/* ---- value parsing ------------------------------------------------------ */

static bool pc_parse_mac(const char *s, uint8_t out[POL_MAC_LEN])
{
	size_t i;
	unsigned v[POL_MAC_LEN];

	if (!s)
		return false;
	/* Accept aa:bb:cc:dd:ee:ff and aa-bb-cc-dd-ee-ff, nothing else. A
	 * lenient parser here would accept a typo and produce a rule aimed at
	 * a device that does not exist. */
	if (strlen(s) != 17)
		return false;
	for (i = 0; i < 5; i++) {
		char sep = s[2 + i * 3];

		if (sep != ':' && sep != '-')
			return false;
	}
	if (sscanf(s, "%2x%*c%2x%*c%2x%*c%2x%*c%2x%*c%2x", &v[0], &v[1], &v[2],
	           &v[3], &v[4], &v[5]) != 6)
		return false;
	for (i = 0; i < POL_MAC_LEN; i++) {
		if (v[i] > 0xff)
			return false;
		out[i] = (uint8_t)v[i];
	}
	return true;
}

/* "HH:MM" or a plain minute count. Returns -1 if out of 0..1439. */
static int pc_parse_minute(const char *s)
{
	const char *colon;
	long h, m;
	char *endp;

	if (!s || !*s)
		return -1;
	colon = strchr(s, ':');
	if (colon) {
		h = strtol(s, &endp, 10);
		if (endp != colon)
			return -1;
		m = strtol(colon + 1, &endp, 10);
		if (*endp != '\0')
			return -1;
		if (h < 0 || h > 23 || m < 0 || m > 59)
			return -1;
		return (int)(h * 60 + m);
	}
	m = strtol(s, &endp, 10);
	if (*endp != '\0' || m < 0 || m > 1439)
		return -1;
	return (int)m;
}

/*
 * Day list: "mon,tue,wed" / "mon-fri" / "all" / "1,2,3" (0 = Sunday).
 *
 * Returns 0 on failure, which is also "no days" -- and a window covering no
 * days can never fire, so both are refused identically and deliberately.
 */
static uint8_t pc_parse_days(const char *s)
{
	static const char *const names[7] = { "sun", "mon", "tue", "wed",
		                              "thu", "fri", "sat" };
	uint8_t mask = 0;
	char buf[128];
	char *tok, *save = NULL;

	if (!s || !*s)
		return 0;
	if (strlen(s) >= sizeof(buf))
		return 0;
	strcpy(buf, s);
	for (char *q = buf; *q; q++)
		*q = (char)tolower((unsigned char)*q);

	if (strcmp(buf, "all") == 0 || strcmp(buf, "daily") == 0)
		return 0x7f;

	for (tok = strtok_r(buf, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		char *dash = strchr(tok, '-');
		int from = -1, to = -1, i;

		if (dash) {
			*dash = '\0';
			for (i = 0; i < 7; i++) {
				if (strcmp(tok, names[i]) == 0)
					from = i;
				if (strcmp(dash + 1, names[i]) == 0)
					to = i;
			}
			if (from < 0 || to < 0)
				return 0;
			/* Ranges wrap: fri-mon is Fri, Sat, Sun, Mon. */
			for (i = from;; i = (i + 1) % 7) {
				mask |= POL_DAY(i);
				if (i == to)
					break;
			}
			continue;
		}
		for (i = 0; i < 7; i++) {
			if (strcmp(tok, names[i]) == 0) {
				mask |= POL_DAY(i);
				break;
			}
		}
		if (i == 7) {
			/* Numeric form. */
			char *endp;
			long d = strtol(tok, &endp, 10);

			if (*endp != '\0' || d < 0 || d > 6)
				return 0;
			mask |= POL_DAY((int)d);
		}
	}
	return mask;
}

/*
 * Copy a value, refusing rather than truncating.
 *
 * A silently-shortened tag or MAC becomes a rule aimed at something else, or
 * at nothing -- and it would still be counted as accepted. Refusing keeps the
 * count honest: what this loader reports as added is what the engine can act
 * on.
 */
static bool pc_take(char *dst, size_t cap, const char *src)
{
	size_t n = strlen(src);

	if (n >= cap)
		return false;
	memcpy(dst, src, n + 1);
	return true;
}

/* ---- section assembly --------------------------------------------------- */

enum pc_section { PC_NONE = 0, PC_SUBJECT, PC_RULE, PC_UNKNOWN };

struct pc_pending {
	enum pc_section kind;

	/* subject */
	uint8_t mac[POL_MAC_LEN];
	bool has_mac;
	char label[32];

	/* rule */
	char subject_mac[32];
	bool has_subject_mac;
	char tag[SIG_TAG_LEN];
	bool has_tag;
	enum pol_target target;
	enum pol_action action;
	bool has_action;

	bool has_window;
	char w_days[128];
	char w_start[32];
	char w_end[32];
	char w_sense[32];

	uint32_t quota;

	/* Set when a value in this section was rejected. The section is then
	 * dropped whole rather than committed half-configured -- a rule with a
	 * silently-missing window is a rule that fires all day. */
	bool poisoned;
};

static void pc_reset(struct pc_pending *p, enum pc_section kind)
{
	memset(p, 0, sizeof(*p));
	p->kind = kind;
	p->target = POL_TARGET_APP;
	p->action = POL_BLOCK;
}

static void pc_commit(struct pc_pending *p, struct pol_db *db,
                      const struct sig_db *sigs, struct polcfg_stats *st)
{
	if (p->kind == PC_NONE || p->kind == PC_UNKNOWN)
		return;

	if (p->poisoned)
		return; /* already counted where it was detected */

	if (p->kind == PC_SUBJECT) {
		if (!p->has_mac) {
			st->bad_mac++;
			return;
		}
		if (pol_add_subject(db, p->mac, p->label) == SIZE_MAX) {
			st->refused_by_policy++;
			return;
		}
		st->subjects_added++;
		return;
	}

	/* PC_RULE */
	{
		struct pol_rule r;
		size_t si = 0;

		if (!p->has_tag) {
			st->missing_tag++;
			return;
		}

		memset(&r, 0, sizeof(r));
		r.target = p->target;
		r.action = p->has_action ? p->action : POL_BLOCK;
		r.daily_quota_sec = p->quota;
		memcpy(r.tag, p->tag, sizeof(r.tag));

		if (p->has_subject_mac) {
			uint8_t mac[POL_MAC_LEN];

			if (!pc_parse_mac(p->subject_mac, mac)) {
				st->bad_mac++;
				return;
			}
			si = pol_find_subject(db, mac);
			if (si == SIZE_MAX) {
				/* Deliberately NOT auto-created. A rule aimed
				 * at a device nobody declared is far more
				 * likely a typo than an intention, and
				 * inventing the subject would make the typo
				 * enforce against nothing, invisibly. */
				st->unknown_subject++;
				return;
			}
			r.subject_index = (uint16_t)si;
		} else {
			/*
			 * The policy engine has no "all devices" subject:
			 * pol_add_rule requires an index below n_subjects and
			 * pol_evaluate matches it exactly. A house-wide rule
			 * therefore cannot be represented, and this refuses it
			 * rather than inventing semantics the evaluator does
			 * not implement.
			 *
			 * Expanding it into one rule per declared subject was
			 * considered and rejected: it would silently multiply
			 * the rule count, quietly miss any device not yet
			 * declared, and make "block YouTube everywhere" mean
			 * something different the day a new device joins.
			 *
			 * KNOWN GAP, deliberately visible rather than papered
			 * over -- "block this for the whole house" is an
			 * ordinary thing to want. See ADR-020.
			 */
			st->no_subject++;
			return;
		}

		if (p->has_window) {
			int s_min = pc_parse_minute(p->w_start);
			int e_min = pc_parse_minute(p->w_end);
			uint8_t days = pc_parse_days(p->w_days);

			if (s_min < 0 || e_min < 0 || days == 0) {
				st->bad_window++;
				return;
			}
			if (s_min == e_min) {
				/* Zero-length. Refused rather than treated as
				 * "all day" or "never" -- both readings are
				 * defensible, which is exactly why guessing
				 * one is wrong. */
				st->bad_window++;
				return;
			}
			r.has_window = true;
			r.window.start_min = (uint16_t)s_min;
			r.window.end_min = (uint16_t)e_min;
			r.window.days = days;
			r.window.sense = POL_WINDOW_BLOCK_IN;
			if (p->w_sense[0]) {
				if (strcmp(p->w_sense, "allow_in") == 0 ||
				    strcmp(p->w_sense, "allow-in") == 0)
					r.window.sense = POL_WINDOW_ALLOW_IN;
				else if (strcmp(p->w_sense, "block_in") != 0 &&
				         strcmp(p->w_sense, "block-in") != 0) {
					st->bad_window++;
					return;
				}
			}
		}

		if (!pol_add_rule(db, sigs, &r)) {
			st->refused_by_policy++;
			return;
		}
		st->rules_added++;
	}
}

/* ---- the parser --------------------------------------------------------- */

static bool pc_streq(const char *a, const char *b)
{
	return strcmp(a, b) == 0;
}

long polcfg_parse(struct pol_db *db, const struct sig_db *sigs,
                  const char *text, size_t len, struct polcfg_stats *stats)
{
	struct polcfg_stats local;
	struct pc_pending pend;
	const char *p, *end;

	if (!db || !text)
		return -1;
	if (!stats)
		stats = &local;
	memset(stats, 0, sizeof(*stats));
	pc_reset(&pend, PC_NONE);

	p = text;
	end = text + len;

	while (p < end) {
		const char *eol = memchr(p, '\n', (size_t)(end - p));
		const char *line_end = eol ? eol : end;
		const char *q;
		char kw[64], a[PC_MAX_LINE], b[PC_MAX_LINE];
		bool ok;

		/* Strip a trailing CR so CRLF files behave. */
		if (line_end > p && line_end[-1] == '\r')
			line_end--;

		q = pc_skip_ws(p, line_end);
		if (q >= line_end || *q == '#') {
			p = eol ? eol + 1 : end;
			continue;
		}

		q = pc_token(q, line_end, kw, sizeof(kw), &ok);
		if (!q || !ok || kw[0] == '\0') {
			stats->bad_syntax++;
			p = eol ? eol + 1 : end;
			continue;
		}

		if (pc_streq(kw, "config")) {
			/* A new section ends the previous one. */
			pc_commit(&pend, db, sigs, stats);
			stats->sections++;

			q = pc_token(q, line_end, a, sizeof(a), &ok);
			if (!q || !ok || a[0] == '\0') {
				stats->bad_syntax++;
				pc_reset(&pend, PC_UNKNOWN);
				p = eol ? eol + 1 : end;
				continue;
			}
			if (pc_streq(a, "subject") || pc_streq(a, "device"))
				pc_reset(&pend, PC_SUBJECT);
			else if (pc_streq(a, "rule") || pc_streq(a, "app_rule"))
				pc_reset(&pend, PC_RULE);
			else {
				pc_reset(&pend, PC_UNKNOWN);
				stats->unknown_section++;
			}
			p = eol ? eol + 1 : end;
			continue;
		}

		if (!pc_streq(kw, "option") && !pc_streq(kw, "list")) {
			stats->bad_syntax++;
			p = eol ? eol + 1 : end;
			continue;
		}

		q = pc_token(q, line_end, a, sizeof(a), &ok);
		if (!q || !ok || a[0] == '\0') {
			stats->bad_syntax++;
			p = eol ? eol + 1 : end;
			continue;
		}
		q = pc_token(q, line_end, b, sizeof(b), &ok);
		if (!q || !ok) {
			stats->bad_syntax++;
			p = eol ? eol + 1 : end;
			continue;
		}

		if (pend.kind == PC_UNKNOWN || pend.kind == PC_NONE) {
			/* An option outside any section we handle. Counted, so
			 * a file whose sections are all misspelled does not
			 * look like an empty file. */
			if (pend.kind == PC_NONE)
				stats->bad_syntax++;
			p = eol ? eol + 1 : end;
			continue;
		}

		if (pend.kind == PC_SUBJECT) {
			if (pc_streq(a, "mac")) {
				if (!pc_parse_mac(b, pend.mac)) {
					stats->bad_mac++;
					pend.poisoned = true;
				} else {
					pend.has_mac = true;
				}
			} else if (pc_streq(a, "label") || pc_streq(a, "name")) {
				if (!pc_take(pend.label, sizeof(pend.label), b)) {
					stats->unknown_option++;
					pend.poisoned = true;
				}
			} else {
				stats->unknown_option++;
			}
			p = eol ? eol + 1 : end;
			continue;
		}

		/* PC_RULE */
		if (pc_streq(a, "subject") || pc_streq(a, "mac")) {
			if (pc_streq(b, "*") || pc_streq(b, "all") ||
			    pc_streq(b, "")) {
				pend.has_subject_mac = false;
			} else {
				if (!pc_take(pend.subject_mac,
				             sizeof(pend.subject_mac), b)) {
					stats->bad_mac++;
					pend.poisoned = true;
				} else {
					pend.has_subject_mac = true;
				}
			}
		} else if (pc_streq(a, "tag") || pc_streq(a, "app")) {
			if (!pc_take(pend.tag, sizeof(pend.tag), b)) {
				stats->missing_tag++;
				pend.poisoned = true;
			} else {
				pend.has_tag = pend.tag[0] != '\0';
			}
			pend.target = POL_TARGET_APP;
		} else if (pc_streq(a, "category")) {
			if (!pc_take(pend.tag, sizeof(pend.tag), b)) {
				stats->missing_tag++;
				pend.poisoned = true;
			} else {
				pend.has_tag = pend.tag[0] != '\0';
			}
			pend.target = POL_TARGET_CATEGORY;
		} else if (pc_streq(a, "action")) {
			if (pc_streq(b, "block") || pc_streq(b, "deny")) {
				pend.action = POL_BLOCK;
				pend.has_action = true;
			} else if (pc_streq(b, "allow") || pc_streq(b, "permit")) {
				pend.action = POL_ALLOW;
				pend.has_action = true;
			} else {
				stats->bad_action++;
				pend.poisoned = true;
			}
		} else if (pc_streq(a, "days")) {
			if (!pc_take(pend.w_days, sizeof(pend.w_days), b)) {
				stats->bad_window++;
				pend.poisoned = true;
			}
			pend.has_window = true;
		} else if (pc_streq(a, "start")) {
			if (!pc_take(pend.w_start, sizeof(pend.w_start), b)) {
				stats->bad_window++;
				pend.poisoned = true;
			}
			pend.has_window = true;
		} else if (pc_streq(a, "stop") || pc_streq(a, "end")) {
			if (!pc_take(pend.w_end, sizeof(pend.w_end), b)) {
				stats->bad_window++;
				pend.poisoned = true;
			}
			pend.has_window = true;
		} else if (pc_streq(a, "sense")) {
			if (!pc_take(pend.w_sense, sizeof(pend.w_sense), b)) {
				stats->bad_window++;
				pend.poisoned = true;
			}
			pend.has_window = true;
		} else if (pc_streq(a, "quota") || pc_streq(a, "daily_quota_sec")) {
			char *endp;
			long v = strtol(b, &endp, 10);

			if (*endp != '\0' || v < 0 || v > 86400) {
				stats->bad_window++;
				pend.poisoned = true;
			} else {
				pend.quota = (uint32_t)v;
			}
		} else if (pc_streq(a, "enabled")) {
			if (pc_streq(b, "0") || pc_streq(b, "false"))
				pend.poisoned = true; /* explicitly off, not an error */
		} else {
			stats->unknown_option++;
		}

		p = eol ? eol + 1 : end;
	}

	pc_commit(&pend, db, sigs, stats);
	return (long)stats->rules_added;
}

long polcfg_load_file(struct pol_db *db, const struct sig_db *sigs,
                      const char *path, struct polcfg_stats *stats)
{
	FILE *f;
	char *buf;
	size_t got = 0, cap = 8192;
	long rc;

	if (!db || !path)
		return -1;
	f = fopen(path, "rb");
	if (!f)
		return -1;

	buf = malloc(cap);
	if (!buf) {
		fclose(f);
		return -1;
	}
	for (;;) {
		size_t n;

		if (got == cap) {
			char *nb;

			if (cap >= PC_MAX_FILE)
				break; /* bounded; see PC_MAX_FILE */
			cap *= 2;
			nb = realloc(buf, cap);
			if (!nb) {
				free(buf);
				fclose(f);
				return -1;
			}
			buf = nb;
		}
		n = fread(buf + got, 1, cap - got, f);
		if (n == 0)
			break;
		got += n;
	}
	fclose(f);

	rc = polcfg_parse(db, sigs, buf, got, stats);
	free(buf);
	return rc;
}

bool polcfg_had_refusals(const struct polcfg_stats *s)
{
	if (!s)
		return false;
	return s->bad_syntax || s->unknown_section || s->unknown_option ||
	       s->bad_mac || s->bad_window || s->bad_action || s->missing_tag ||
	       s->unknown_subject || s->no_subject || s->refused_by_policy;
}

void polcfg_report(const struct polcfg_stats *s,
                   void (*emit)(void *user, const char *line), void *user)
{
	char line[256];

	if (!s || !emit)
		return;

	snprintf(line, sizeof(line),
	         "policy: %u subjects, %u rules accepted from %u sections",
	         s->subjects_added, s->rules_added, s->sections);
	emit(user, line);

	if (!polcfg_had_refusals(s))
		return;

	/* One line, every category, including the zeroes -- so the shape of a
	 * failure is comparable between two devices. */
	snprintf(line, sizeof(line),
	         "policy REFUSED: syntax=%u unknown_section=%u unknown_option=%u "
	         "bad_mac=%u bad_window=%u bad_action=%u missing_tag=%u "
	         "unknown_subject=%u no_subject=%u refused=%u",
	         s->bad_syntax, s->unknown_section, s->unknown_option, s->bad_mac,
	         s->bad_window, s->bad_action, s->missing_tag, s->unknown_subject,
	         s->no_subject, s->refused_by_policy);
	emit(user, line);
}
