/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 */

#include "match.h"

#include <ctype.h>
#include <string.h>

const char *match_kind_str(enum match_kind k)
{
	switch (k) {
	case MATCH_HOST_EXACT:
		return "host_exact";
	case MATCH_HOST_SUFFIX:
		return "host_suffix";
	case MATCH_PORT:
		return "port";
	case MATCH_NONE:
	default:
		return "none";
	}
}

bool match_host_pattern(const char *host, const char *pattern,
                        enum match_kind *kind)
{
	if (!host || !pattern || !*host || !*pattern)
		return false;

	size_t hl = strlen(host);
	size_t pl = strlen(pattern);

	/* Ignore a trailing root dot on the observed name. */
	if (hl > 1 && host[hl - 1] == '.')
		hl--;

	if (hl == pl && strncasecmp(host, pattern, hl) == 0) {
		if (kind)
			*kind = MATCH_HOST_EXACT;
		return true;
	}

	/* A dotless pattern is a LABEL-PREFIX match.
	 *
	 * The shipped database contains ten bare tokens -- youtube, tiktok,
	 * netflix, vimeo, dailymotion, hulu, vube, twitch, itemfix, yahoo. That
	 * is 0.7% of 1,344 host-bearing signatures, but it is almost exactly the
	 * streaming category, which is the highest-value one for parental
	 * controls. Small surface, high stakes.
	 *
	 * OAF substring-matches these. Substring also matches
	 * "evil-youtube.com", which is a look-alike hole we will not ship.
	 * Requiring a whole label to EQUAL the token closes that hole but is too
	 * strict: these services carry the token as a label prefix in their real
	 * traffic domains, so equality silently drops
	 *
	 *     youtubei.googleapis.com   (label "youtubei"  -- InnerTube API)
	 *     tiktokcdn.com             (label "tiktokcdn")
	 *     tiktokv.com               (label "tiktokv")
	 *
	 * Matching a label that STARTS WITH the token keeps those and still
	 * rejects "evil-youtube.com", whose label does not start with it.
	 *
	 * Known and accepted: "youtube.evil.com" still matches, because the
	 * token IS a whole label there. That is inherent to a bare token and is
	 * not solvable in the matcher; it over-blocks rather than under-blocks,
	 * which is the safer direction for this feature. It is deliberate, not
	 * an oversight. */
	if (!memchr(pattern, '.', pl)) {
		size_t start = 0;
		for (size_t i = 0; i <= hl; i++) {
			if (i == hl || host[i] == '.') {
				size_t label_len = i - start;
				if (label_len >= pl &&
				    strncasecmp(host + start, pattern, pl) == 0) {
					if (kind)
						*kind = MATCH_HOST_SUFFIX;
					return true;
				}
				start = i + 1;
			}
		}
		return false;
	}

	/* Suffix must land on a label boundary: "www.signal.org" matches
	 * "signal.org", but "notsignal.org" must not. */
	if (hl > pl + 1 && host[hl - pl - 1] == '.') {
		const char *tail = host + hl - pl;
		size_t i = 0;
		for (; i < pl; i++) {
			if (tolower((unsigned char)tail[i]) !=
			    tolower((unsigned char)pattern[i]))
				break;
		}
		if (i == pl) {
			if (kind)
				*kind = MATCH_HOST_SUFFIX;
			return true;
		}
	}

	return false;
}

/* Higher is more specific. */
static int specificity(enum match_kind k)
{
	switch (k) {
	case MATCH_HOST_EXACT:
		return 3;
	case MATCH_HOST_SUFFIX:
		return 2;
	case MATCH_PORT:
		return 1;
	default:
		return 0;
	}
}

struct match_result match_flow(const struct sig_db *db, const char *host,
                               uint8_t proto, uint16_t dport)
{
	struct match_result best = { MATCH_NONE, NULL, 0, 0 };
	int best_score = 0;
	size_t best_len = 0;
	/* Distinct apps tied at the winning (score, pattern-length). */
	const struct sig_app *tied[8];
	uint8_t n_tied = 0;

	if (!db)
		return best;

	bool have_host = host && *host;

	for (size_t i = 0; i < db->n_rules; i++) {
		const struct sig_rule *r = &db->rules[i];

		if (r->proto != SIG_PROTO_ANY && proto != SIG_PROTO_ANY &&
		    r->proto != proto)
			continue;
		if (r->dport != 0 && dport != 0 && r->dport != dport)
			continue;
		/* A rule pinned to a port cannot match a flow whose port we do
		 * not know -- guessing here would attribute traffic to the
		 * wrong subscriber's app history. */
		if (r->dport != 0 && dport == 0)
			continue;

		enum match_kind k = MATCH_NONE;
		size_t plen = 0;

		if (r->host[0] != '\0') {
			if (!have_host)
				continue;
			if (!match_host_pattern(host, r->host, &k))
				continue;
			plen = strlen(r->host);
		} else {
			/* Port-only rule. Requires an actual port to have been
			 * observed; see above. */
			if (r->dport == 0 && r->sport == 0)
				continue;
			k = MATCH_PORT;
			plen = 0;
		}

		int score = specificity(k);
		const struct sig_app *app = sig_db_app_at(db, r->app_index);

		if (score > best_score || (score == best_score && plen > best_len)) {
			/* Strictly better: this is now the only candidate. */
			best_score = score;
			best_len = plen;
			best.kind = k;
			best.rule_index = (uint16_t)i;
			best.app = app;
			n_tied = 0;
			if (app && n_tied < (uint8_t)(sizeof(tied) / sizeof(tied[0])))
				tied[n_tied++] = app;
		} else if (score == best_score && plen == best_len && app &&
		           best.app) {
			/* Equally specific. Record it only if it is a DIFFERENT
			 * application -- one app with several rules for the same
			 * pattern is not ambiguity. */
			bool seen = false;
			for (uint8_t j = 0; j < n_tied; j++) {
				if (tied[j] == app) {
					seen = true;
					break;
				}
			}
			if (!seen && n_tied < (uint8_t)(sizeof(tied) / sizeof(tied[0])))
				tied[n_tied++] = app;
		}
	}

	if (!best.app) {
		best.kind = MATCH_NONE;
		best.ambiguous_apps = 0;
	} else {
		best.ambiguous_apps = n_tied;
	}
	return best;
}
