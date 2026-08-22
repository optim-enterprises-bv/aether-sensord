/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 */

#include "feed.h"

#include <stdlib.h>
#include <string.h>

const char *feed_outcome_str(enum feed_outcome o)
{
	switch (o) {
	case FEED_APPLIED:
		return "applied";
	case FEED_STALE:
		return "stale";
	case FEED_RESYNC_REQUIRED:
		return "resync_required";
	default:
		return "unknown";
	}
}

/*
 * Minimal, bounded scanning for the specific shapes aether-nemesis emits.
 *
 * This is not a general JSON parser and must not become one. It looks for
 * known keys and pulls out quoted strings and one integer; anything it does
 * not recognise it ignores, and every string it does find goes through
 * nft_elem_parse, which refuses anything that is not an address. A permissive
 * scanner in front of a strict validator is safe; the reverse is not.
 */

static const char *find_key(const char *s, const char *end, const char *key)
{
	size_t klen = strlen(key);
	for (const char *p = s; p + klen < end; p++) {
		if (*p != '"')
			continue;
		if ((size_t)(end - p) < klen + 2)
			break;
		if (strncmp(p + 1, key, klen) == 0 && p[1 + klen] == '"')
			return p + 1 + klen + 1; /* just past the closing quote */
	}
	return NULL;
}

/* Read the next quoted string into `buf`. Returns the char after it, or NULL. */
static const char *next_string(const char *p, const char *end, char *buf,
                               size_t buflen)
{
	while (p < end && *p != '"' && *p != ']' && *p != '}')
		p++;
	if (p >= end || *p != '"')
		return NULL;
	p++;
	size_t n = 0;
	while (p < end && *p != '"') {
		if (n + 1 < buflen)
			buf[n++] = *p;
		else
			n++; /* keep counting so an over-long value is refused */
		p++;
	}
	if (p >= end)
		return NULL;
	buf[n < buflen ? n : buflen - 1] = '\0';
	/* An over-long value is truncated here, but nft_elem_parse enforces its
	 * own length bound and will refuse it. */
	return p + 1;
}

/* Collect address strings from a JSON array into `dst`. */
static void collect_array(const char *p, const char *end, struct nft_elem *dst,
                          size_t cap, size_t *n_out, uint32_t *rejected,
                          uint32_t *overflowed)
{
	while (p < end && *p != '[') {
		/* An empty or absent array is normal, not an error. */
		if (*p == ',' || *p == '}')
			return;
		p++;
	}
	if (p >= end)
		return;
	p++; /* past '[' */

	while (p < end && *p != ']') {
		char text[NFT_ELEM_TEXT_MAX + 8];
		const char *next = next_string(p, end, text, sizeof(text));
		if (!next)
			return;
		p = next;

		struct nft_elem e;
		if (nft_elem_parse(text, &e) != NFT_OK) {
			(*rejected)++;
		} else if (*n_out >= cap) {
			(*overflowed)++;
		} else {
			dst[(*n_out)++] = e;
		}

		while (p < end && *p != '"' && *p != ']')
			p++;
	}
}

bool feed_parse(const char *json, size_t len, struct feed_msg *out)
{
	if (!json || !out || len == 0)
		return false;
	memset(out, 0, sizeof(*out));
	const char *end = json + len;

	const char *tp = find_key(json, end, "type");
	if (!tp)
		return false;
	char type[16];
	if (!next_string(tp, end, type, sizeof(type)))
		return false;
	if (strcmp(type, "delta") == 0)
		out->type = FEED_MSG_DELTA;
	else if (strcmp(type, "list") == 0)
		out->type = FEED_MSG_LIST;
	else
		return false;

	const char *sp = find_key(json, end, "serial");
	if (!sp)
		return false;
	while (sp < end && (*sp == ':' || *sp == ' '))
		sp++;
	char *endp = NULL;
	unsigned long long serial = strtoull(sp, &endp, 10);
	if (endp == sp)
		return false;
	out->serial = (uint64_t)serial;

	if (out->type == FEED_MSG_DELTA) {
		const char *ap = find_key(json, end, "add");
		if (ap)
			collect_array(ap, end, out->add, FEED_MAX_ELEMS, &out->n_add,
			              &out->rejected, &out->overflowed);
		const char *rp = find_key(json, end, "remove");
		if (rp)
			collect_array(rp, end, out->remove, FEED_MAX_ELEMS,
			              &out->n_remove, &out->rejected, &out->overflowed);
	} else {
		const char *ep = find_key(json, end, "entries");
		if (ep)
			collect_array(ep, end, out->add, FEED_MAX_ELEMS, &out->n_add,
			              &out->rejected, &out->overflowed);
	}

	return true;
}

void feed_client_init(struct feed_client *c)
{
	if (c)
		memset(c, 0, sizeof(*c));
}

bool feed_client_needs_resync(const struct feed_client *c)
{
	return c && c->missed >= FEED_MISSING_LIMIT;
}

enum feed_outcome feed_client_accept(struct feed_client *c,
                                     const struct feed_msg *msg)
{
	if (!c || !msg || msg->type == FEED_MSG_NONE)
		return FEED_RESYNC_REQUIRED;

	if (msg->type == FEED_MSG_LIST) {
		/* A snapshot is authoritative whatever we had. */
		c->serial = msg->serial;
		c->have_baseline = true;
		c->missed = 0;
		c->applied_lists++;
		return FEED_APPLIED;
	}

	/* First message ever is a delta: there is no baseline, so we cannot
	 * know what came before it. */
	if (!c->have_baseline) {
		c->missed = FEED_MISSING_LIMIT;
		c->resyncs++;
		return FEED_RESYNC_REQUIRED;
	}

	if (msg->serial <= c->serial)
		return FEED_STALE;

	if (msg->serial == c->serial + 1) {
		c->serial = msg->serial;
		c->missed = 0;
		c->applied_deltas++;
		return FEED_APPLIED;
	}

	/*
	 * Gap. Count what was missed and leave the caller's set ALONE -- the
	 * whole point of the protocol. A half-applied delta stream diverges
	 * silently from the controller.
	 */
	uint64_t gap = msg->serial - c->serial - 1;
	if (gap > FEED_MISSING_LIMIT)
		gap = FEED_MISSING_LIMIT;
	c->missed += (uint32_t)gap;
	c->resyncs++;
	return FEED_RESYNC_REQUIRED;
}
