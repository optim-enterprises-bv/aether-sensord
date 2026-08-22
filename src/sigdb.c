/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 */

#include "sigdb.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define LINE_MAX_LEN 2048

static void copy_bounded(char *dst, size_t dst_len, const char *src, size_t n)
{
	if (n >= dst_len)
		n = dst_len - 1;
	memcpy(dst, src, n);
	dst[n] = '\0';
}

void sig_tag_normalise(const char *name, char *out, size_t out_len)
{
	if (!out || out_len == 0)
		return;
	out[0] = '\0';
	if (!name)
		return;

	size_t o = 0;
	bool pending_sep = false;

	for (const char *p = name; *p && o + 1 < out_len; p++) {
		unsigned char c = (unsigned char)*p;
		if (isalnum(c)) {
			/* Only emit a separator once we know a real character
			 * follows, so tags never end in '-'. */
			if (pending_sep && o > 0 && o + 2 < out_len)
				out[o++] = '-';
			pending_sep = false;
			out[o++] = (char)tolower(c);
		} else {
			if (o > 0)
				pending_sep = true;
		}
	}
	out[o] = '\0';
}

bool sig_db_init(struct sig_db *db)
{
	if (!db)
		return false;
	memset(db, 0, sizeof(*db));
	db->apps = calloc(SIG_MAX_APPS, sizeof(struct sig_app));
	db->rules = calloc(SIG_MAX_RULES, sizeof(struct sig_rule));
	if (!db->apps || !db->rules) {
		free(db->apps);
		free(db->rules);
		memset(db, 0, sizeof(*db));
		return false;
	}
	return true;
}

void sig_db_free(struct sig_db *db)
{
	if (!db)
		return;
	free(db->apps);
	free(db->rules);
	memset(db, 0, sizeof(*db));
}

const struct sig_app *sig_db_app_at(const struct sig_db *db, size_t index)
{
	if (!db || index >= db->n_apps)
		return NULL;
	return &db->apps[index];
}

const struct sig_app *sig_db_by_tag(const struct sig_db *db, const char *tag)
{
	if (!db || !tag)
		return NULL;
	for (size_t i = 0; i < db->n_apps; i++) {
		if (strcmp(db->apps[i].tag, tag) == 0)
			return &db->apps[i];
	}
	return NULL;
}

const struct sig_app *sig_db_by_id(const struct sig_db *db, uint32_t id)
{
	if (!db)
		return NULL;
	for (size_t i = 0; i < db->n_apps; i++) {
		if (db->apps[i].id == id)
			return &db->apps[i];
	}
	return NULL;
}

static uint8_t parse_proto(const char *s, size_t n)
{
	if (n == 3 && strncasecmp(s, "tcp", 3) == 0)
		return SIG_PROTO_TCP;
	if (n == 3 && strncasecmp(s, "udp", 3) == 0)
		return SIG_PROTO_UDP;
	return SIG_PROTO_ANY;
}

static uint16_t parse_port(const char *s, size_t n)
{
	if (n == 0)
		return 0;
	char buf[8];
	if (n >= sizeof(buf))
		return 0;
	memcpy(buf, s, n);
	buf[n] = '\0';
	long v = strtol(buf, NULL, 10);
	if (v <= 0 || v > 65535)
		return 0;
	return (uint16_t)v;
}

/*
 * Parse one `proto;sport;dport;host;request;dict` rule body.
 *
 * `request` and `dict` are accepted and ignored: they are HTTP-path and
 * dictionary matches that this engine does not implement, and silently
 * dropping the whole rule because a trailing field is populated would lose
 * the host match that IS usable.
 */
static bool parse_rule(struct sig_db *db, const char *body, size_t len,
                       uint16_t app_index)
{
	const char *fields[6] = { NULL, NULL, NULL, NULL, NULL, NULL };
	size_t flen[6] = { 0, 0, 0, 0, 0, 0 };

	int f = 0;
	const char *start = body;
	for (size_t i = 0; i <= len && f < 6; i++) {
		if (i == len || body[i] == ';') {
			fields[f] = start;
			flen[f] = (size_t)(body + i - start);
			f++;
			start = body + i + 1;
		}
	}
	/* Fewer than three fields cannot even name a transport and a port. */
	if (f < 3)
		return false;

	if (db->n_rules >= SIG_MAX_RULES) {
		db->rejected_rules_full++;
		return false;
	}

	struct sig_rule *r = &db->rules[db->n_rules];
	memset(r, 0, sizeof(*r));
	r->app_index = app_index;
	r->proto = parse_proto(fields[0], flen[0]);
	r->sport = parse_port(fields[1], flen[1]);
	r->dport = parse_port(fields[2], flen[2]);

	if (f >= 4 && flen[3] > 0)
		copy_bounded(r->host, sizeof(r->host), fields[3], flen[3]);

	/* A rule with neither a host nor a port matches everything, which is
	 * never what a signature means. Refuse it rather than let it shadow the
	 * whole database. */
	if (r->host[0] == '\0' && r->dport == 0 && r->sport == 0)
		return false;

	db->n_rules++;
	return true;
}

static void parse_header(struct sig_db *db, const char *line)
{
	const char *p = line + 1; /* skip '#' */
	while (*p == ' ')
		p++;
	if (strncmp(p, "format", 6) == 0) {
		p += 6;
		while (*p == ' ')
			p++;
		copy_bounded(db->format, sizeof(db->format), p, strlen(p));
	} else if (strncmp(p, "version", 7) == 0) {
		p += 7;
		while (*p == ' ')
			p++;
		copy_bounded(db->version, sizeof(db->version), p, strlen(p));
	}
}

long sig_db_load(struct sig_db *db, FILE *fp)
{
	if (!db || !db->apps || !db->rules || !fp)
		return -1;

	char line[LINE_MAX_LEN];
	long accepted = 0;

	while (fgets(line, sizeof(line), fp)) {
		/* Trim trailing whitespace and the record's trailing comma. */
		size_t n = strlen(line);
		while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r' ||
		                 line[n - 1] == ' ' || line[n - 1] == '\t' ||
		                 line[n - 1] == ','))
			line[--n] = '\0';
		if (n == 0)
			continue;
		if (line[0] == '#') {
			parse_header(db, line);
			continue;
		}

		/* `<id> <name>:[<rules>]` */
		char *sp = strchr(line, ' ');
		char *colon = strchr(line, ':');
		char *lb = strchr(line, '[');
		char *rb = strrchr(line, ']');
		if (!sp || !colon || !lb || !rb || colon < sp || lb < colon || rb < lb) {
			db->rejected_malformed++;
			continue;
		}

		char *endp = NULL;
		unsigned long id = strtoul(line, &endp, 10);
		if (endp != sp || id == 0) {
			db->rejected_malformed++;
			continue;
		}

		if (db->n_apps >= SIG_MAX_APPS) {
			/* The defect this bound exists for. Refuse and count;
			 * never write entry 1025 past the end of the array. */
			db->rejected_apps_full++;
			continue;
		}

		struct sig_app app;
		memset(&app, 0, sizeof(app));
		app.id = (uint32_t)id;
		app.db_class = (uint16_t)(id / 1000);
		copy_bounded(app.name, sizeof(app.name), sp + 1,
		             (size_t)(colon - sp - 1));
		sig_tag_normalise(app.name, app.tag, sizeof(app.tag));
		if (app.tag[0] == '\0') {
			db->rejected_malformed++;
			continue;
		}

		/* The shipped database defines the same application under more
		 * than one numeric id -- YouTube is both 11001 and 39037, and 27
		 * other names repeat. Those are not collisions to reject, they
		 * are the same app described twice, and unifying them is exactly
		 * what the tag exists for. Merge: keep the first app record and
		 * attach this line's rules to it. */
		const struct sig_app *existing = sig_db_by_tag(db, app.tag);
		uint16_t app_index;
		if (existing) {
			app_index = (uint16_t)(existing - db->apps);
			db->merged_by_tag++;
		} else {
			app_index = (uint16_t)db->n_apps;
			db->apps[db->n_apps++] = app;
			accepted++;
		}

		/* Rule list: comma-separated inside the brackets. Splitting on
		 * ',' is safe because no field may contain one. */
		const char *p = lb + 1;
		const char *end = rb;
		while (p < end) {
			const char *comma = memchr(p, ',', (size_t)(end - p));
			const char *stop = comma ? comma : end;
			if (stop > p)
				parse_rule(db, p, (size_t)(stop - p), app_index);
			if (!comma)
				break;
			p = comma + 1;
		}
	}

	return accepted;
}

long sig_db_load_path(struct sig_db *db, const char *path)
{
	FILE *fp = fopen(path, "r");
	if (!fp)
		return -1;
	long n = sig_db_load(db, fp);
	fclose(fp);
	return n;
}
