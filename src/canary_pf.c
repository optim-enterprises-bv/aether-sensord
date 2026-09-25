/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * pf enforcement canary. See canary_pf.h for why this exists and why it is
 * structured differently from the nftables original.
 *
 * THE PROBE IS NOT A sendto(). See canary_pf_probe_blocked's comment: pf
 * discards a blocked packet silently, so the original's EPERM test reports a
 * false NOT_ENFORCED here. The verdict rests on pf's own table counters.
 *
 * Portability: builds on FreeBSD (clang) and Linux (gcc). `pfctl` is only
 * invoked on the FreeBSD path; on other systems the impure half reports
 * INCONCLUSIVE rather than pretending.
 */

#include "canary_pf.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#if defined(__FreeBSD__)
#include <syslog.h>
#else
#include <syslog.h>
#endif

const char *pf_canary_addr(bool v6)
{
	return v6 ? PF_CANARY_V6 : PF_CANARY_V4;
}

const char *pf_canary_str(enum pf_canary_result r)
{
	switch (r) {
	case PF_CANARY_ENFORCED:
		return "enforced (the table is referenced by a live rule)";
	case PF_CANARY_TABLE_MISSING:
		return "the table does not exist";
	case PF_CANARY_ADD_REJECTED:
		return "pfctl refused the canary element";
	case PF_CANARY_NOT_HELD:
		return "pfctl accepted it but the table does not hold it";
	case PF_CANARY_NOT_ENFORCED:
		return "TABLE HOLDS IT BUT NOTHING REFERS TO IT -- not blocking";
	case PF_CANARY_CLEANUP_FAILED:
		return "enforced, but the canary was left behind";
	case PF_CANARY_INCONCLUSIVE:
		return "could not be checked";
	default:
		return "?";
	}
}

const char *pf_canary_token(enum pf_canary_result r)
{
	/*
	 * Must stay in step with enum Verdict in aether-aegis::proof. These are
	 * the ORIGINAL nftables daemon's tokens, unchanged on purpose: a
	 * controller that received a new token for an existing state would
	 * treat an unknown verdict as unusable and the whole fleet would read
	 * as "never reported".
	 */
	switch (r) {
	case PF_CANARY_ENFORCED:
		return "enforced";
	case PF_CANARY_TABLE_MISSING:
		return "set_missing";
	case PF_CANARY_ADD_REJECTED:
		return "add_rejected";
	case PF_CANARY_NOT_HELD:
		return "not_held";
	case PF_CANARY_NOT_ENFORCED:
		return "not_enforced";
	case PF_CANARY_CLEANUP_FAILED:
		return "cleanup_failed";
	default:
		return "inconclusive";
	}
}

enum pf_canary_result pf_canary_classify(const struct pf_canary_obs *o)
{
	if (!o)
		return PF_CANARY_INCONCLUSIVE;

	/*
	 * First fault wins. A missing table also makes the add fail, but
	 * ADD_REJECTED would send an operator to inspect the feed when the real
	 * problem is that the declaration never landed.
	 */
	if (!o->table_exists)
		return PF_CANARY_TABLE_MISSING;
	if (!o->add_accepted)
		return PF_CANARY_ADD_REJECTED;
	if (!o->held_in_table)
		return PF_CANARY_NOT_HELD;

	/*
	 * A probe that could not run is not a pass and not evidence of failure.
	 * It is the one state where we know we do not know, and it must stay
	 * distinct from both verdicts.
	 */
	if (!o->probe_ran)
		return PF_CANARY_INCONCLUSIVE;

	/*
	 * THE dangerous state: the table exists, it holds the address, and no
	 * rule anywhere refers to it -- so nothing is ever dropped. On pf this
	 * is the expected outcome of an anchor-based plugin under OPNsense:
	 * the generated ruleset contains zero anchor lines (measured on
	 * 26.7.2_2), so the anchor is never traversed. Nothing errors, `-T
	 * show` lists the contents, and not one packet dies. It is
	 * indistinguishable from success by every signal except this one.
	 */
	if (!o->referenced_by_rule)
		return PF_CANARY_NOT_ENFORCED;

	if (!o->cleanup_ok)
		return PF_CANARY_CLEANUP_FAILED;
	return PF_CANARY_ENFORCED;
}

bool pf_canary_passed(enum pf_canary_result r)
{
	return r == PF_CANARY_ENFORCED;
}

int pf_canary_probe_blocked(const char *addr, bool v6)
{
	static const uint8_t payload[4] = { 0xae, 0x11, 0xca, 0x1a };
	int fd, i, sent_ok = 0;

	if (!addr)
		return -1;

	fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	for (i = 0; i < PF_CANARY_PROBES; i++) {
		ssize_t s;

		if (v6) {
			struct sockaddr_in6 sa;
			memset(&sa, 0, sizeof(sa));
			sa.sin6_family = AF_INET6;
			sa.sin6_port = htons(9);
			if (inet_pton(AF_INET6, addr, &sa.sin6_addr) != 1) {
				close(fd);
				return -1;
			}
			s = sendto(fd, payload, sizeof(payload), MSG_DONTWAIT,
			           (struct sockaddr *)&sa, sizeof(sa));
		} else {
			struct sockaddr_in sa;
			memset(&sa, 0, sizeof(sa));
			sa.sin_family = AF_INET;
			sa.sin_port = htons(9);
			if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
				close(fd);
				return -1;
			}
			s = sendto(fd, payload, sizeof(payload), MSG_DONTWAIT,
			           (struct sockaddr *)&sa, sizeof(sa));
		}

		/*
		 * A refused send is recorded as a success here, not a failure:
		 * it means a firewall DID stop it. But it is not required --
		 * pf normally drops silently -- so it is never a verdict.
		 */
		if (s >= 0)
			sent_ok++;
	}

	close(fd);
	return sent_ok;
}

/*
 * Does the MAIN ruleset reference `table`? See the header for why the
 * per-table reference count is not sufficient evidence.
 *
 * Scans for `<table>` as a whole token: pf renders a table reference in a rule
 * as `<name>`, so the angle brackets are the discriminator, and a table whose
 * name is a substring of another cannot be mistaken for it.
 */
bool pf_canary_ruleset_references(const char *main_rules, const char *table)
{
	char needle[256];
	const char *p;
	size_t n;

	if (!main_rules || !table)
		return false;
	n = strlen(table);
	/* 2 for '<' '>', 1 for NUL. Also rejects a name that could not be a
	 * table, and a name containing '>' could not match a real reference. */
	if (n == 0 || n > 240)
		return false;

	needle[0] = '<';
	memcpy(needle + 1, table, n);
	needle[n + 1] = '>';
	needle[n + 2] = '\0';

	p = strstr(main_rules, needle);
	if (!p)
		return false;

	/*
	 * Must be followed by a character that ends the token, so `<rep4>` is
	 * not matched by `<rep4x>`. pf separates a table reference from what
	 * follows with whitespace, a comma, a brace or end of line; anything
	 * else (a name character) means this is a longer table's name.
	 */
	{
		char after = p[n + 2];
		if (after == '\0' || after == ' ' || after == '	' ||
		    after == '\n' || after == ',' || after == '}' ||
		    after == ')')
			return true;
	}
	return false;
}

#if defined(__FreeBSD__)

/* Run a command, capturing stdout into `out`. Returns the exit status, or -1
 * if the command could not be run.
 *
 * ALWAYS DRAINS THE PIPE, even when `out` filled up. This is not tidiness:
 * a reader that stops early leaves the child with unwritten output, the child
 * dies of SIGPIPE, and pclose() then reports signal 13 rather than success.
 * Measured on a production OPNsense firewall whose main ruleset is 13,592
 * bytes against an 8 KB buffer: pclose() returned 13, the caller concluded it
 * "could not check", and the enforcement canary answered INCONCLUSIVE on every
 * run. The canary exists to answer exactly this question, so a silent
 * degradation to "unknown" is worse than a wrong answer -- every caller that
 * treats non-zero as "not enforced" reads it as a pass.
 *
 * `truncated` (optional) reports that output was discarded, so a caller can
 * distinguish "searched the whole listing and did not find it" from "searched
 * only the first N bytes". Concluding NOT_ENFORCED from a partial listing would
 * be a statement about a ruleset we did not fully read.
 */
static int run_capture(const char *cmd, char *out, size_t out_len,
                       bool *truncated)
{
	FILE *p;
	size_t used = 0;
	bool trunc = false;
	char sink[4096];
	size_t n;

	if (truncated)
		*truncated = false;
	if (out && out_len)
		out[0] = '\0';

	p = popen(cmd, "r");
	if (!p)
		return -1;

	if (out && out_len > 1) {
		used = fread(out, 1, out_len - 1, p);
		out[used] = '\0';
	}

	/* Drain whatever is left -- including the case above where `out` filled. */
	while ((n = fread(sink, 1, sizeof(sink), p)) > 0)
		trunc = true;

	if (truncated)
		*truncated = trunc;
	return pclose(p);
}

/*
 * `pfctl -t <t> -T show` and friends: the table name is NOT shell-quoted
 * because it never comes from a feed. It is a compile-time constant chosen by
 * the packager (see PF_TABLE_NAME_DEFAULT). If that ever changes to a
 * runtime-supplied name, this must gain a strict [A-Za-z0-9_] validation first
 * -- a table name is an argv position in pfctl, and the same injection concern
 * that governs elements applies to it.
 */
enum pf_canary_result pf_canary_run(const char *table, bool v6)
{
	char cmd[512];
	/*
	 * Sized for a real OPNsense main ruleset. It is not a nicety: when this
	 * buffer was 8192 the listing was truncated on a production firewall
	 * (13,592 bytes), the caller could not see the table, and the canary
	 * degraded to INCONCLUSIVE on every run. Bigger, and `truncated` below
	 * makes a partial read an explicit fact rather than a silent one.
	 */
	static char listing[512 * 1024];
	const char *addr;
	struct pf_canary_obs o;
	bool truncated = false;
	int rc;

	if (!table)
		return PF_CANARY_INCONCLUSIVE;

	memset(&o, 0, sizeof(o));
	addr = pf_canary_addr(v6);

	/* 1. does the table exist? */
	snprintf(cmd, sizeof(cmd), "pfctl -t %s -T show 2>/dev/null", table);
	rc = run_capture(cmd, listing, sizeof(listing), NULL);
	o.table_exists = (rc == 0);

	/* 2. can the canary be added? */
	if (o.table_exists) {
		snprintf(cmd, sizeof(cmd), "pfctl -t %s -T add %s 2>/dev/null",
		         table, addr);
		rc = run_capture(cmd, NULL, 0, NULL);
		o.add_accepted = (rc == 0);
	}

	/* 3. does the table actually hold it? A `-T add` that returns 0 while
	 * the entry is absent is precisely the "it said it worked" failure. */
	if (o.add_accepted) {
		snprintf(cmd, sizeof(cmd), "pfctl -t %s -T show 2>/dev/null", table);
		rc = run_capture(cmd, listing, sizeof(listing), NULL);
		o.held_in_table = (rc == 0 && strstr(listing, addr) != NULL);
	}

	/*
	 * 4. THE ACTUAL QUESTION. Send traffic at the canary, then ask whether
	 * the MAIN ruleset references the table. The datagram result itself is
	 * deliberately not used: pf discards a dropped packet silently, so "the
	 * send succeeded" cannot distinguish an enforcing table from a dead one
	 * -- it is true in both cases.
	 */
	if (o.held_in_table) {
		int sends = pf_canary_probe_blocked(addr, v6);

		if (sends >= 0) {
			/*
			 * `pfctl -s rules` is the MAIN ruleset. `-vvsT` is NOT
			 * used: its per-table Rules count includes rules inside
			 * an unreferenced anchor, which measured 2 while the
			 * main ruleset referenced the table zero times -- an
			 * enforced verdict on a firewall that blocks nothing.
			 *
			 * A TRUNCATED listing is not evidence. "The table is
			 * absent from the first N bytes I read" is a statement
			 * about an unread ruleset, and reporting NOT_ENFORCED
			 * from it would accuse a firewall on the strength of a
			 * partial read. INCONCLUSIVE is the honest answer.
			 */
			snprintf(cmd, sizeof(cmd),
			         "pfctl -s rules 2>/dev/null");
			truncated = false;
			rc = run_capture(cmd, listing, sizeof(listing),
			                 &truncated);
			o.probe_ran = (rc == 0 && !truncated);
			o.referenced_by_rule =
			    o.probe_ran &&
			    pf_canary_ruleset_references(listing, table);
		}
	}

	/* 5. always clean up, on every path. */
	snprintf(cmd, sizeof(cmd), "pfctl -t %s -T delete %s 2>/dev/null",
	         table, addr);
	run_capture(cmd, NULL, 0, NULL);
	snprintf(cmd, sizeof(cmd), "pfctl -t %s -T show 2>/dev/null", table);
	rc = run_capture(cmd, listing, sizeof(listing), NULL);
	o.cleanup_ok = (rc == 0 && strstr(listing, addr) == NULL);

	return pf_canary_classify(&o);
}

int pf_canary_report(const char *spool_dir, const char *serial,
                     enum pf_canary_result r, const char *table, bool v6)
{
	char path[512], tmp[540];
	FILE *f;
	time_t now;

	if (!spool_dir)
		return -1;

	now = time(NULL);
	snprintf(path, sizeof(path), "%s/canary-%lld.ndjson", spool_dir,
	         (long long)now);
	snprintf(tmp, sizeof(tmp), "%s.partial", path);

	f = fopen(tmp, "w");
	if (!f) {
		syslog(LOG_ERR, "cannot open canary spool %s: %s", tmp,
		       strerror(errno));
		return -1;
	}

	fputs("{\"canary\":true,", f);
	if (serial && serial[0])
		fprintf(f, "\"serial\":\"%s\",", serial);
	fprintf(f, "\"verdict\":\"%s\",\"target\":\"%s\",\"family\":\"%s\","
	           "\"ts\":%lld}\n",
	        pf_canary_token(r), table ? table : "", v6 ? "v6" : "v4",
	        (long long)now);

	if (fclose(f) != 0)
		return -1;
	if (rename(tmp, path) != 0)
		return -1;
	return 0;
}

#else /* not FreeBSD */

enum pf_canary_result pf_canary_run(const char *table, bool v6)
{
	/* No pfctl here. Reporting INCONCLUSIVE rather than a verdict keeps the
	 * "could not check" case distinct from "it works". */
	(void)table;
	(void)v6;
	return PF_CANARY_INCONCLUSIVE;
}

int pf_canary_report(const char *spool_dir, const char *serial,
                     enum pf_canary_result r, const char *table, bool v6)
{
	(void)spool_dir;
	(void)serial;
	(void)r;
	(void)table;
	(void)v6;
	return -1;
}

#endif /* __FreeBSD__ */
