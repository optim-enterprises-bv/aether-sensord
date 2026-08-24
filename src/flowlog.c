/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 */

#include "flowlog.h"

#include "observe.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

bool flowlog_init(struct flowlog *fl, const char *spool_dir)
{
	if (!fl || !spool_dir || !spool_dir[0])
		return false;

	memset(fl, 0, sizeof(*fl));
	snprintf(fl->spool, sizeof(fl->spool), "%s", spool_dir);

	if (mkdir(fl->spool, 0750) != 0 && errno != EEXIST) {
		syslog(LOG_ERR, "flowlog: cannot create %s: %s", fl->spool,
		       strerror(errno));
		fl->spool[0] = '\0';
		return false;
	}
	return true;
}

/* Keep only the newest FLOWLOG_MAX_BATCHES files. The uplink deletes what it
 * ships, so this only bites when nothing is collecting -- and then the newest
 * flows are the ones worth keeping. */
static void flowlog_prune(const char *dir)
{
	char cmd[640];

	snprintf(cmd, sizeof(cmd),
	         "ls -1t '%s'/flows-*.ndjson 2>/dev/null | tail -n +%u | "
	         "xargs -r rm -f",
	         dir, FLOWLOG_MAX_BATCHES + 1);
	if (system(cmd) != 0)
		syslog(LOG_DEBUG, "flowlog: prune returned non-zero");
}

void flowlog_record(struct flowlog *fl, const struct dpi_result *f,
                    const struct appblock_decision *d,
                    const uint8_t *subject_mac)
{
	char dst[64] = "?";
	char mac[24];
	const char *scope;
	const char *action;

	if (!fl || !fl->spool[0] || !f || !d)
		return;

	if (fl->n_pending >= FLOWLOG_BATCH_ROWS) {
		/* Counted, not silently discarded: a vanished flow record makes
		 * the controller's per-app totals quietly wrong, and nothing
		 * downstream could tell. The count rides in the batch. */
		fl->dropped++;
		return;
	}

	obs_addr_str(&f->dst, dst, sizeof(dst));
	/* An unattributable flow carries no MAC rather than a zeroed one:
	 * 00:00:00:00:00:00 is a plausible-looking value that would attribute
	 * every unattributed flow on the network to one fictional client. */
	if (subject_mac)
		snprintf(mac, sizeof(mac), "\"%02x:%02x:%02x:%02x:%02x:%02x\"",
		         subject_mac[0], subject_mac[1], subject_mac[2],
		         subject_mac[3], subject_mac[4], subject_mac[5]);
	else
		snprintf(mac, sizeof(mac), "null");
	scope = f->scope == DPI_SCOPE_ADDRESS ? "address" : "name_hash";
	switch (d->action) {
	case ACT_ADDR: action = "blocked_address"; break;
	case ACT_HASH: action = "blocked_name"; break;
	default:       action = "allowed"; break;
	}

	/* Precision specifiers on every variable-length field, so the maximum
	 * output is a compile-time fact rather than a hope. Without them gcc
	 * cannot prove the row fits and -Wformat-truncation is right to
	 * complain: a silently truncated record parses and is wrong, and a
	 * hostname cut mid-label is a different hostname. */
	snprintf(fl->pending[fl->n_pending], sizeof(fl->pending[0]),
	         "{\"proto\":\"%.64s\",\"l4\":\"%.8s\",\"dport\":%u,\"dst\":\"%.64s\","
	         "\"hostname\":%s%.256s%s,\"app\":%s%.64s%s,\"scope\":\"%.16s\","
	         "\"client_mac\":%.24s,"
	         "\"action\":\"%.24s\",\"reason\":\"%.24s\",\"at\":%lld}\n",
	         f->proto_name[0] ? f->proto_name : "unknown",
	         f->l4proto == 6 ? "tcp" : (f->l4proto == 17 ? "udp" : "other"),
	         f->dport, dst,
	         /* null rather than "" for an unrecovered name: the controller
	          * must be able to tell "no SNI in this flow" from "the SNI was
	          * an empty string", and they are different failures. */
	         f->have_host && f->host[0] ? "\"" : "", f->have_host && f->host[0] ? f->host : "null",
	         f->have_host && f->host[0] ? "\"" : "",
	         d->app_tag[0] ? "\"" : "", d->app_tag[0] ? d->app_tag : "null",
	         d->app_tag[0] ? "\"" : "",
	         scope, mac, action, appblock_reason_wire(d->reason),
	         (long long)time(NULL));

	fl->n_pending++;
	if (fl->n_pending >= FLOWLOG_BATCH_ROWS)
		flowlog_flush(fl);
}

void flowlog_flush(struct flowlog *fl)
{
	char path[512], tmp[540];
	FILE *out;
	time_t now;
	size_t i;
	int err;

	if (!fl || !fl->spool[0] || fl->n_pending == 0)
		return;

	now = time(NULL);
	snprintf(path, sizeof(path), "%s/flows-%lld.ndjson", fl->spool,
	         (long long)now);
	snprintf(tmp, sizeof(tmp), "%s.partial", path);

	out = fopen(tmp, "w");
	if (!out) {
		syslog(LOG_ERR, "flowlog: cannot open %s: %s", tmp,
		       strerror(errno));
		/* Rows are kept, not dropped: the next flush retries them. A
		 * full flash should cost latency, not data. */
		return;
	}

	for (i = 0; i < fl->n_pending; i++)
		fputs(fl->pending[i], out);

	/* The batch reports its own losses. A consumer that cannot see the
	 * sensor dropped rows will read the totals as complete (ADR-017). */
	fprintf(out,
	        "{\"meta\":true,\"rows\":%zu,\"dropped\":%llu,"
	        "\"total_written\":%llu,\"emitted_at\":%lld}\n",
	        fl->n_pending, (unsigned long long)fl->dropped,
	        (unsigned long long)(fl->written + fl->n_pending),
	        (long long)now);

	err = ferror(out);
	if (fclose(out) != 0 || err) {
		syslog(LOG_ERR, "flowlog: write failed, discarding batch");
		unlink(tmp);
		fl->n_pending = 0;
		return;
	}

	/* Renamed only once complete: the uplink requires a .ndjson suffix, so
	 * a .partial is invisible to it -- but only because we never write to
	 * the final name directly. */
	if (rename(tmp, path) != 0) {
		syslog(LOG_ERR, "flowlog: cannot rename %s: %s", tmp,
		       strerror(errno));
		unlink(tmp);
		fl->n_pending = 0;
		return;
	}

	fl->written += fl->n_pending;
	fl->n_pending = 0;
	flowlog_prune(fl->spool);
}
