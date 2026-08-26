/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Classified flows, on their way off the device.
 *
 * WHY THIS EXISTS. The classifier worked and its output went nowhere. nDPI
 * named the protocol, the SNI was recovered, the policy decision was made --
 * and the only record was a rate-limited syslog line capped at 25 entries per
 * run. Nothing shipped it, so the controller could not show an operator a
 * single classified flow, and "app visibility" was a feature the platform
 * itself could not see.
 *
 * This is the producer. `ac-client` carries the batches over USP exactly as it
 * carries the sense batches; the controller aggregates them.
 *
 * CONSENT. Classification reads packet PAYLOAD and is consented separately from
 * everything else this daemon does (ADR-020 §3). This file only ever runs when
 * `-Q` is on, and writes nothing otherwise -- a device that has not consented
 * produces no spool at all.
 *
 * WHAT IS AND IS NOT RECORDED. The destination, the recovered server name, the
 * protocol, the matched application, the enforcement decision, and the subject
 * MAC. NOT the payload.
 *
 * The subject MAC was omitted in the first version of this file, on the
 * reasoning that a per-flow MAC ships the household's internal topology. That
 * was wrong twice over: the controller ALREADY holds every client MAC in
 * `client_fingerprints` via argus, so withholding it protected nothing; and the
 * rollup is keyed per (client, app), so a record without one cannot be
 * attributed at all. 520 records were rejected as `MissingClient` before this
 * was noticed.
 */

#ifndef AETHER_SENSORD_FLOWLOG_H
#define AETHER_SENSORD_FLOWLOG_H

#include "appblock.h"
#include "dpi.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * One serialised row.
 *
 * Sized so a maximum-length record cannot truncate: DPI_HOST_MAX (256) plus
 * DPI_PROTO_NAME_MAX (64) plus SIG_TAG_LEN (64) plus the fixed JSON around
 * them. Truncating would produce a record that parses and is wrong -- a
 * hostname cut mid-label is a different hostname.
 */
#define FLOWLOG_ROW_MAX 768

/* Rows held before a batch is written. ~98 KB of buffer: large enough that a
 * busy link does not write constantly, small enough to bound what an unshipped
 * spool costs on flash. */
#define FLOWLOG_BATCH_ROWS 128

/* Batches kept before the oldest is dropped. The uplink deletes what it ships,
 * so this only fills when nothing is collecting -- at which point the newest
 * flows are the ones worth keeping. */
#define FLOWLOG_MAX_BATCHES 16

struct flowlog {
	char spool[256];
	char pending[FLOWLOG_BATCH_ROWS][FLOWLOG_ROW_MAX];
	size_t n_pending;
	/* Rows discarded because the buffer was full between flushes. Reported
	 * in the batch: a flow record that silently vanishes makes the
	 * controller's per-app totals quietly wrong, and nothing downstream
	 * could tell. */
	uint64_t dropped;
	uint64_t written;
};

/* Prepare the spool. Returns false if the directory cannot be created, in
 * which case every later call is a no-op rather than an error per flow. */
bool flowlog_init(struct flowlog *fl, const char *spool_dir);

/*
 * Record one classified flow and its decision.
 *
 * Never blocks on I/O: rows accumulate and are written when the batch fills or
 * flowlog_flush() is called on the daemon's interval. Classification runs in
 * the NFLOG callback, and a synchronous write there would put flash latency in
 * the packet path.
 */
void flowlog_record(struct flowlog *fl, const struct dpi_result *f,
                    const struct appblock_decision *d,
                    const uint8_t *subject_mac);

/* Write whatever is buffered, if anything. Called on the daemon interval so a
 * quiet link still reports before its rows go stale. */
/*
 * Record what a DNS reply resolved to.
 *
 * A THIRD row shape in this stream, alongside flow rows and the trailing
 * `meta` row: {"dns_map":true,"hostname":...,"ips":[...],"ttl":N,"at":...}
 *
 * Separate from the flow row rather than a field on it, because only DNS
 * flows have answers and widening every row for a field almost all of them
 * leave empty costs spool on flash for nothing.
 *
 * No-op when the flow is not a DNS reply, carries no name, or resolved to
 * nothing reportable -- NXDOMAIN and CNAME-only replies are ordinary and a
 * mapping to no address is not worth a row.
 */
void flowlog_record_dns(struct flowlog *fl, const struct dpi_result *f);

void flowlog_flush(struct flowlog *fl);

#endif /* AETHER_SENSORD_FLOWLOG_H */
