/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * The BRIDGE: local decisions -> real pf state, with the enforcement proof
 * carried all the way through.
 *
 * ======================= WHY THIS IS SEPARATE ==============================
 *
 * local_decide.c answers "should this destination be blocked". This file
 * answers "and did pf actually block it". Splitting them is not tidiness:
 *
 *   - local_decide is a PURE function of the flow, the signature database and
 *     the policy. That is what makes the decision testable without a firewall.
 *   - This file EXECUTES pfctl and then READS BACK. It can only be tested
 *     against a real pf, so it must stay thin -- every branch added here is a
 *     branch that host tests cannot reach.
 *
 * ===================== THE ONE RULE THIS FILE OBEYS =======================
 *
 * `applied` from local_decide means "an element was written to the pf command
 * stream". It does NOT mean pf accepted it. This file closes that last gap by
 * checking the table's own listing after the add, because the failure this
 * project must never produce is a report of ENFORCED for a rule that is not
 * there. A pf table add can fail silently in ways an exit code does not reveal
 * -- the table can vanish between render and apply, the address family can be
 * wrong for the table, a table with an `expire` can have already dropped the
 * element. So the only accepted proof is reading the table back.
 */

#ifndef AETHER_SENSORD_LOCAL_ENFORCE_H
#define AETHER_SENSORD_LOCAL_ENFORCE_H

#include "apply_pf.h"
#include "local_decide.h"
#include "pf.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Per-pass enforcement result.
 *
 * The three fields here are the whole point of the module, so they are
 * deliberately NOT a single "blocked" number:
 *
 *   attempted  elements whose add was issued
 *   confirmed  elements READ BACK from the table afterwards
 *   failed     adds that did not end up verifiable in the table
 *
 * `confirmed == attempted` is the only state that may be described as
 * enforcing. Anything else is a partial application and must be reported as
 * such -- a firewall that block 9 of 10 destinations is not "on".
 */
struct locef_stats {
	uint32_t attempted;
	uint32_t confirmed;
	uint32_t failed;
	uint32_t flushed;     /* elements cleared before this pass */
	uint32_t flush_failed;
};

/*
 * Apply a batch of decisions to one pf table.
 *
 * `enforce` false means observe: NOTHING is executed, and the caller gets
 * attempted=0/confirmed=0 so no enforcement claim can be assembled from it.
 * This is checked here as well as in local_decide because this is the function
 * that would actually run pfctl -- a single point of failure is not enough for
 * the one operation that can take a firewall's table away from it.
 *
 * `verify` false skips the read-back. It exists ONLY so a test can exercise the
 * add path without a live pf; a production caller must leave it true, and the
 * stats then distinguish confirmed from merely-attempted. Callers that pass
 * false cannot obtain a "confirmed" count, which is the correct consequence.
 *
 * The table is NOT flushed here: flushing a table the rest of the system may be
 * writing to is a destructive act that belongs to the caller's policy, not to a
 * per-pass helper. Call `locef_flush` explicitly when that is what you want.
 *
 * Returns true when EVERY attempted add was confirmed (or when nothing was
 * attempted), false when any add failed or could not be verified. A false return
 * with attempted>0 is the "this is NOT enforcing" signal and must be surfaced,
 * not logged and dropped.
 */
bool locef_apply(struct pf_apply_ctx *ctx, const char *table,
                 const struct locdec_block *blocks, size_t n_blocks,
                 bool enforce, bool verify, struct locef_stats *out);

/*
 * Clear the table, and report whether it is genuinely empty afterwards.
 *
 * Separate from apply because the two have different safety profiles: adding
 * elements narrows what passes, flushing REMOVES protection the operator may
 * have expected to be there. A caller that flushes must say so.
 */
bool locef_flush(struct pf_apply_ctx *ctx, const char *table,
                 struct locef_stats *out);

/*
 * One line, in the same shape as locdec_stats_line, so a log reader does not
 * have to learn two formats.
 */
const char *locef_stats_line(const struct locef_stats *s, char *buf,
                             size_t buf_len);

#endif /* AETHER_SENSORD_LOCAL_ENFORCE_H */
