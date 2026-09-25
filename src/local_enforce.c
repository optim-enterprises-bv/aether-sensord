/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * The bridge: local decisions -> real pf state. See local_enforce.h for why
 * this is separate from local_decide.c (purity vs execution) and for the rule
 * it obeys (the only accepted proof is reading the table back).
 */

#include "local_enforce.h"

#include <stdio.h>
#include <string.h>

#include "pf.h"

bool locef_apply(struct pf_apply_ctx *ctx, const char *table,
                 const struct locdec_block *blocks, size_t n_blocks,
                 bool enforce, bool verify, struct locef_stats *out)
{
	struct pf_elem elems[LOCDEC_MAX_BLOCKS];
	char err[512];
	size_t i, n = 0;
	bool ok;

	if (!out)
		return false;
	memset(out, 0, sizeof *out);

	if (!ctx || !table || !blocks)
		return false;
	if (n_blocks > LOCDEC_MAX_BLOCKS)
		return false;

	/*
	 * OBSERVE MODE IS ENFORCED HERE, not merely honoured upstream.
	 *
	 * local_decide already leaves the block array empty in observe mode, so
	 * this looks redundant -- and it is the single most valuable redundancy
	 * in the module. If a caller ever passes enforce=false with a populated
	 * batch (a refactor, a mistake, a test left in), the consequence is a
	 * firewall silently blocking traffic nobody approved. Checking here
	 * means the mistake cannot reach pfctl from this function at all.
	 *
	 * It returns TRUE: declining to act in observe mode is correct
	 * behaviour, not a failure. The stats say nothing was attempted, which
	 * is what stops an enforcement claim being assembled from it.
	 */
	if (!enforce)
		return true;

	/*
	 * Narrow the block records to bare elements. pf_apply_add takes elements
	 * and the block records carry an app tag and a reason for the audit
	 * trail -- that context stays with the caller, because pf has nowhere to
	 * put it.
	 */
	for (i = 0; i < n_blocks && n < LOCDEC_MAX_BLOCKS; i++)
		elems[n++] = blocks[i].elem;

	if (n == 0)
		return true; /* nothing to apply is not a failure */

	err[0] = '\0';

	if (verify) {
		/*
		 * The strong path: pf_apply_and_verify confirms membership AND
		 * that a rule in the MAIN ruleset references the table.
		 *
		 * The second check is not belt-and-braces. A populated pf table
		 * proves nothing on its own -- `pfctl -t <t> -T add` auto-creates
		 * a table and exits 0, so a table full of addresses that no rule
		 * reads is indistinguishable from working enforcement if you only
		 * look at the table. Measured: `pfctl -s rules | grep -c
		 * '<aisense_rep4>'` is 0 in exactly that situation.
		 *
		 * So a table with every element present but no rule referencing
		 * it reports FAILED here, which is the honest verdict: the
		 * destinations are not blocked, they are merely listed.
		 */
		ok = pf_apply_and_verify(ctx, table, elems, n, err, sizeof err);
		out->attempted = (uint32_t)n;
		if (ok) {
			out->confirmed = (uint32_t)n;
		} else {
			/*
			 * We cannot say WHICH elements are missing without a
			 * second listing, and guessing one confirmed/total split
			 * from a boolean would invent detail. Report the whole
			 * batch as unconfirmed: a partial application must not be
			 * summarised as "mostly worked".
			 */
			out->failed = (uint32_t)n;
		}
		return ok;
	}

	/*
	 * The weak path, for a test harness with no live pf. Adds are issued
	 * but never claimed as confirmed -- confirmed stays 0, so a caller
	 * cannot mistake this for verification even by accident.
	 */
	{
		enum pf_apply_result r = pf_apply_add(ctx, table, elems, n, err,
		                                      sizeof err);

		out->attempted = (uint32_t)n;
		if (r == PF_APPLY_OK)
			return true;
		out->failed = (uint32_t)n;
		return false;
	}
}

bool locef_flush(struct pf_apply_ctx *ctx, const char *table,
                 struct locef_stats *out)
{
	char err[512];

	if (out)
		memset(out, 0, sizeof *out);
	if (!ctx || !table)
		return false;

	err[0] = '\0';
	if (pf_apply_flush(ctx, table, err, sizeof err) != PF_APPLY_OK)
		goto fail;

	/*
	 * CONFIRM THE TABLE IS ACTUALLY EMPTY.
	 *
	 * pfctl prints "N addresses deleted." and exits 0, and there is a
	 * measured trap here worth naming: `pfctl -F tables` is the
	 * obvious-looking way to clear tables and it FAILS with "Unknown flush
	 * modifier 'tables'", so a cleanup script that used it silently
	 * removed nothing while reporting success. Reading the listing back is
	 * the check that does not depend on reading pfctl's prose correctly.
	 */
	{
		char listing[8192];
		long got = pf_apply_show(ctx, table, listing, sizeof listing);

		if (got < 0)
			goto fail; /* unreadable: cannot claim it worked */
		if (got > 0 && listing[0] != '\0')
			goto fail; /* something is still in the table */
	}

	if (out)
		out->flushed = 1;
	return true;

fail:
	if (out)
		out->flush_failed = 1;
	return false;
}

const char *locef_stats_line(const struct locef_stats *s, char *buf,
                             size_t buf_len)
{
	if (!s || !buf || buf_len == 0)
		return NULL;
	snprintf(buf, buf_len,
	         "attempted=%u confirmed=%u failed=%u flushed=%u "
	         "flush_failed=%u%s",
	         s->attempted, s->confirmed, s->failed, s->flushed,
	         s->flush_failed,
	         /*
	          * Make the ONLY acceptable enforcement state explicit in the
	          * line itself, so nobody has to derive "is this enforcing"
	          * from three numbers while reading a log at 3am.
	          */
	         /*
	          * The state words are chosen so that a substring search for
	          * "ENFORCING" finds enforcement and ONLY enforcement.
	          *
	          * An earlier version printed "PARTIAL -- NOT ENFORCING", and
	          * `grep ENFORCING` matched it -- so the routine way an operator
	          * checks a log ("is this box enforcing?") returned a hit for a
	          * box that was enforcing nothing. The failure direction is the
	          * bad one: the check is designed to answer yes/no quickly, and
	          * a quick yes for a non-enforcing firewall is worse than no
	          * answer.
	          */
	         (s->attempted > 0 && s->confirmed == s->attempted)
	             ? " ENFORCING"
	             : (s->attempted > 0 ? " PARTIAL_DEGRADED" : " idle"));
	return buf;
}
