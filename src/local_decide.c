/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * The local decision path: captured flow -> signature match -> policy verdict
 * -> a pf table element. See local_decide.h for what this is and what it
 * deliberately does not do (no DNS, so no pre-population and late enforcement).
 */

#include "local_decide.h"

#include <stdio.h>
#include <string.h>

/*
 * Narrow an observed destination address to the element pf will accept.
 *
 * A detection is about ONE observed destination, so this is deliberately a host
 * route (a full-length prefix) rather than anything wider. Widening from a
 * single observation would block unrelated addresses that happen to share a
 * range, and the whole point of the exercise is to avoid blocking things nobody
 * asked to block.
 *
 * pf.h refuses prefixes wider than PF_MIN_PREFIX_*; a host route is the
 * narrowest possible and is always accepted, so there is no case here where the
 * address must be refused for being too broad.
 */
static bool elem_from_addr(uint8_t family, const uint8_t addr[16],
                           struct pf_elem *out)
{
	if (!out || (family != 4 && family != 6))
		return false;

	memset(out, 0, sizeof *out);
	memcpy(out->addr, addr, family == 4 ? 4 : 16);
	out->family = family;
	/* A single host: every address bit is significant. */
	out->prefix = (family == 4) ? 32 : 128;
	/*
	 * No per-element timeout. pf cannot express one -- decay is the table's
	 * `expire` property -- and pf.h reports that through
	 * timeout_unrepresentable rather than pretending. Setting it here to a
	 * non-zero value would make pf_elem_render report a limitation on every
	 * element, which is noise that would hide a real one.
	 */
	out->timeout_sec = 0;
	out->timeout_unrepresentable = false;
	return true;
}

bool locdec_decide(const struct sig_db *db, const struct pol_db *pol,
                   const struct locdec_flow *flow, struct pol_time now,
                   uint32_t used_today_sec, struct locdec_block *out,
                   bool *block_out, enum pol_reason *reason_out,
                   enum match_kind *kind_out, uint8_t *ambiguous_out)
{
	struct match_result m;
	struct pol_verdict v;
	uint8_t no_mac[POL_MAC_LEN];

	if (block_out)
		*block_out = false;
	if (reason_out)
		*reason_out = POL_REASON_NO_SUBJECT;
	if (kind_out)
		*kind_out = MATCH_NONE;
	if (ambiguous_out)
		*ambiguous_out = 0;

	if (!db || !pol || !flow || !out)
		return false;

	/*
	 * Match the flow against the signature database.
	 *
	 * A NULL or empty host is NORMAL and must not be treated as an error: a
	 * plain-TCP flow, an unparsed QUIC flow, or a fragment has no name, and
	 * port-only rules can still match. Passing "" rather than NULL because
	 * match_flow documents that both are accepted, and an empty string keeps
	 * the call site free of a branch that would only be tested by luck.
	 */
	m = match_flow(db, flow->host ? flow->host : "", flow->proto, flow->dport);
	if (kind_out)
		*kind_out = m.kind;
	if (ambiguous_out)
		*ambiguous_out = m.ambiguous_apps;

	if (m.kind == MATCH_NONE || m.app == NULL)
		return false; /* nothing claims this flow */

	/*
	 * THE AMBIGUITY GUARD, and it is the reason ambiguous_apps exists.
	 *
	 * 30 host patterns in the shipped database are claimed by more than one
	 * application, and the one the matcher returns is whichever the scan
	 * reached first -- not the best one, because it cannot tell them apart.
	 * `en.wikipedia.org` is claimed by six applications, one of which is
	 * classified as Malware.
	 *
	 * Acting on an ambiguous match means a parent is told their child
	 * visited a malware site for reading Wikipedia. So an ambiguous match is
	 * NOT blocked and is NOT silently allowed either -- it is counted
	 * separately, because the operator action (fix the database) is
	 * different from "no rule covers this".
	 */
	if (m.ambiguous_apps > 1)
		return false;

	/*
	 * Policy subject lookup.
	 *
	 * On a ROUTED firewall (which OPNsense is) the frames arriving at an
	 * interface do not carry the original client's MAC -- the router's own
	 * address is there instead. So `have_smac` false is expected rather than
	 * exceptional, and with no MAC there is no SUBJECT, and with no subject
	 * there is no policy.
	 *
	 * This is the honest structural limit of porting an OpenWrt LAN filter
	 * onto a firewall: the identity model is per-LAN-client, and a firewall
	 * is not on the same L2 segment. Rather than inventing a subject (or,
	 * worse, choosing a default such as "block everything for an unknown
	 * client"), this reports NO_SUBJECT and counts it.
	 */
	memset(no_mac, 0, sizeof no_mac);
	v = pol_evaluate(pol, flow->have_smac ? flow->smac : no_mac,
	                 m.app->tag, NULL, now, used_today_sec);
	if (reason_out)
		*reason_out = v.reason;

	if (v.action != POL_BLOCK)
		return false;

	/*
	 * From here the POLICY has said block. Record that fact BEFORE checking
	 * whether it is achievable, because those are different reports and an
	 * earlier version lost the difference: it fell through to "allowed" for
	 * a flow the policy had explicitly blocked.
	 */
	if (block_out)
		*block_out = true;

	/*
	 * We are going to block. Everything from here must be honest about
	 * whether a block is actually ACHIEVABLE, because a block verdict with
	 * no element is a block that cannot exist -- and that is the one report
	 * this project must never fabricate.
	 */
	if (!flow->have_daddr)
		return false; /* counted as no_address by the caller */

	if (!elem_from_addr(flow->daddr_family, flow->daddr, &out->elem))
		return false;

	out->reason = v.reason;
	/*
	 * snprintf rather than strlcpy: these are fixed-size fields being filled
	 * from a variable-length source, and truncation must be defined. The
	 * result is only used for logging and explanation, never for a decision.
	 */
	snprintf(out->app_tag, sizeof out->app_tag, "%s", m.app->tag);
	snprintf(out->host_snip, sizeof out->host_snip, "%s",
	         flow->host ? flow->host : "");
	return true;
}

static bool same_addr(const struct pf_elem *a, const struct pf_elem *b)
{
	size_t n;

	if (a->family != b->family || a->prefix != b->prefix)
		return false;
	n = (a->family == 4) ? 4 : 16;
	return memcmp(a->addr, b->addr, n) == 0;
}

int locdec_fold(const struct sig_db *db, const struct pol_db *pol,
                const struct locdec_flow *flows, size_t n_flows,
                struct pol_time now, uint32_t used_today_sec, bool enforce,
                struct locdec_block *blocks, size_t blocks_cap,
                struct locdec_stats *out, struct locdec_note *notes,
                size_t notes_cap, size_t *n_notes)
{
	size_t i, n_blocks = 0, n_nt = 0;

	if (!out)
		return -1;
	memset(out, 0, sizeof *out);
	if (n_notes)
		*n_notes = 0;

	if (!db || !pol)
		return -1;
	if (n_flows > 0 && !flows)
		return -1;
	if (enforce && blocks_cap > 0 && !blocks)
		return -1;

	for (i = 0; i < n_flows; i++) {
		const struct locdec_flow *f = &flows[i];
		struct locdec_block b;
		enum pol_reason why = POL_REASON_NO_SUBJECT;
		enum match_kind kind = MATCH_NONE;
		uint8_t amb = 0;
		bool have_elem, policy_block;
		size_t k;
		bool dup = false;

		out->flows++;

		have_elem = locdec_decide(db, pol, f, now, used_today_sec, &b,
		                          &policy_block, &why, &kind, &amb);

		/*
		 * Attribute the REFUSAL first, because the counters are what make
		 * an all-allow run diagnosable. Order matters: an ambiguous match
		 * and an unmatched flow both return false, and folding them into
		 * one counter would hide a database defect behind ordinary
		 * traffic.
		 */
		if (!policy_block) {
			if (f->host == NULL || f->host[0] == '\0')
				out->no_host++;
			else if (amb > 1) {
				out->ambiguous++;
				if (notes && n_nt < notes_cap) {
					snprintf(notes[n_nt].host_snip,
					         sizeof notes[n_nt].host_snip,
					         "%s", f->host);
					notes[n_nt].reason = why;
					notes[n_nt].dport = f->dport;
					n_nt++;
				}
			} else if (kind == MATCH_NONE)
				out->not_in_db++;
			else if (why == POL_REASON_NO_SUBJECT)
				out->no_subject++;
			else
				out->allowed++;
			continue;
		}

		/*
		 * The policy said BLOCK. It is counted as blocked, NOT as allowed
		 * -- and regardless of whether an element could be produced,
		 * because "we wanted to block it" and "we managed to" are
		 * different facts and an operator needs both.
		 */
		out->blocked++;

		if (!have_elem) {
			/*
			 * Unenforceable: no destination address was available. This
			 * is the LATE-ENFORCEMENT limitation showing up as a number
			 * rather than as a false claim of success.
			 */
			out->no_address++;
			if (notes && n_nt < notes_cap) {
				snprintf(notes[n_nt].host_snip,
				         sizeof notes[n_nt].host_snip, "%s",
				         f->host ? f->host : "");
				notes[n_nt].reason = why;
				notes[n_nt].dport = f->dport;
				n_nt++;
			}
			continue;
		}

		/* Deduplicate within the batch. */
		for (k = 0; k < n_blocks; k++) {
			if (same_addr(&blocks[k].elem, &b.elem)) {
				dup = true;
				break;
			}
		}
		if (dup) {
			/*
			 * A duplicate is a second FLOW to a destination already in
			 * this batch. It is already in `blocked`; it is one fewer
			 * ELEMENT. Not an error, and not a silent drop either.
			 */
			out->duplicate++;
			continue;
		}

		if (enforce) {
			if (n_blocks >= blocks_cap) {
				out->overflow++;
				continue;
			}
			blocks[n_blocks] = b;
			n_blocks++;
			out->applied++;
		} else {
			out->would_block++;
			/*
			 * Still record it for dedup purposes so observe mode
			 * reports the same duplicate/applied arithmetic a real run
			 * would, but WITHOUT writing to the caller's buffer.
			 */
			if (n_blocks < blocks_cap && blocks) {
				blocks[n_blocks] = b;
				n_blocks++;
			} else if (n_blocks >= blocks_cap) {
				out->overflow++;
			}
		}

		if (notes && n_nt < notes_cap) {
			memcpy(notes[n_nt].daddr, b.elem.addr,
			       b.elem.family == 4 ? 4 : 16);
			notes[n_nt].family = b.elem.family;
			notes[n_nt].reason = b.reason;
			notes[n_nt].dport = f->dport;
			snprintf(notes[n_nt].app_tag, sizeof notes[n_nt].app_tag,
			         "%s", b.app_tag);
			snprintf(notes[n_nt].host_snip,
			         sizeof notes[n_nt].host_snip, "%s",
			         b.host_snip);
			n_nt++;
		}
	}

	if (n_notes)
		*n_notes = n_nt;
	/*
	 * Return the number of elements in `blocks` for BOTH modes. In observe
	 * mode the caller must ignore it -- the buffer was filled for
	 * duplicate arithmetic only, and nothing may be applied from it. The
	 * mode is the caller's own argument, so there is no ambiguity about
	 * which it was.
	 */
	return (int)n_blocks;
}

const char *locdec_stats_line(const struct locdec_stats *s, char *buf,
                              size_t buf_len)
{
	if (!s || !buf || buf_len == 0)
		return NULL;
	snprintf(buf, buf_len,
	         "flows=%u no_host=%u not_in_db=%u ambiguous=%u allowed=%u "
	         "blocked=%u would_block=%u no_address=%u no_subject=%u "
	         "refused=%u duplicate=%u overflow=%u",
	         s->flows, s->no_host, s->not_in_db, s->ambiguous, s->allowed,
	         s->blocked, s->would_block, s->no_address, s->no_subject,
	         s->refused, s->duplicate, s->overflow);
	return buf;
}
