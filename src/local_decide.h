/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * The LOCAL decision path: from a captured flow to a pf table element.
 *
 * ======================== WHY THIS FILE EXISTS =============================
 *
 * Before this, the port had two halves that did not touch:
 *
 *   - src/ng_sni.c read frames off a real interface and produced a hostname.
 *     It was referenced by NOTHING except its own test. It was a capability
 *     demonstration with no consumer.
 *
 *   - src/daemon_pf.c enforced -- but only what the REMOTE FEED told it to
 *     block. Its decisions arrived as reputation prefixes over the network.
 *
 * So the daemon could not act on anything it saw locally, and the detector's
 * output went into the void. This file is the join.
 *
 * ===================== IT DOES NOT DO DNS. THAT IS THE POINT. ==============
 *
 * The interesting property, and the reason this is worth building at all: the
 * pipeline runs SNI -> signature -> pf table and never resolves a name. There
 * is no resolver in the path, so there is nothing to poison, no cache to
 * manipulate, and no query leaving the network that tells anyone which names
 * this device cares about. A DNS-based filter leaks that; this one cannot.
 *
 * It also means the local path cannot be defeated by a client choosing a
 * resolver you do not control, which is the standard bypass for DNS filtering.
 * The name is read where it is actually used -- in the handshake -- rather than
 * where it was looked up.
 *
 * ============================ WHAT THIS IS NOT ============================
 *
 * NO DNS NAME -> ADDRESS MAPPING IS PERFORMED, SO THE TABLE CANNOT BE PRE-
 * POPULATED. This is the honest limitation and it is structural, not a bug to
 * be fixed later:
 *
 *   - A pf rule matches on ADDRESS. Reading a hostname tells you nothing about
 *     which address the client is about to use, without a DNS lookup.
 *   - So acting on a detection means adding the destination address of the
 *     flow that was just observed -- AFTER its first packets have already
 *     flowed. Enforcement is therefore LATE, by exactly one handshake.
 *
 * An earlier design considered capturing a DNS response (read the name ->
 * address binding off the wire, still without querying) and pre-populating from
 * that. It is a genuinely better design and it is NOT implemented here. It is
 * called out because a reader will otherwise assume the obvious thing happens.
 *
 * The late-by-one-handshake property is why this is described as ADVISORY /
 * ENFORCEMENT-ASSIST rather than as a filter that stops browsing. What it
 * reliably does is ensure the SAME destination is denied on every subsequent
 * connection, which for a persistent endpoint is most of them.
 *
 * ============================== SAFETY =====================================
 *
 * The unforgivable failure for anything that writes pf state is reporting
 * ENFORCED when nothing blocks, so:
 *
 *   - a BLOCK verdict requires the destination address in hand. No address, no
 *     element: the flow is counted as unenforceable and REPORTED, never turned
 *     into a block that cannot exist.
 *   - the address is narrowed to the widest prefix pf will accept for an
 *     address-derived entry (a single host), because a detection is about one
 *     observed destination, not about a range. Widening is never justified by a
 *     single observation.
 *   - nothing is applied unless the caller said enforce=true. In observe mode
 *     this records what it WOULD have done, which is what makes a dry run
 *     meaningful rather than a guess.
 *
 * PURE AND HOST-TESTABLE. No sockets, no netgraph, no pfctl, no clock. The
 * caller owns all of that; this decides.
 */

#ifndef AETHER_SENSORD_LOCAL_DECIDE_H
#define AETHER_SENSORD_LOCAL_DECIDE_H

#include "match.h"
#include "pf.h"
#include "policy.h"
#include "sigdb.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Bounded, and the bound is load-bearing. A daemon that accumulates a
 * flow-decision per packet would grow without limit under traffic, and the
 * growth would be invisible until it was fatal. Per-pass.
 */
#define LOCDEC_MAX_BLOCKS 512

/*
 * One captured flow, as the capture layer sees it. Deliberately NOT the capture
 * layer's own struct: this file must be testable without netgraph, and the
 * capture struct is owned by ng_sni.h.
 */
struct locdec_flow {
	const char *host;      /* SNI hostname, or NULL/empty when none was parsed */
	uint8_t proto;         /* SIG_PROTO_TCP / UDP */
	uint16_t dport;
	/* The client and server addresses of THIS flow, already parsed. The
	 * server side is what a pf table can hold. `have_daddr` false means the
	 * capture layer could not give us one -- see the honesty note below. */
	uint8_t daddr[16];
	uint8_t daddr_family;  /* 4 or 6 */
	bool have_daddr;
	/* Source MAC, for policy subject lookup. False when unavailable, which
	 * is normal on a routed firewall (see the note in decide()). */
	uint8_t smac[POL_MAC_LEN];
	bool have_smac;
};

/*
 * Per-pass counters.
 *
 * `blocked` is what was APPLIED; `would_block` is what would have been applied
 * in observe mode. They are separate fields on purpose: a single "blocked"
 * counter that counted dry-run decisions is how a report of enforcement ends up
 * describing something that never happened.
 */
struct locdec_stats {
	uint32_t flows;             /* decisions requested */
	uint32_t no_host;           /* nothing parsed: counted, not guessed at */
	uint32_t not_in_db;         /* a hostname, but no signature claims it */
	uint32_t ambiguous;         /* matched, but the database was ambiguous */
	uint32_t allowed;           /* matched and policy allowed it */
	uint32_t no_subject;        /* policy has no subject for this MAC */

	/*
	 * THE DISTINCTION THAT MATTERS, and the reason `blocked` is not the same
	 * as `applied`.
	 *
	 * `blocked` counts FLOWS whose policy verdict was BLOCK and for which an
	 * element could actually be produced. `applied` counts ELEMENTS written.
	 * They differ because several flows routinely share one destination.
	 *
	 * An earlier version conflated a block verdict with a successful apply,
	 * and the consequence was worse than a wrong number: a block verdict
	 * with NO destination address fell through to `allowed`, so a flow the
	 * policy wanted blocked was reported as explicitly permitted. That is
	 * the failure direction this project exists to eliminate.
	 */
	uint32_t blocked;           /* block verdict, address in hand */
	uint32_t applied;           /* elements actually written to pf */
	uint32_t would_block;       /* observe mode: blocked, but not applied */

	uint32_t no_address;        /* block verdict, but no destination address */
	uint32_t refused;           /* pf rejected the element */
	uint32_t overflow;          /* hit LOCDEC_MAX_BLOCKS this pass */
	uint32_t duplicate;         /* addr already in this batch (subset of
	                             * blocked, and NOT a second element) */
};

/*
 * HOW TO READ THE COUNTERS -- the partition rule, stated because getting it
 * wrong reads as a data-loss bug when it is not one.
 *
 * Every flow falls into EXACTLY ONE of these buckets:
 *
 *     no_host | not_in_db | ambiguous | allowed | no_subject | blocked
 *
 * The remaining fields QUALIFY the blocked bucket and do not partition it:
 *
 *     no_address   blocked, but unenforceable (no address in hand)
 *     duplicate    blocked, but this batch already had that address
 *     overflow     blocked, but the batch buffer was full
 *     applied      ELEMENTS written (not flows) -- several flows commonly
 *                  share one destination, so applied <= blocked
 *     would_block  blocked in observe mode; nothing was written
 *
 * So `blocked + no_address` is NOT a meaningful sum: an unenforceable block is
 * counted in `blocked` AND in `no_address`. It would be reasonable to read that
 * as double-counting. It is not -- an earlier version kept them as separate
 * buckets and consequently counted a blocked-but-unenforceable flow as
 * ALLOWED, which reported explicit permission for a flow the policy had
 * explicitly denied.
 */

/*
 * Why a decision came out the way it did. One entry per considered block, kept
 * so a verdict is explainable after the fact -- "why was this blocked" must
 * have an answer that is not "run it again and watch".
 */
struct locdec_note {
	uint8_t daddr[16];
	uint8_t family;
	uint16_t dport;
	enum pol_reason reason;
	char app_tag[SIG_TAG_LEN];
	char host_snip[64];
};

/*
 * One detection: the answer to "should this flow's destination be in the block
 * table", with everything needed to apply and to explain it.
 */
struct locdec_block {
	struct pf_elem elem;
	enum pol_reason reason;
	char app_tag[SIG_TAG_LEN];
	char host_snip[64];
};

/*
 * Decide for one flow.
 *
 * PURE: no I/O, no clock, no allocation. `now` and `used_today_sec` are
 * supplied by the caller exactly as pol_evaluate needs them, so a test can
 * reach every branch.
 *
 * Returns true when an element was produced (the caller then owns `out`).
 *
 * `*block_out` is set when the POLICY said block, whether or not an element
 * could be produced. The two are genuinely different questions and conflating
 * them was a defect: "the policy wants this blocked" and "we have something to
 * block" must be reported separately, or an unenforceable block gets counted as
 * an allowed flow.
 *
 * `*reason_out` always receives the policy's reason, so the caller can count WHY
 * -- which is what makes an all-allow run diagnosable rather than merely quiet.
 */
bool locdec_decide(const struct sig_db *db, const struct pol_db *pol,
                   const struct locdec_flow *flow, struct pol_time now,
                   uint32_t used_today_sec, struct locdec_block *out,
                   bool *block_out, enum pol_reason *reason_out,
                   enum match_kind *kind_out, uint8_t *ambiguous_out);

/*
 * Fold a batch of flows into block decisions.
 *
 * The caller supplies the flows, then applies whatever came back. Deduplicates
 * by destination within the batch, because the same address is routinely seen
 * on many flows (a CDN, a retry, several connections to one endpoint) and
 * applying it repeatedly is wasted pfctl invocations and a misleading count.
 *
 * `enforce` false means observe: decisions are still made and counted, but the
 * blocks array is left EMPTY and would_block is incremented instead. That is
 * the dry-run, and separating it from `blocked` is deliberate.
 *
 * Returns the number of blocks written, or -1 on a bad argument.
 */
int locdec_fold(const struct sig_db *db, const struct pol_db *pol,
                const struct locdec_flow *flows, size_t n_flows,
                struct pol_time now, uint32_t used_today_sec, bool enforce,
                struct locdec_block *blocks, size_t blocks_cap,
                struct locdec_stats *out, struct locdec_note *notes,
                size_t notes_cap, size_t *n_notes);

const char *locdec_stats_line(const struct locdec_stats *s, char *buf,
                              size_t buf_len);

#endif /* AETHER_SENSORD_LOCAL_DECIDE_H */
