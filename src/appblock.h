/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Turning a dissected flow into an enforcement action.
 *
 * This is the join between the three halves that already exist separately:
 *
 *   dpi.c      says what the flow IS      (protocol, hostname, and crucially
 *                                          WHERE a block could be applied)
 *   sigdb/match says which application    (hostname -> stable tag)
 *   policy.c   says whether it is allowed (tag + subject + time -> verdict)
 *
 * and it emits one of exactly two things, because the kernel module and the
 * firewall can each only enforce what they can re-derive:
 *
 *   ACT_HASH  push a name hash to aether-af. Only valid when the kernel can
 *             read that name off the wire itself: TCP, TLS or HTTP.
 *
 *   ACT_ADDR  add the peer address to an nftables set. The only option for
 *             QUIC and the other ~470 protocols, where the name existed only
 *             inside userspace and the kernel has no way to recover it.
 *
 * WHY THE SPLIT MATTERS. Emitting ACT_HASH for a QUIC flow would push a hash
 * that can never match. Nothing would error, the counters would all increment,
 * and the application would simply not be blocked. That is the exact failure
 * ADR-017 is about, so the choice is made in one place and tested on its own.
 *
 * ADDRESS BLOCKS ARE COARSE, AND THAT IS A REAL COST. Blocking an address
 * blocks every name behind it. On shared CDN infrastructure that reaches far
 * beyond the application asked for. The timeout on every element is what keeps
 * the damage bounded and self-healing: an address nobody re-observes ages out
 * rather than being blocked forever on the strength of one classification.
 */

#ifndef AETHER_SENSORD_APPBLOCK_H
#define AETHER_SENSORD_APPBLOCK_H

#include "dpi.h"
#include "nft.h"
#include "policy.h"
#include "sigdb.h"

#include <stdbool.h>
#include <stdint.h>

enum appblock_action {
	ACT_NONE = 0, /* allowed, unknown, or nothing to enforce */
	ACT_HASH,     /* kernel can match the name: push a hash */
	ACT_ADDR      /* kernel cannot: block the peer address */
};

/* Why nothing was enforced. A silent ACT_NONE is indistinguishable from "the
 * policy permits this", and those need to be told apart. */
enum appblock_reason {
	ABR_ENFORCED = 0,
	ABR_NO_HOST,        /* classified, but nDPI recovered no server name */
	ABR_UNKNOWN_APP,    /* hostname matches no signature */
	ABR_NO_SUBJECT,     /* could not attribute the flow to a known device */
	ABR_ALLOWED,        /* policy says allow */
	ABR_AMBIGUOUS       /* hostname claimed by several apps; see below */
};

struct appblock_decision {
	enum appblock_action action;
	enum appblock_reason reason;

	char app_tag[SIG_TAG_LEN];
	uint64_t name_hash;    /* valid when action == ACT_HASH */
	struct nft_elem elem;  /* valid when action == ACT_ADDR */
};

const char *appblock_reason_str(enum appblock_reason r);

/*
 * The same reason as a stable wire token.
 *
 * Deliberately NOT appblock_reason_str(): that returns prose for a human
 * reading syslog ("hostname claimed by several applications"), and the
 * controller parses this one. Same split as canary_result_token(), for the same
 * reason -- shipping the prose would send an unparseable string to a consumer
 * that has its own wording, and the two would drift.
 */
const char *appblock_reason_wire(enum appblock_reason r);

/*
 * Decide what to do about one classified flow.
 *
 * `subject_mac` may be NULL when the flow could not be attributed to a device;
 * the result is then ABR_NO_SUBJECT rather than a guess. The policy engine is
 * per-subject and applying one device's rules to an unattributed flow would
 * block the wrong people.
 *
 * `addr_timeout_sec` is applied to address blocks. Zero is refused rather than
 * meaning "forever": a permanent block from a single heuristic classification
 * is not something this should be able to express by accident.
 */
struct appblock_decision appblock_decide(const struct dpi_result *flow,
                                         const struct sig_db *sigs,
                                         const struct pol_db *pol,
                                         const uint8_t *subject_mac,
                                         struct pol_time now,
                                         uint32_t used_today_sec,
                                         uint32_t addr_timeout_sec);

#endif /* AETHER_SENSORD_APPBLOCK_H */
