/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Detecting the flow-offload conflict.
 *
 * THE PROBLEM, established from fw4's own ruleset template:
 *
 *     chain forward {
 *         meta l4proto { tcp, udp } flow offload @ft;   <- emitted FIRST
 *         {% fw4.includes('chain-prepend', 'forward') %}
 *         ...
 *
 * The offload statement precedes every include point fw4 offers, so no rule we
 * can install runs before it. Once a connection is established it is added to
 * the flowtable, and subsequent packets are handled at the ingress hook and
 * never traverse netfilter at all.
 *
 * For a TCP flow that means: SYN, SYN-ACK and ACK traverse the forward chain,
 * and the flow is offloaded. The TLS ClientHello is typically the FOURTH
 * packet. It never arrives.
 *
 * So with flow offloading enabled:
 *   - aether-af sees no ClientHello and matches no SNI
 *   - the classification mirror sees nothing to dissect
 *   - both report healthy, and nothing is inspected
 *
 * This is precisely why Open App Filter shipped disable_hnat=1 as a default.
 * It is not a tuning preference; it is the difference between inspection
 * working and inspection being decorative.
 *
 * WHAT THIS FILE DOES, AND DOES NOT DO. It detects the conflict and reports it.
 * It does NOT silently disable offloading: that is a throughput decision worth
 * real money on IPQ and filogic hardware, and making it behind the operator's
 * back would be its own kind of dishonesty. The init script exposes the choice;
 * this makes sure an unresolved conflict is never quiet.
 */

#ifndef AETHER_SENSORD_OFFLOAD_H
#define AETHER_SENSORD_OFFLOAD_H

#include "apply.h"

#include <stdbool.h>

enum offload_state {
	OFFLOAD_ABSENT = 0,  /* no flowtable: inspection will see traffic */
	OFFLOAD_PRESENT,     /* a flowtable exists: inspection is compromised */
	OFFLOAD_UNKNOWN      /* could not determine -- NOT the same as absent */
};

/*
 * Ask nftables whether a flowtable exists.
 *
 * OFFLOAD_UNKNOWN is deliberately distinct from OFFLOAD_ABSENT. "I could not
 * check" must never be reported as "there is no problem", because the failure
 * being guarded against is itself invisible.
 */
enum offload_state offload_probe(struct apply_ctx *c);

const char *offload_state_str(enum offload_state s);

/*
 * Parse `nft list flowtables` output. Exposed so the decision is testable
 * without nftables, root, or a device.
 */
enum offload_state offload_parse(const char *nft_output);

#endif /* AETHER_SENSORD_OFFLOAD_H */
