/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * nDPI dissection: identifying what a flow actually is.
 *
 * WHY THIS EXISTS. aether-af matches TLS SNI and HTTP Host by hash, in the
 * kernel, and af_module.c refuses anything that is not IPPROTO_TCP. That covers
 * the traffic OAF covered and nothing more. It cannot see QUIC, which is where
 * Chrome and YouTube actually go, and it cannot tell Signal from Slack -- only
 * whether a hostname string matched.
 *
 * nDPI is the answer to both, and it is a LIBRARY, not a daemon. libndpi is
 * LGPL-3.0-or-later, which links into this BSD-3-Clause binary without
 * contaminating it. The nDPId daemon (GPL-3, libpcap, cannot enforce) is a
 * different thing and is deliberately not used.
 *
 * WHERE ENFORCEMENT HAPPENS, which is the part worth understanding:
 *
 *   TCP + TLS/HTTP  -> the kernel already extracts the name itself. nDPI adds
 *                      accuracy, not reach. Enforcement stays in aether-af by
 *                      name hash.
 *
 *   QUIC and the    -> the kernel CANNOT re-derive the name; it never sees UDP,
 *   other 473          and QUIC's SNI is inside an encrypted Initial packet
 *   protocols          that only nDPI decrypts. A name hash is therefore
 *                      useless here. Enforcement must be by ADDRESS, using the
 *                      same nftables set machinery reputation already uses.
 *
 * That asymmetry is not a wart, it is the whole reason this file exists: the
 * kernel enforces what it can re-derive, and userspace enforces what only it
 * can see.
 *
 * FIRST FLOW LEAKS. Classification needs several packets, so the flow that
 * teaches us an address is already in progress when we learn it. Subsequent
 * flows to that address are blocked. This is the same trade OAF makes and
 * ADR-020 accepted; it is stated here so nobody reads "blocked" as "no packet
 * ever reached it".
 */

#ifndef AETHER_SENSORD_DPI_H
#define AETHER_SENSORD_DPI_H

#include "observe.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* nDPI's own host_server_name is 80 bytes; a DNS name is at most 253. We keep
 * the larger bound and truncate explicitly rather than inheriting a limit we
 * did not choose. */
#define DPI_HOST_MAX 256
#define DPI_PROTO_NAME_MAX 64

/*
 * How many packets of a flow to keep feeding nDPI before giving up on it.
 *
 * Deliberately NOT OAF's behaviour. OAF's g_by_pass_accl abandons a flow after
 * 256 packets and lets everything after through -- FEATURE-MATRIX records that
 * as a rejected bug, not a feature. This limit only stops DISSECTION, which
 * nDPI has either finished or failed by then; it never changes a verdict and
 * never lets an already-blocked address through.
 */
#define DPI_MAX_PKTS_PER_FLOW 32

/* Answers carried per DNS reply.
 *
 * nDPI stores up to MAX_NUM_DNS_RSP_ADDRESSES; this takes the first few. A
 * CDN name resolving to a dozen addresses does not need all of them recorded
 * to attribute a flow -- the client connects to one, and any of the first few
 * is as likely as the rest. Bounded because every one of these widens the
 * flow row, and a row that cannot be shown to fit is a row that truncates. */
#define DPI_MAX_ANSWERS 4

enum dpi_verdict_scope {
	/* Kernel can re-derive this name from the wire: push a hash. */
	DPI_SCOPE_NAME_HASH = 0,
	/* Kernel cannot: block by address in nftables. */
	DPI_SCOPE_ADDRESS = 1
};

struct dpi_result {
	bool classified;      /* nDPI reached a verdict */
	bool have_host;       /* a usable server name was extracted */
	uint16_t master_proto;
	uint16_t app_proto;
	char proto_name[DPI_PROTO_NAME_MAX];
	char host[DPI_HOST_MAX];
	bool host_truncated;  /* name was longer than we store; NEVER silent */

	struct obs_addr src, dst;
	uint16_t sport, dport;
	uint8_t l4proto;

	/* Where a block for this flow has to be applied. See the header note. */
	enum dpi_verdict_scope scope;

	/*
	 * DNS answers, when this flow is a DNS reply.
	 *
	 * WHY. nDPI recovers a QUIC SNI only when the ClientHello fits in one
	 * Initial packet, and Chrome's no longer does -- its post-quantum key
	 * share splits the ClientHello across two or three Initials and nDPI
	 * does not reassemble QUIC CRYPTO frames. Measured on a capture from
	 * the BPI-R4: Wireshark recovered 6 names, nDPI 5.0.0 recovered 1, and
	 * nDPI dev (with the Wireshark-derived QUIC refactor) also 1. Every
	 * QUIC flow therefore reaches the controller unnamed.
	 *
	 * The addresses were resolved by this same household moments earlier
	 * and nDPI has always parsed the answers -- nothing read them. The
	 * flow's `dst` for a DNS reply is the RESOLVER, so the controller
	 * learned which name was asked for and never what it resolved to.
	 * These fields carry the missing half.
	 *
	 * NOT a lookup. This is an answer the device already forwarded to the
	 * client that asked for it.
	 */
	struct obs_addr answers[DPI_MAX_ANSWERS];
	uint32_t answer_ttl[DPI_MAX_ANSWERS];
	uint8_t n_answers;
};

/* Counters. Every one of these is a way dissection can fail to happen, and a
 * silent zero is indistinguishable from a quiet network. */
struct dpi_stats {
	uint64_t packets_in;
	uint64_t undecodable;      /* not parseable as IPv4/IPv6 */
	uint64_t flows_new;
	uint64_t flows_evicted;    /* table full: oldest dropped */
	uint64_t flows_refused;    /* table full AND nothing evictable */
	uint64_t classified;
	uint64_t with_host;
	uint64_t host_truncated;
	uint64_t gave_up;          /* hit DPI_MAX_PKTS_PER_FLOW unclassified */
};

struct dpi_ctx;

/*
 * Create a dissection context holding at most `max_flows` concurrent flows.
 *
 * Returns NULL if nDPI could not initialise or the bound is unusable. It does
 * NOT fall back to an unbounded table: memory exhaustion on a router is a
 * worse failure than not classifying.
 */
struct dpi_ctx *dpi_new(size_t max_flows);
void dpi_free(struct dpi_ctx *c);

/*
 * Feed one L3 packet (IPv4 or IPv6 header first).
 *
 * Returns true when `out` holds a NEW classification -- once per flow, at the
 * moment nDPI reaches a verdict. Returns false for packets that merely advance
 * a flow, so a caller can act on the result without deduplicating.
 */
bool dpi_process(struct dpi_ctx *c, const uint8_t *pkt, uint32_t len,
                 uint64_t now_ms, struct dpi_result *out);

/* Expire flows idle for longer than `idle_ms`. Returns how many were freed. */
size_t dpi_expire(struct dpi_ctx *c, uint64_t now_ms, uint64_t idle_ms);

void dpi_get_stats(const struct dpi_ctx *c, struct dpi_stats *out);

/* Human-readable nDPI protocol name, or "" when unavailable. */
const char *dpi_proto_name(struct dpi_ctx *c, uint16_t proto_id);

/*
 * True when the kernel module could re-derive this protocol's name itself.
 *
 * Exposed and tested separately because getting it wrong is silent in the
 * dangerous direction: treating a QUIC flow as name-hashable pushes a hash the
 * kernel will never match, and the block simply never happens while every
 * counter reports success.
 */
bool dpi_kernel_can_match(uint8_t l4proto, uint16_t master_proto,
                          uint16_t app_proto);

#endif /* AETHER_SENSORD_DPI_H */
