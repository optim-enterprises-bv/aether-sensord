/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * TCP stream reassembly, for the case the frame walk cannot handle.
 *
 * THE PROBLEM THIS SOLVES, measured. sni_extract_frame parses one frame, and a
 * TLS ClientHello does not have to fit in one frame. Modern browsers send a
 * large ClientHello -- post-quantum key shares pushed it past 1,400 bytes -- so
 * the record header and the SNI routinely land in DIFFERENT segments. On the
 * single-frame path that case returns SNI_INCOMPLETE, the name is never
 * recovered, and the flow is not classified. A user can therefore reach an
 * application this appliance is supposed to block simply by having it send a
 * large ClientHello. That is not a corner case; it is the shipping default in
 * current browsers.
 *
 * WHAT THIS DOES. It keeps a small per-flow buffer of the out-of-order-tolerant
 * kind: each segment is placed at its TCP sequence offset and the SNI is
 * re-extracted once enough contiguous bytes exist. It stops as soon as the name
 * is known or the answer is conclusive, so the steady-state cost per flow is one
 * ClientHello.
 *
 * DELIBERATE LIMITS, stated so nobody has to infer them:
 *
 *   - One direction only. We reassemble the client->server stream, because the
 *     ClientHello only ever travels that way. Nothing here is a general TCP
 *     stack and it must not be used as one.
 *
 *   - Bounded memory, hard. Each flow keeps at most FLOW_CAP bytes and at most
 *     FLOW_SEGS segments. Once the buffer is full, bytes are DROPPED and the
 *     flow is marked truncated rather than growing. The alternative -- letting
 *     an attacker choose our memory footprint by sending a large stream -- is
 *     how a filtering appliance becomes a denial-of-service target.
 *
 *   - No overlap resolution beyond "first write wins". A retransmission that
 *     carries different bytes will not overwrite what is already placed. For
 *     finding a hostname that is adequate, and being deterministic matters more
 *     here than being maximal: a flow that classifies differently on a retransmit
 *     is a flow whose verdict changes under network conditions.
 *
 *   - No timeouts here. Eviction is the caller's business (it owns the clock);
 *     flow_free releases a slot and the caller decides when a flow is abandoned.
 *
 * PURE: no sockets, no netgraph, no clock. Every case below is host-testable,
 * which is the only reason the adversarial ones can be asserted at all.
 */

#ifndef AETHER_SENSORD_REASSEMBLY_H
#define AETHER_SENSORD_REASSEMBLY_H

#include "sni.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Largest reassembly window. A ClientHello is ~2 KB with post-quantum keys;
 * this leaves room for a split one plus a little reordering. */
#define REASM_CAP 4096
/* Segments retained. Real splits are 2-3; more than this is not a ClientHello
 * we are going to parse anyway. */
#define REASM_MAX_SEGS 8

enum reasm_result {
	/* A name was recovered. `out` holds it. */
	REASM_FOUND = 0,
	/* Enough of the stream was seen to know there is no hostname. */
	REASM_ABSOLUTE_NONE,
	/* Need more bytes; feed another segment. */
	REASM_NEED_MORE,
	/* Not a TLS ClientHello: plain HTTP, a non-web protocol, a bare ACK. */
	REASM_NOT_TLS,
	/* The bytes are structurally invalid and will not become valid. */
	REASM_INVALID,
	/* A gap or an overrun means the missing bytes will never arrive, so this
	 * flow will never be classified. NOT the same as NEED_MORE, and the
	 * distinction is the whole reason this enum has six members. */
	REASM_WILL_NOT_RESOLVE
};

const char *reasm_result_str(enum reasm_result r);

struct reasm_flow {
	uint32_t next_seq;   /* next byte we have contiguously */
	uint32_t start_seq;  /* first byte we ever saw */
	bool     started;
	bool     saw_gap;
	bool     truncated;
	unsigned segs;       /* segments placed, for the termination budget */
	uint8_t  buf[REASM_CAP];
	size_t   len;
};

void reasm_init(struct reasm_flow *f);

/*
 * Place one segment's payload and try to extract the SNI.
 *
 * `seq` is the TCP sequence number of the FIRST payload byte; `data`/`len` is
 * the payload. Returns the current best answer -- which may improve as later
 * segments arrive, so a caller should keep feeding until the result is one of
 * FOUND / ABSOLUTE_NONE / INVALID / WILL_NOT_RESOLVE, and stop there.
 *
 * Calling this with a segment that is entirely retransmitted is harmless: the
 * bytes are already placed and the same answer is returned.
 */
enum reasm_result reasm_feed(struct reasm_flow *f, uint32_t seq,
                             const uint8_t *data, size_t len, char *out,
                             size_t out_len);

/*
 * Should the caller keep feeding this flow?
 *
 * False once the answer cannot change. A caller that ignores this wastes memory
 * buffering the rest of a connection it has already decided about.
 */
bool reasm_wants_more(const struct reasm_flow *f, enum reasm_result r);

/*
 * True when bytes were dropped because the buffer filled.
 *
 * Reported separately from a bad verdict because the operator action differs:
 * a truncated flow means our window was too small for the traffic being seen,
 * which is a capacity question, not a blocking question.
 */
bool reasm_was_truncated(const struct reasm_flow *f);

#endif /* AETHER_SENSORD_REASSEMBLY_H */
