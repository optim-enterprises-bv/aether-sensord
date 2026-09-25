/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Reputation feed client -- delta, serial, gap-triggered resync (ADR-019 §7).
 *
 * The device half of the protocol aether-nemesis publishes. A monotonic serial
 * rides every message; deltas apply in order; a gap makes the client demand a
 * full snapshot instead of applying an out-of-order delta.
 *
 * The rule that matters: A GAP LEAVES THE SET UNTOUCHED. Applying a delta
 * across a hole silently diverges the device from the controller, and the
 * divergence is invisible from both ends -- the controller believes it pushed,
 * the device believes it applied. Refusing and resyncing is the only outcome
 * where a missed message is recoverable.
 *
 * Parsing is deliberately narrow. The payload is attacker-influenced in the
 * same sense as nft.h's input, so this extracts only what it recognises and
 * hands every address string to nft_elem_parse, which is strict. Nothing here
 * builds a command; nothing here trusts a string.
 *
 * Pure and host-testable: no sockets, no files, no nft.
 */

#ifndef AETHER_SENSORD_FEED_H
#define AETHER_SENSORD_FEED_H

#include "nft.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * The element representation this protocol carries.
 *
 * The protocol itself is datapath-agnostic -- it is a serial/delta/gap state
 * machine over a set of address prefixes, and whether those end up in an nft
 * set or a pf table is the caller's business. The one place the two met was
 * `struct nft_elem`, whose fields (`addr[16]`, `family`, `prefix`) are already
 * the portable part; only `timeout_sec` is nft set-attribute semantics.
 *
 * Overridable so the FreeBSD/pf build can substitute `struct pf_elem` and reuse
 * this file UNCHANGED, rather than forking the gap/resync logic. A duplicate of
 * correctness-critical serial tracking is how the two builds would drift, and a
 * gap-handling difference is invisible from both ends of the connection.
 *
 * The override must expose the same `addr`, `family` and `prefix` members and
 * provide `<T>_elem_parse(const char *text, <T>* out) == 0` on success.
 */
#ifndef FEED_ELEM_TYPE
#define FEED_ELEM_TYPE struct nft_elem
/*
 * Parse one address string, and carry a default timeout on it.
 *
 * Two calls rather than one because the timeout is not a parse concern: nft
 * accepts it verbatim, while pf cannot express a per-element timeout at all
 * (decay there is a table property -- OPNsense's static-alias `expire`). The
 * pf override therefore RECORDS that the timeout is unrepresentable and still
 * ADMITS the element, because the table's `expire` provides the same decay.
 *
 * Note the failure mode this avoids: rejecting the element instead would make
 * every feed entry unappliable, so the firewall would enforce nothing while
 * looking correctly configured. A capability difference must be reported, not
 * turned into a total loss of function.
 */
#define feed_elem_parse(text, out) (nft_elem_parse((text), (out)) == NFT_OK)
static inline int feed_elem_set_timeout(struct nft_elem *e, uint32_t t)
{
	e->timeout_sec = t;
	return 0;
}
#endif

/* Default timeout carried per element. */
#ifndef FEED_ELEM_TIMEOUT
#define FEED_ELEM_TIMEOUT 604800u
#endif

/*
 * Consecutive missed updates tolerated before a snapshot is demanded. Turris
 * DynFW uses 10 for the same reason: large enough to ride out reordering,
 * small enough to bound how far the device can drift.
 */
#define FEED_MISSING_LIMIT 10

/* Elements carried in one message. Bounded; overflow is counted, not written. */
#define FEED_MAX_ELEMS 512

enum feed_msg_type { FEED_MSG_NONE = 0, FEED_MSG_DELTA, FEED_MSG_LIST };

struct feed_msg {
	enum feed_msg_type type;
	uint64_t serial;
	FEED_ELEM_TYPE add[FEED_MAX_ELEMS];
	size_t n_add;
	FEED_ELEM_TYPE remove[FEED_MAX_ELEMS];
	size_t n_remove;
	/* Elements the payload offered that we refused, and why they were
	 * refused. Reported so a feed shipping junk is visible rather than
	 * presenting as a small update. */
	uint32_t rejected;
	uint32_t overflowed;
};

/*
 * Parse one feed message.
 *
 * Accepts the JSON shape aether-nemesis emits:
 *   {"type":"delta","serial":7,"add":["1.2.0.0/16"],"remove":[]}
 *   {"type":"list","serial":7,"entries":["1.2.0.0/16"],"attribution":[...]}
 *
 * Returns false only when the message is unusable as a whole (no type, no
 * serial). Individual bad elements are refused and counted, because one
 * malformed prefix must not discard an otherwise good update.
 */
bool feed_parse(const char *json, size_t len, struct feed_msg *out);

enum feed_outcome {
	FEED_APPLIED = 0,
	FEED_STALE,          /* serial already seen; ignored */
	FEED_RESYNC_REQUIRED /* gap, or a delta with no baseline */
};

const char *feed_outcome_str(enum feed_outcome o);

struct feed_client {
	uint64_t serial;
	bool have_baseline;
	uint32_t missed;
	/* Cumulative, for the health surface. */
	uint64_t applied_deltas;
	uint64_t applied_lists;
	uint64_t resyncs;
};

void feed_client_init(struct feed_client *c);
bool feed_client_needs_resync(const struct feed_client *c);

/*
 * Fold a message into the client's serial state.
 *
 * Returns what the caller should do. On FEED_APPLIED the caller applies
 * msg->add / msg->remove (or replaces the set outright, for a list). On
 * FEED_RESYNC_REQUIRED the caller must request a snapshot and apply NOTHING
 * from this message.
 */
enum feed_outcome feed_client_accept(struct feed_client *c,
                                     const struct feed_msg *msg);

#endif /* AETHER_SENSORD_FEED_H */
