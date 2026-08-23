/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * NFLOG over raw netlink, with no GPL library.
 *
 * WHY THIS EXISTS: aether-fwlogs previously linked libnetfilter_log and
 * libnfnetlink, both GPL-2.0-or-later, while declaring BSD-3-Clause. Linking a
 * GPL library into a binary makes the combined work GPL, so the declared
 * licence was simply wrong. This file removes the dependency rather than
 * changing the declaration, because a BSD daemon was the point.
 *
 * The convenience those libraries provide is message construction and
 * attribute walking. Both are small when the message set is this narrow: bind
 * a group, set copy mode, then parse one message type. A protocol is an
 * interface, not expression -- the same reasoning that let us reimplement the
 * DynFW feed protocol.
 *
 * Nothing here is generic. It handles exactly the NFULNL messages we need and
 * refuses everything else, which is a deliberate limit: a general netlink
 * parser is a much larger attack surface for a daemon reading data that
 * ultimately originates off-device.
 */

#ifndef AETHER_FWLOGS_NFLOG_RAW_H
#define AETHER_FWLOGS_NFLOG_RAW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bounded so a hostile or buggy sender cannot make us allocate. */
#define NFR_RECV_BUF 65536

struct nfr_conn {
	/* What we asked the kernel to copy. Recorded so a caller can report
	 * it: a dissector fed truncated packets identifies protocols it
	 * cannot name, and the request is the only way to tell. */
	uint16_t copy_range;
	int fd;
	uint16_t group;
	/* Counted, never silently dropped: a receive error or a malformed
	 * message must be visible, since this daemon's entire job is to notice
	 * things. */
	uint64_t recv_errors;
	uint64_t malformed;
	uint64_t overruns;
};

/*
 * Bind to an NFLOG group and set copy mode.
 *
 * `copy_range` is how many bytes of each packet the kernel sends us. 96 is
 * enough for the L3/L4 headers, and asking for no more is what keeps packet
 * CONTENTS out of this process entirely -- we read addresses and ports, never
 * payload.
 */
bool nfr_open(struct nfr_conn *c, uint16_t group, uint16_t copy_range);
void nfr_close(struct nfr_conn *c);

/*
 * Called for each packet payload recovered from a message.
 *
 * `data`/`len` is the raw L3 packet, exactly what obs_decode expects.
 */
typedef void (*nfr_packet_fn)(const uint8_t *data, uint32_t len, void *user);

/*
 * Read whatever is available and dispatch each packet.
 *
 * Returns the number of packets dispatched, or -1 on a fatal socket error.
 * ENOBUFS is NOT fatal -- it means the kernel queue overran and we lost
 * records, which is counted in `overruns` and reported, because a sensor that
 * hides its own data loss reports a quiet network during exactly the event
 * that matters.
 */
long nfr_dispatch(struct nfr_conn *c, nfr_packet_fn cb, void *user);

/*
 * Parse one NFULNL message buffer and dispatch the payloads inside it.
 *
 * Exposed separately from the socket so the parser can be unit-tested against
 * malformed and truncated input on the host, with no netlink, no root and no
 * kernel. Returns packets dispatched; increments `malformed` on bad input.
 */
/*
 * Parse a netlink ACK. Exposed so the "did the kernel actually accept this"
 * decision is testable without root -- the failure it guards against is a
 * sensor that reports itself live while receiving nothing.
 *
 * True ONLY for an explicit success ACK. Anything else, including a reply we
 * do not recognise, is refused rather than read as consent.
 */
bool nfr_parse_ack(const uint8_t *buf, size_t len);

long nfr_parse_buffer(struct nfr_conn *c, const uint8_t *buf, size_t len,
                      nfr_packet_fn cb, void *user);

#endif /* AETHER_FWLOGS_NFLOG_RAW_H */
