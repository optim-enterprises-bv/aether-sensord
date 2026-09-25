/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * TLS server-name (SNI) extraction, and the frame walk that reaches it.
 *
 * WHY THIS FILE EXISTS AND WHY IT IS NEW. On Linux, `aether-af` is a kernel
 * module: it runs in the netfilter FORWARD hook, pulls the SNI out of the
 * packet, hashes it, and drops. The extraction therefore happened in kernel
 * context and nothing in userspace ever had to parse a ClientHello.
 *
 * FreeBSD has no such module, and the measured replacement (see the
 * freebsd-payload-filtering skill) is netgraph: ng_bpf does the in-kernel
 * filtering and hands the FRAME to a userspace process. So userspace now has to
 * do the parsing the module used to do -- that is the one genuinely new piece in
 * this port, and it is why this is a separate file rather than a branch inside
 * an existing one.
 *
 * WHAT IS REUSED, UNCHANGED: once the hostname is a string, src/match.c decides
 * which application it is and src/policy.c decides the verdict. This file only
 * gets the string out of the bytes; it makes no policy decision and knows nothing
 * about applications. That split is the same one the Linux build has, just moved
 * across the boundary.
 *
 * THE PARSING IS DELIBERATELY SCEPTICAL, because the input is attacker-controlled
 * and arrives from the network. Every length is bounds-checked against the buffer
 * BEFORE it is used, no length is trusted to be self-consistent, and the walk
 * never advances without a bounds check. A malformed ClientHello must produce
 * "malformed", never a read past the end.
 *
 * INCOMPLETE IS NOT NONE, and conflating them is the subtle bug this file is
 * shaped to avoid. A ClientHello can span TCP segments, so a frame walk will
 * routinely see a truncated handshake. Reporting that as "no SNI" would make an
 * unblocked connection indistinguishable from a blocked one in the logs, and
 * would silently under-report coverage. The caller gets the number of bytes it
 * would need to decide.
 *
 * PURE: no sockets, no netgraph, no clock. Host-testable, which is the only
 * reason the fragmented cases below can be asserted at all.
 */

#ifndef AETHER_SENSORD_SNI_H
#define AETHER_SENSORD_SNI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Longest name we will return. DNS names are 253 max; 255 gives margin. */
#define SNI_MAX_NAME 256

enum sni_result {
	/* out holds the name, NUL-terminated. */
	SNI_FOUND = 0,
	/* A parseable ClientHello that carries no server_name. Legal: TLS 1.3
	 * with ECH, resumed sessions, and non-web TLS all do this. */
	SNI_NONE,
	/* The buffer ends before the answer is known. `*need` receives the total
	 * byte count required, so the caller can grow its buffer and retry.
	 * NEVER treat this as "not blocked". */
	SNI_INCOMPLETE,
	/* Not a TLS handshake record at all (SSH, HTTP, QUIC, ...). Normal
	 * traffic, not an error. */
	SNI_NOT_TLS,
	/* Structurally invalid: a length that runs past its container, a
	 * truncated field with more data present, a name with no terminator.
	 * Distinct from INCOMPLETE, which is honest truncation. */
	SNI_MALFORMED
};

const char *sni_result_str(enum sni_result r);

/*
 * Extract the SNI from a TLS record buffer (starting at the record header).
 *
 * `data`/`len` is exactly the TLS bytes. On SNI_FOUND, `out` receives the
 * NUL-terminated hostname. On SNI_INCOMPLETE, `*need` receives the total length
 * required -- the caller should accumulate that many bytes and call again.
 *
 * Names are returned as they appear on the wire, minus a trailing root dot.
 * No lowercasing and no normalisation happen here: the matcher owns case
 * handling (`match_host_pattern`), and doing it twice is how the two get to
 * disagree.
 */
enum sni_result sni_extract(const uint8_t *data, size_t len, char *out,
                            size_t out_len, size_t *need);

/*
 * Walk an Ethernet frame to the TLS record and extract the SNI.
 *
 * Handles Ethernet (with 802.1Q VLAN tags) -> IPv4 -> TCP (with options).
 * Returns SNI_NOT_TLS when the frame is not a TLS-carrying TCP segment, so a
 * caller sees ordinary non-TLS traffic as normal rather than as an error.
 *
 * `*tcp_payload` and `*tcp_payload_len` receive the TLS region on success or
 * when SNI_INCOMPLETE/SNI_NONE is returned, so a caller can cache the bytes and
 * reassemble across segments. `*tcp_seq` receives the segment's sequence number
 * -- the FIRST payload byte's sequence -- which is what a reassembler needs to
 * place this segment correctly. Without it, out-of-order delivery cannot be
 * handled and a ClientHello spanning segments is unparseable. Any of the three
 * output pointers may be NULL.
 *
 * NOT YET HANDLED, stated rather than implied: IPv6, IP fragmentation, and TCP
 * segment reassembly. Each returns SNI_NOT_TLS or SNI_INCOMPLETE rather than a
 * wrong answer, but a caller must not read "no SNI" from a fragmented flow as
 * "nothing to block". See the coverage note at the bottom of sni.c.
 */
enum sni_result sni_extract_frame(const uint8_t *frame, size_t len, char *out,
                                  size_t out_len, size_t *need,
                                  const uint8_t **tcp_payload,
                                  size_t *tcp_payload_len,
                                  uint32_t *tcp_seq);

/*
 * The 5-tuple of a frame, for keying per-flow state and for building an
 * enforcement element.
 *
 * Returns SNI_OK when IPv4/TCP (or UDP) was parsed and `out` is filled, and a
 * non-OK result otherwise. Deliberately NOT a bool: a caller that cannot tell
 * "not IPv4" from "truncated" will mis-count its own coverage, and this layer
 * exists precisely to make coverage visible.
 *
 * This exists separately from sni_extract_frame because the two answer
 * different questions -- "what name is on the wire" and "which flow is this" --
 * and bundling them would put the flow identity behind the SNI parser's
 * success, so a flow whose ClientHello has not arrived yet would have no
 * identity and could not be keyed for reassembly at all. That is a real
 * ordering problem, not a hypothetical one: the first packets of a connection
 * carry no ClientHello.
 *
 * `have_smac` is set from the Ethernet source address. On a ROUTED firewall
 * that is the router's address, not the original client's -- an accurate
 * reading of the frame and a structural limit of the identity model.
 */
struct sni_tuple {
	uint8_t saddr[16];
	uint8_t daddr[16];
	uint8_t family;      /* 4 or 6; only 4 is produced today */
	uint8_t proto;       /* IPPROTO_TCP (6) / IPPROTO_UDP (17) */
	uint16_t sport;
	uint16_t dport;
	uint8_t smac[6];
	bool have_smac;
};

enum sni_result sni_frame_tuple(const uint8_t *frame, size_t len,
                                struct sni_tuple *out);

/*
 * Extract the Ethernet SOURCE MAC from a frame.
 *
 * Separate from sni_extract_frame rather than an extra output parameter,
 * because the two questions have different audiences: the frame parser wants a
 * hostname, and the policy layer wants to know WHICH CLIENT the flow came from.
 * Adding a 7th out-parameter to a function four call sites already use would
 * churn all of them to serve one.
 *
 * Returns true when a MAC was read. False means the frame is too short, is not
 * Ethernet, or is not IPv4 -- caller must then treat the flow as having NO
 * subject rather than substituting a default, because picking a default subject
 * silently applies one client's policy to every other client.
 *
 * NOTE for a ROUTED firewall: this is the MAC ON THE WIRE, which for traffic
 * being forwarded by a router is the ROUTER's address, not the original
 * client's. That is an accurate reading of the frame and a structural limit of
 * the identity model, not a parse failure -- see local_decide.c.
 */
bool sni_frame_src_mac(const uint8_t *frame, size_t len, uint8_t out[6]);

/*
 * Does this result mean the caller knows there is nothing to enforce?
 *
 * True only for SNI_NONE and SNI_NOT_TLS -- the two cases where the answer is
 * genuinely "no hostname". Deliberately false for SNI_INCOMPLETE and
 * SNI_MALFORMED, because in both of those the absence of a name is an artefact
 * of what we saw, not a property of the traffic. A caller that treats those as
 * "nothing to block" under-reports its own coverage.
 */
bool sni_result_is_conclusive(enum sni_result r);

#endif /* AETHER_SENSORD_SNI_H */
