/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Observation aggregation for aether-sensord (originally the aether-fwlogs
 * daemon, merged in; see ADR-020 decision 1).
 *
 * Deliberately free of netlink and libnetfilter_log includes: everything here
 * is pure state machinery over (source address, destination port, timestamp)
 * triples and raw packet bytes, so it builds and unit-tests on the host with
 * plain gcc. `main.c` owns the kernel interface (NFLOG) and does nothing but
 * hand payloads to `obs_decode` and results to `obs_record`.
 */

#ifndef AETHER_FWLOGS_OBSERVE_H
#define AETHER_FWLOGS_OBSERVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Distinct destination ports remembered per source before we stop counting
 * new ones. A scan is identified well below this; the cap bounds memory on a
 * device with 128 MB of RAM facing an internet-wide scanner. */
#define OBS_MAX_PORTS 32

/* What the aggregate looked like. Mirrors `ObservationKind` in the backend
 * crate (aether-nemesis); the strings are the wire contract between them. */
enum obs_kind {
	OBS_BLOCKED_CONNECT, /* few ports, low volume -- near-noise */
	OBS_PORT_SCAN        /* many distinct ports -- intent */
};

const char *obs_kind_str(enum obs_kind k);

/* An address, family-tagged. Stored as bytes so v4 and v6 share one table
 * without a union the caller has to reason about. */
struct obs_addr {
	uint8_t bytes[16];
	uint8_t len; /* 4 or 16 */
};

bool obs_addr_from_v4(struct obs_addr *a, const uint8_t ip[4]);
bool obs_addr_from_v6(struct obs_addr *a, const uint8_t ip[16]);
bool obs_addr_parse(struct obs_addr *a, const char *text);
/* Writes presentation form. `out` must be at least 46 bytes. */
bool obs_addr_str(const struct obs_addr *a, char *out, size_t out_len);
bool obs_addr_eq(const struct obs_addr *a, const struct obs_addr *b);

/*
 * Is this address one we must never report?
 *
 * The firewall rule is supposed to be WAN-scoped, but a misconfigured rule
 * that logs LAN traffic would turn this daemon into a device that reports the
 * subscriber's own network to the cloud. That is a privacy failure, not a data
 * quality one, so it is refused here as well rather than trusted to config.
 *
 * Mirrors the reserved ranges in aether-nemesis's allowlist.
 */
bool obs_addr_is_private(const struct obs_addr *a);

struct obs_entry {
	struct obs_addr src;
	int64_t first_seen; /* unix seconds */
	int64_t last_seen;
	uint32_t hits;
	uint16_t ports[OBS_MAX_PORTS];
	uint8_t n_ports;     /* distinct ports STORED, capped at OBS_MAX_PORTS */
	/*
	 * Distinct destination ports observed, and a FLOOR once the store is
	 * full.
	 *
	 * Dedup can only scan what is stored, so past OBS_MAX_PORTS we cannot
	 * tell a new port from a repeat of an unstored one. This counter
	 * therefore stops at the cap and `ports_truncated` is set, rather than
	 * continuing to increment and reporting 1032 for 33 distinct ports --
	 * which is what an earlier version did, while its comment claimed the
	 * number was exact.
	 *
	 * Precision past the cap is worthless for the decision anyway: the scan
	 * threshold is 8 and the cap is 32, so anything that reaches the cap was
	 * classified as a scan long before.
	 */
	uint32_t ports_seen;
	bool ports_truncated;
	bool used;
};

struct obs_table {
	struct obs_entry *entries;
	size_t capacity;
	size_t used;
	/*
	 * Records refused because the table was full. Reported, never silently
	 * dropped -- a sensor that quietly loses data under load reports a
	 * healthy-looking quiet network during exactly the event we care about.
	 *
	 * Deliberate trade: a full table drops NEW sources and keeps the ones
	 * already tracked. An attacker who fills it early therefore keeps their
	 * own entry and prevents later sources being seen. The alternative, LRU
	 * eviction, lets an attacker evict a legitimately tracked source
	 * instead -- so drop-new is the safer of the two and is chosen, not
	 * inherited. Raise `capacity` if the counter is non-zero in practice.
	 */
	uint64_t dropped_full;
	/* Records refused because the source was private/reserved. Non-zero here
	 * means the firewall rule is mis-scoped. */
	uint64_t dropped_private;
	/*
	 * Distinct destination ports at or above which a source is a scan.
	 *
	 * MUST NOT exceed OBS_MAX_PORTS. `ports_seen` cannot exceed the store,
	 * so a threshold above it is unreachable and would silently disable
	 * scan detection entirely. obs_table_init refuses such a configuration
	 * rather than starting in a state that reports a quiet network.
	 *
	 * That coupling is enforced in code because it used to rest on a UCI
	 * default happening to be smaller than a #define in this header, with
	 * nothing connecting the two.
	 */
	uint32_t scan_port_threshold;
};

/*
 * Returns false on a configuration that cannot work -- notably a
 * scan_port_threshold above OBS_MAX_PORTS, which would be unreachable.
 * Refusing to start beats starting with scan detection silently off.
 */
bool obs_table_init(struct obs_table *t, size_t capacity, uint32_t scan_port_threshold);
void obs_table_free(struct obs_table *t);
void obs_table_reset(struct obs_table *t);

/*
 * Record one dropped/rejected packet.
 *
 * Returns true if it was recorded, false if refused (private source, or table
 * full). Refusals are counted on the table.
 */
bool obs_record(struct obs_table *t, const struct obs_addr *src, uint16_t dst_port,
                int64_t now);

/*
 * Decode a raw L3 packet into (source address, destination port).
 *
 * Returns 0 on success, -1 if the packet cannot be parsed. `dst_port` is 0
 * when the L4 header is absent or not TCP/UDP.
 *
 * Exposed (rather than kept static in main.c) because byte-offset header
 * parsing is the highest-risk correctness code in this package and belongs
 * under test.
 */
int obs_decode(const unsigned char *pkt, int len, struct obs_addr *src,
               uint16_t *dst_port);

/* Classification for an aggregated entry, given the table's threshold. */
enum obs_kind obs_classify(const struct obs_table *t, const struct obs_entry *e);

/*
 * Serialise the table as newline-delimited JSON, one object per source.
 *
 * NDJSON rather than a single document so a truncated spool file (power cut
 * mid-write on a router) loses one line instead of the whole batch.
 *
 * Returns the number of records written, or -1 on write error.
 */
long obs_write_ndjson(const struct obs_table *t, FILE *out);

#endif /* AETHER_FWLOGS_OBSERVE_H */
