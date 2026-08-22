/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Pushing compiled rules to the aether-af kernel module.
 *
 * This is the userspace half of the licence boundary. Everything valuable
 * lives on this side -- the 1,347-signature database, the matcher, the tag
 * vocabulary, the policy engine -- and what crosses to the kernel is only
 * (hash, subject, verdict). The module cannot reconstruct a signature from a
 * hash, which is exactly why the GPL obligation stops at the module.
 *
 * NO GPL LIBRARY IS USED HERE. A custom netlink unit needs nothing beyond
 * socket(AF_NETLINK, SOCK_RAW, unit) and sendmsg, both plain POSIX. This file
 * deliberately does not link libnetfilter_* (GPL-2.0-or-later) or libnfnetlink
 * (GPL-2.0+). That is not incidental -- linking either would make this binary
 * GPL and defeat the entire split.
 *
 * Message construction is separated from socket I/O so the wire format can be
 * unit-tested on the host without a module loaded, root, or a device.
 */

#ifndef AETHER_SENSORD_AFPUSH_H
#define AETHER_SENSORD_AFPUSH_H

#include "policy.h"
#include "sigdb.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Kept in step with net/aether-af/src/af_proto.h. Duplicated rather than
 * shared by path because the two packages build independently; a mismatch is
 * caught by the version handshake rather than by a build error, which is why
 * the handshake exists. */
#define AFPUSH_NETLINK_UNIT 31
#define AFPUSH_PROTO_VERSION 1
#define AFPUSH_MAC_LEN 6
#define AFPUSH_MAX_MSG 8192

enum afpush_msg {
	AFPUSH_NOOP = 0,
	AFPUSH_HELLO,
	AFPUSH_RULES_BEGIN,
	AFPUSH_RULE_ADD,
	AFPUSH_RULES_COMMIT,
	AFPUSH_SUBJECT_ADD,
	AFPUSH_SUBJECT_CLEAR,
	AFPUSH_STATS_REQ
};

/*
 * FNV-1a over the lowercased name.
 *
 * MUST match af_hash_name() in the module byte for byte. A divergence would
 * not fail loudly -- it would silently stop every rule matching, which looks
 * exactly like "there is nothing to block". The shared test vector below
 * exists so a drift is caught by a test rather than in the field.
 */
uint64_t afpush_hash_name(const char *name, size_t len);

/* Build one message into `buf`. Returns bytes written, 0 if it would not fit. */
size_t afpush_build_hello(uint8_t *buf, size_t cap);
size_t afpush_build_simple(uint8_t *buf, size_t cap, enum afpush_msg type);
size_t afpush_build_rules(uint8_t *buf, size_t cap, const uint64_t *hashes,
                          const uint8_t (*macs)[AFPUSH_MAC_LEN],
                          const bool *per_subject, size_t n,
                          size_t *n_written);
size_t afpush_build_subjects(uint8_t *buf, size_t cap,
                             const uint8_t (*macs)[AFPUSH_MAC_LEN], size_t n,
                             size_t *n_written);

/*
 * Compile a policy database plus a signature database into the hashes the
 * module needs.
 *
 * This is where the product becomes fingerprints. For every BLOCK rule the
 * policy holds, every host pattern of the matching application is hashed. The
 * kernel receives those hashes and nothing else -- no tag, no id, no category.
 *
 * Returns the number of hashes produced, or -1 on error. `n_collisions`
 * receives the number of distinct patterns that hashed to a value already
 * present. The daemon can detect those because it holds both sides; the kernel
 * cannot and must not try.
 */
long afpush_compile(const struct pol_db *pol, const struct sig_db *sigs,
                    uint64_t *out, size_t out_cap, size_t *n_collisions);

/* Live connection. Kept minimal; the exec seam is the socket itself. */
struct afpush_conn {
	int fd;
	uint64_t sent_rules;
	uint64_t sent_subjects;
};

bool afpush_open(struct afpush_conn *c);
void afpush_close(struct afpush_conn *c);
bool afpush_send(struct afpush_conn *c, const uint8_t *msg, size_t len);

#endif /* AETHER_SENSORD_AFPUSH_H */
