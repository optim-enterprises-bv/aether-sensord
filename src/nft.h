/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * nftables enforcement rendering for aether-sensord (ADR-019, ADR-020).
 *
 * Turns a reputation set into nftables commands. This is the enforcement half
 * of ADR-019: the cloud scores attacker prefixes and ships a delta feed, and
 * this renders the result into a named set the kernel matches at full speed.
 *
 * WHAT THIS FILE DOES NOT DO, deliberately: it does not execute anything. It
 * renders to a buffer. Execution, verification and the difference between them
 * belong to the caller, because ADR-017's central finding is that "the config
 * was applied successfully" is worthless as evidence that a packet died. A
 * renderer that also ran its own output would be able to report success on
 * both halves of that sentence.
 *
 * SECURITY BOUNDARY. Every element here originates in a threat feed -- data
 * from outside, under someone else's control. Formatting it into a command
 * string is exactly the shape that turns a feed entry into command injection.
 * So elements are held as PARSED BINARY (address bytes plus prefix length) and
 * rendered numerically; no caller-supplied string is ever concatenated into
 * output. `nft_elem_parse` is the only entry point that accepts text, and it
 * validates strictly before anything reaches a buffer.
 *
 * That is the same property `obs_write_ndjson` has for free -- no
 * attacker-controlled text reaches its output -- except here it has to be
 * built deliberately, because the input genuinely is attacker-influenced.
 *
 * Pure and host-testable: no netlink, no exec, no nftables required to test.
 */

#ifndef AETHER_SENSORD_NFT_H
#define AETHER_SENSORD_NFT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Elements per `add element` command.
 *
 * nft accepts large batches, but an over-long command line is a failure that
 * surfaces as a truncated set rather than an error, so batches are bounded and
 * the caller emits several.
 */
#define NFT_BATCH_MAX 256

/* Longest single rendered element, e.g. "ffff:...:ffff/128 timeout 4294967s". */
#define NFT_ELEM_TEXT_MAX 64

/*
 * Refuse anything broader than this. A /8 of routable space is 16.7M addresses
 * blocked on one signal; if a feed emits something that wide it is far likelier
 * to be a parse error than 16.7M attackers. Mirrors the same bound in the
 * backend's allowlist (aether-nemesis).
 */
#define NFT_MIN_PREFIX_V4 16
#define NFT_MIN_PREFIX_V6 32

struct nft_elem {
	uint8_t addr[16];
	uint8_t family; /* 4 or 6 */
	uint8_t prefix; /* 0..32 for v4, 0..128 for v6 */
	/* Per-element timeout in seconds; 0 uses the set default. Element
	 * timeouts are how reputation decays in the kernel rather than only in
	 * the scorer -- an entry nobody refreshes disappears on its own. */
	uint32_t timeout_sec;
};

enum nft_reject {
	NFT_OK = 0,
	NFT_REJECT_MALFORMED,   /* not parseable as an address/prefix */
	NFT_REJECT_PREFIX,      /* prefix length out of range for the family */
	NFT_REJECT_TOO_BROAD,   /* wider than NFT_MIN_PREFIX_* */
	NFT_REJECT_HOSTBITS,    /* bits set below the prefix length */
	NFT_REJECT_UNSAFE_CHARS /* input contained anything but [0-9a-fA-F:./] */
};

const char *nft_reject_str(enum nft_reject r);

/*
 * Parse one CIDR (or bare address, treated as a host route) into binary.
 *
 * Strict by design: rejects host bits set below the prefix, over-broad
 * prefixes, and any character outside the address alphabet. The last is
 * belt-and-braces -- inet_pton would reject them anyway -- but it means a feed
 * entry containing shell or nft metacharacters is refused by a rule that is
 * obviously about metacharacters, rather than incidentally by a parser.
 */
enum nft_reject nft_elem_parse(const char *text, struct nft_elem *out);

/* Render one element's set-notation text, e.g. "1.10.16.0/20 timeout 604800s".
 * Returns bytes written, or 0 if it would not fit. */
size_t nft_elem_render(const struct nft_elem *e, char *out, size_t out_len);

struct nft_target {
	const char *family; /* "inet" */
	const char *table;  /* "fw4" */
	const char *set_v4; /* e.g. "aether_rep4" */
	const char *set_v6; /* e.g. "aether_rep6" */
};

/*
 * Render the set DECLARATIONS.
 *
 * These belong in an fw4 include file, not in an imperative command: fw4 owns
 * its ruleset and rebuilds it on every reload, so a set created with `nft add
 * set` disappears the next time anything touches the firewall. Writing the
 * declaration to /usr/share/nftables.d/table-pre/inet/fw4/ makes it survive,
 * which is an explicit ADR-020 gate item.
 */
size_t nft_render_set_decl(const struct nft_target *t, uint32_t default_timeout_sec,
                           char *out, size_t out_len);

/*
 * Render `add element` / `delete element` for a batch.
 *
 * Elements of both families may be passed together; they are routed to the
 * matching set. Returns bytes written, 0 on overflow. `n_rendered` receives how
 * many elements made it, so a caller can detect a short write rather than
 * assume the whole batch went.
 */
size_t nft_render_add(const struct nft_target *t, const struct nft_elem *elems,
                      size_t n, char *out, size_t out_len, size_t *n_rendered);
size_t nft_render_del(const struct nft_target *t, const struct nft_elem *elems,
                      size_t n, char *out, size_t out_len, size_t *n_rendered);

/* Render `flush set` for both families -- used on a full resync. */
size_t nft_render_flush(const struct nft_target *t, char *out, size_t out_len);

#endif /* AETHER_SENSORD_NFT_H */
