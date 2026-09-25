/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * FreeBSD/OPNsense (pf) enforcement rendering for aether-sensord.
 *
 * Port of `nft.c` to the pf primitives. The *shape* of the original is kept
 * deliberately: `nft.c`'s central insight is that a renderer must not execute
 * anything, because ADR-017's finding is that "the config applied successfully"
 * is worthless as evidence a packet died. That holds here unchanged.
 *
 * WHAT DIFFERS FROM THE NFTABLES VERSION, and why each difference is not
 * cosmetic:
 *
 * 1. THE PRIMITIVE IS A TABLE, NOT A SET. pf has `table <name> { ... }`
 *    populated with `pfctl -t <name> -T add <addr>`. There is no `timeout`
 *    keyword on an element and no `auto-merge`.
 *
 * 2. DECAY IS DECLARED IN THE TABLE, NOT THE ELEMENT. nft sets carry
 *    per-element timeouts so a stale feed entry ages out on its own. pf
 *    expresses the same thing per-table: an `expire` setting, which OPNsense
 *    also exposes on its static aliases (`"expire": "3600"` on `sshlockout`
 *    and `virusprot`). So a per-element timeout cannot be honoured here and
 *    is reported rather than silently dropped -- see `pf_reject_str` and
 *    PF_REJECT_TIMEOUT_UNSUPPORTED.
 *
 * 3. THIS IS NOT THE OPNsense SEAM. OPNsense regenerates its ruleset from
 *    config.xml on every filter reload, so a table this daemon declares
 *    imperatively would vanish. The survivable seam is registering the table
 *    in `static_aliases/core.json` as `type: external` and letting OPNsense
 *    generate the rules that reference it. This module renders the table
 *    CONTENT and the pfctl invocation text; declaring it is the caller's job.
 *
 * 4. argv, NOT A SHELL STRING. Elements are handed to `pfctl` as separate
 *    argv entries (see `pf_render_add_argv_text`), never assembled into a
 *    command line. The feed is attacker-influenced, so this is the injection
 *    boundary; keeping elements as parsed binary and rendering numerically is
 *    the same discipline as the original, tightened for the mechanism.
 *
 * Pure and host-testable: no libpf, no exec, no root, no firewall required.
 */

#ifndef AETHER_SENSORD_PF_H
#define AETHER_SENSORD_PF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Elements per invocation.
 *
 * pfctl accepts long argv lists, but ARG_MAX is a hard wall and an over-long
 * invocation fails as a truncated table rather than an error -- the same
 * failure mode the nftables batching guard exists for. Bounded for the same
 * reason.
 */
#define PF_BATCH_MAX 256

/* Longest single element, e.g. "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128". */
#define PF_ELEM_TEXT_MAX 48

/*
 * Refuse anything broader than this, matching the nftables renderer and the
 * backend's allowlist. A /8 of routable space is 16.7M addresses blocked on one
 * signal; a feed emitting that is far likelier to be a parse error than 16.7M
 * attackers.
 */
#define PF_MIN_PREFIX_V4 16
#define PF_MIN_PREFIX_V6 32

/* OPNsense's own static aliases use this table name in the generated ruleset. */
#define PF_TABLE_NAME_DEFAULT "aisense_rep4"

struct pf_elem {
	uint8_t addr[16];
	uint8_t family; /* 4 or 6 */
	uint8_t prefix; /* 0..32 for v4, 0..128 for v6 */
	/*
	 * Per-element timeout, carried for API compatibility with the nftables
	 * renderer and with the feed it is produced from. pf cannot honour it:
	 * expiry is a table property. A non-zero value is reported through
	 * `pf_elem_render`'s status, never silently discarded, so a caller
	 * expecting per-element decay learns it is not in force rather than
	 * believing stale entries will disappear.
	 */
	uint32_t timeout_sec;
	/* Set when the carried timeout could not be expressed in pf. */
	bool timeout_unrepresentable;
};

enum pf_reject {
	PF_OK = 0,
	PF_REJECT_MALFORMED,        /* not parseable as an address/prefix */
	PF_REJECT_PREFIX,           /* prefix length out of range for the family */
	PF_REJECT_TOO_BROAD,        /* wider than PF_MIN_PREFIX_* */
	PF_REJECT_HOSTBITS,         /* bits set below the prefix length */
	PF_REJECT_UNSAFE_CHARS,     /* input contained anything but [0-9a-fA-F:./] */
	PF_REJECT_TIMEOUT_UNSUPPORTED /* parsed fine; per-element expiry is not a pf feature */
};

const char *pf_reject_str(enum pf_reject r);

/*
 * Parse one CIDR (or bare address, treated as a host route) into binary.
 *
 * Same strictness as `nft_elem_parse`: host bits below the prefix, over-broad
 * prefixes, and any character outside the address alphabet are refused. The
 * alphabet check is belt-and-braces -- inet_pton would reject metacharacters
 * anyway -- but it means a feed entry carrying shell or pfctl metacharacters is
 * refused by a rule that is visibly about metacharacters, rather than
 * incidentally by a parser three calls later.
 *
 * `timeout_sec` is carried through unchanged for the caller's bookkeeping;
 * see PF_REJECT_TIMEOUT_UNSUPPORTED for what pf can and cannot do with it.
 */
enum pf_reject pf_elem_parse(const char *text, uint32_t timeout_sec,
                             struct pf_elem *out);

/*
 * Render one element's pfctl argument text, e.g. "192.0.2.0/24".
 *
 * Returns bytes written, or 0 if it would not fit. The rendered text is safe to
 * place in its own argv slot: every byte of it came from parsed binary through
 * inet_ntop, so nothing in the output originated as caller text.
 */
size_t pf_elem_render(const struct pf_elem *e, char *out, size_t out_len);

struct pf_target {
	const char *table_v4; /* e.g. "aisense_rep4" */
	const char *table_v6; /* e.g. "aisense_rep6" */
};

/*
 * Render the `pfctl -t <table> -T add <elem> ...` invocations for a batch, one
 * line per family, with elements space-separated.
 *
 * THIS OUTPUT IS FOR DISPLAY AND LOGGING, NOT FOR `system()`. Execution must
 * pass the elements as separate argv entries. A caller that feeds this string
 * to a shell reintroduces exactly the injection the parse step exists to
 * prevent. The companion `pf_render_argc` reports how many arguments the batch
 * needs so a caller can build argv correctly.
 */
size_t pf_render_add(const struct pf_target *t, const struct pf_elem *elems,
                     size_t n, char *out, size_t out_len, size_t *n_rendered);

size_t pf_render_del(const struct pf_target *t, const struct pf_elem *elems,
                     size_t n, char *out, size_t out_len, size_t *n_rendered);

/*
 * Render the table DECLARATION as pf.conf syntax.
 *
 * Unlike the nftables version this is not installed by an include: OPNsense
 * owns pf.conf and rewrites it. The declaration is rendered so a caller can
 * show an operator what to add to `static_aliases/core.json`, and so a test can
 * assert the intent. `expire_sec` of 0 means entries persist until explicitly
 * removed.
 */
size_t pf_render_table_decl(const struct pf_target *t, uint32_t expire_sec,
                            char *out, size_t out_len);

/*
 * How many argv entries `pfctl -t <table> -T <verb>` plus `n` elements needs.
 *
 * Lets a caller size an argv array exactly. Returns 0 for a NULL target.
 */
size_t pf_render_argc(const struct pf_target *t, size_t n);

/* The fixed argv prefix, e.g. { "pfctl", "-t", "aisense_rep4", "-T", "add" }. */
size_t pf_render_argv_prefix(const struct pf_target *t, bool is_v6, bool add,
                             const char **argv, size_t argv_len);

#endif /* AETHER_SENSORD_PF_H */
