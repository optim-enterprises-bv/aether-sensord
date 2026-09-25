/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Applying reputation policy to pf, and CONFIRMING it took effect.
 *
 * Same premise as apply.h, and the same reason it exists: `pfctl -T add`
 * returning 0 means pfctl parsed an argument list. It does not mean the table
 * holds the element, and it does not mean a rule references the table, and
 * therefore it does not mean a packet will die.
 *
 * WHAT IS DIFFERENT FROM THE NFTABLES VERSION, and why:
 *
 * 1. THE TABLE MUST BE DECLARED OUT OF BAND. nft applies a `set { ... }`
 *    declaration and the elements together, and auto-creates what it needs. pf
 *    will not: `pfctl -t <t> -T add` on an undeclared table fails with "Table
 *    does not exist", and a table declared imperatively is destroyed the next
 *    time OPNsense reloads its ruleset. So the caller declares the table via
 *    OPNsense's static-alias registry (see pf.h), and this layer treats
 *    "table does not exist" as APPLY_UNAVAILABLE rather than retrying -- the
 *    fix is a registration, not a rerun.
 *
 * 2. VERIFICATION IS BY MEMBERSHIP, NOT BY COUNT. nft's `auto-merge` collapses
 *    overlapping prefixes, so apply.h compares a floor count and explains why an
 *    exact comparison would fail on correct behaviour. pf has no auto-merge and
 *    keeps a table entry list, so the honest check is stronger: the specific
 *    elements we sent must be present in `pfctl -t <t> -T show`. A count can be
 *    right while the wrong addresses are in the table -- a feed element that
 *    failed to parse still leaves the count unchanged if a stale entry fills the
 *    slot, and a count cannot tell those apart.
 *
 * 3. TABLE NAME IS A HOSTILE-ADJACENT ARGUMENT. It reaches argv directly. It is
 *    validated to [A-Za-z0-9_] here rather than trusted, because unlike an
 *    element (which pf_elem_parse reduces to parsed binary) a table name is a
 *    raw string a caller could have taken from configuration.
 *
 * The exec seam is injectable exactly as in apply.h, so command construction,
 * error handling and verification are all testable on the host without pf, root,
 * or a firewall.
 */

#ifndef AETHER_SENSORD_APPLY_PF_H
#define AETHER_SENSORD_APPLY_PF_H

#include "pf.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Default location of pfctl. OPNsense inherits FreeBSD's. */
#define PF_APPLY_DEFAULT_PATH "/sbin/pfctl"

/*
 * Longest table name accepted. Also bounded by the [A-Za-z0-9_] rule below.
 */
#define PF_TABLE_NAME_MAX 64

/*
 * Run a command, capturing stdout into `out`.
 *
 * Returns the process exit status, or -1 if it could not be run at all. The
 * distinction matters: non-zero is pfctl refusing our input, -1 is pfctl being
 * absent, and those need different operator responses.
 */
typedef int (*pf_apply_exec_fn)(const char *argv0, const char *const *argv,
                                char *out, size_t out_len, void *ctx);

/*
 * True if `name` is usable as a pf table name.
 *
 * PURE. Rejects anything outside [A-Za-z0-9_], anything empty or over-long, and
 * anything with a leading '-'. That last one is the reason this exists: an argv
 * entry beginning with '-' is read by pfctl as an option, so an unvalidated
 * table name is a way to change what pfctl does rather than what it targets.
 */
bool pf_table_name_ok(const char *name);

struct pf_apply_ctx {
	pf_apply_exec_fn exec;
	void *user;
	const char *pfctl_path;
	/* Cumulative, for the health surface. */
	uint64_t applied_batches;
	uint64_t failed_batches;
	uint64_t verify_mismatches;
	/* Elements refused because the table did not exist. Not a failure of the
	 * feed, and not retried -- it means the alias was never registered. */
	uint64_t missing_table;
	/* Times the elements landed but no rule referenced the table. This is
	 * the silent-failure counter; it is separate from verify_mismatches
	 * because the operator action is different (register the alias). */
	uint64_t unreferenced_tables;
};

void pf_apply_ctx_init(struct pf_apply_ctx *c, pf_apply_exec_fn exec, void *user);

enum pf_apply_result {
	PF_APPLY_OK = 0,
	PF_APPLY_REJECTED,     /* pfctl ran and refused our input */
	PF_APPLY_UNAVAILABLE,  /* pfctl could not be run, or the table is absent */
	PF_APPLY_BAD_TABLE     /* the table name is not usable */
};

const char *pf_apply_result_str(enum pf_apply_result r);

/*
 * Add `n` elements to `table`, one argv entry per element, in ONE pfctl
 * invocation so the batch is a single operation.
 *
 * Returns the table's exit status semantics. `err` receives pfctl's output on
 * failure, which is where "Table does not exist" is distinguished from a
 * malformed address.
 *
 * Elements are passed as separate argv entries -- NEVER assembled into a command
 * line. Each element's text came out of inet_ntop over parsed binary, but the
 * argv boundary is the actual protection and this signature makes it structural
 * rather than a convention a caller could violate.
 */
enum pf_apply_result pf_apply_add(struct pf_apply_ctx *c, const char *table,
                                  const struct pf_elem *elems, size_t n,
                                  char *err, size_t err_len);

enum pf_apply_result pf_apply_del(struct pf_apply_ctx *c, const char *table,
                                  const struct pf_elem *elems, size_t n,
                                  char *err, size_t err_len);

/*
 * Remove every element from `table`, leaving the table itself declared.
 *
 * Needed for a LIST (full snapshot): after a resync the table's contents must
 * match the snapshot exactly, so entries the controller has dropped must go. A
 * delta protocol never needs this; a resync does.
 *
 * Measured on FreeBSD 16.0: `pfctl -t <t> -T flush` prints "N addresses deleted."
 * and empties the table. Note the obvious-looking alternative does NOT work --
 * `pfctl -F tables` fails with "Unknown flush modifier 'tables'", so a script
 * that "cleans up" with it silently does nothing.
 */
enum pf_apply_result pf_apply_flush(struct pf_apply_ctx *c, const char *table,
                                    char *err, size_t err_len);

/*
 * Read the table's contents. Returns the byte count written, or -1 if the table
 * could not be read -- which includes it not existing, the case that matters
 * most. An absent table yields an empty string to a careless reader and -1 here.
 *
 * Note `-T show` prints one address per line, and prefixes are printed as
 * `a.b.c.d/len` or as a range depending on pf's mood for interval tables, so
 * callers should test membership with pf_table_lists_addr rather than by
 * string equality of a whole line.
 */
long pf_apply_show(struct pf_apply_ctx *c, const char *table, char *out,
                   size_t out_len);

/*
 * Does `listing` (from pf_apply_show) contain `elem`?
 *
 * PURE, and the reason the count-based check from the nftables version is not
 * reused. Exact for host addresses. For a prefix it accepts either the CIDR form
 * or the `start - end` interval form pf uses for interval tables, because a
 * caller must not have to know which form pf chose today.
 */
bool pf_table_lists_elem(const char *listing, const struct pf_elem *elem);

/*
 * Read the MAIN ruleset for the purpose of finding a table reference.
 *
 * Returns bytes written, or -1 if it could not be read. A read failure must never
 * be treated as "no reference": that would report a working firewall as
 * unenforced, and the fix an operator would reach for is the wrong one.
 */
long pf_apply_ruleset(struct pf_apply_ctx *c, char *out, size_t out_len);

/*
 * Does the MAIN ruleset text reference `<table>`?
 *
 * PURE. THE ENFORCEMENT EVIDENCE, and the reason apply_and_verify is not
 * satisfied by elements landing in the table.
 *
 * WHY THE POPULATED TABLE IS NOT ENOUGH. `pfctl -t <undeclared> -T add` does not
 * fail -- it CREATES the table and returns success (measured on FreeBSD 16.0:
 * "1 table created."). So a batch can report APPLY_OK, every element can be
 * present in the table, and verification can pass, while NO RULE REFERENCES IT
 * and not one packet will ever be dropped. The newly created table is also
 * destroyed the next time OPNsense reloads its ruleset from config.xml, so the
 * state is both useless and temporary.
 *
 * That is the same silent-degradation shape as the nftables failure this daemon
 * exists to catch, one level up: there, the set existed with no rule referencing
 * it; here, the table is created by the very write that is supposed to populate
 * something an operator already declared.
 *
 * WHY NOT the per-table `Rules:` count from `pfctl -vvsT`: it counts rules that
 * mention the table ANYWHERE, including inside an anchor the main ruleset never
 * calls. Measured state where that count lies:
 *
 *     References:  [ Anchors: 1   Rules: 1  ]              <- looks enforced
 *     pfctl -s rules | grep -c '<aisense_rep4>'  ->  0      <- nothing live
 *
 * Reporting enforcement there is fabricated protection -- worse than reporting
 * nothing, because it is the answer an operator stops double-checking. So the
 * reference must be visible in the MAIN ruleset, which is also exactly the shape
 * the OPNsense static-alias design produces (and OPNsense emits zero anchors,
 * measured on 26.7.2_2).
 *
 * Deliberate cost: a hand-written config that enforces from a *called* anchor
 * reads as unreferenced. That trade is correct -- a missed enforcement prompts a
 * look, an invented one does not.
 */
bool pf_apply_ruleset_references(const char *main_rules, const char *table);

/*
 * Apply a batch and confirm it. Returns true only when pfctl accepted the input,
 * every element sent is present in the table, AND a rule in the main ruleset
 * references that table.
 *
 * `expect_min` is kept for signature parity with apply_and_verify and is used as
 * a cheap guard: if the table is empty afterwards, verification fails without
 * reading it out. Membership and the rule reference are the real checks.
 *
 * The three failures are distinct because they need different operator actions:
 * a missing element means the feed or the write failed; an unreferenced table
 * means the static alias was never registered, so retrying is pointless.
 */
bool pf_apply_and_verify(struct pf_apply_ctx *c, const char *table,
                         const struct pf_elem *elems, size_t n, char *err,
                         size_t err_len);

/* The real exec, used in production. Not used by tests. */
int pf_apply_exec_posix(const char *argv0, const char *const *argv, char *out,
                        size_t out_len, void *ctx);

#endif /* AETHER_SENSORD_APPLY_PF_H */
