/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Proving that pf enforcement actually enforces (FreeBSD/OPNsense port of
 * canary.c).
 *
 * WHY THIS EXISTS, unchanged from the nftables original: on 2026-08-22 this
 * daemon reported "set declaration installed" and "Reputation enforcement is
 * live" while `nft list sets` showed no aether sets at all. Nothing errored.
 * Every counter agreed. Configuration state is not enforcement; this measures
 * enforcement.
 *
 * WHY PF MAKES THIS WORSE, NOT BETTER. On nftables the silent failure was an
 * include that never landed. On pf it has a second form: OPNsense regenerates
 * its whole ruleset from config.xml on every filter reload, so a table declared
 * imperatively exists, `pfctl -t <t> -T show` lists its contents, and NO RULE
 * REFERENCES IT -- so nothing is ever dropped. Measured on OPNsense 26.7.2_2:
 * the generated ruleset contains zero `anchor` lines, so an anchor-based plugin
 * is dormant by construction. That state is indistinguishable from success by
 * every signal except a probe.
 *
 * STRUCTURE DIFFERS FROM THE ORIGINAL, deliberately. canary.c interleaves the
 * observation and the verdict in one function, which is why its own comments
 * record that 624 host tests passed while asserting only that rendered text was
 * well-formed. Here the verdict is a PURE FUNCTION of the observations
 * (`pf_canary_classify`), so the failure taxonomy itself is testable without
 * root, pf, or a firewall -- and the impure half only gathers booleans.
 *
 * The wire tokens are IDENTICAL to canary.c's, because they must stay in step
 * with `enum Verdict` in aether-aegis::proof. There is no shared header to
 * enforce that, so `pf_canary_token` is asserted against the documented set in
 * the test.
 */

#ifndef AETHER_SENSORD_CANARY_PF_H
#define AETHER_SENSORD_CANARY_PF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * TEST-NET-1 and the v6 documentation prefix. Neither can carry real traffic,
 * and obs_addr_is_private() already refuses both, so the reputation feed can
 * never legitimately contain one. A canary left behind by a crash therefore
 * blocks nothing a subscriber would miss.
 */
#define PF_CANARY_V4 "192.0.2.199"
#define PF_CANARY_V6 "2001:db8::c0de"

/*
 * How many verdict files to keep. Same reasoning as the original: the uplink
 * only forwards the newest, so older files are dead weight, but keeping a few
 * means a reader scanning during a write still finds a complete record.
 */
#define PF_CANARY_KEEP 8u

enum pf_canary_result {
	PF_CANARY_ENFORCED = 0, /* proven: a packet was stopped */
	PF_CANARY_TABLE_MISSING,   /* the table does not exist -- the declaration never landed */
	PF_CANARY_ADD_REJECTED,    /* pfctl refused the element */
	PF_CANARY_NOT_HELD,        /* pfctl accepted it and the table does not list it */
	PF_CANARY_NOT_ENFORCED,    /* the dangerous one: held, but the packet went out */
	PF_CANARY_CLEANUP_FAILED,  /* enforced, but the canary was left behind */
	PF_CANARY_INCONCLUSIVE     /* could not run the test at all */
};

/*
 * How many datagrams the probe sends.
 *
 * They are not evidence of a drop (pf discards silently); they exist to make
 * the table's counters move so a rule reference becomes measurable.
 */
#define PF_CANARY_PROBES 10

/*
 * The raw observations a canary run produces. Every field is a plain boolean so
 * the verdict can be derived without repeating the I/O.
 *
 * NOTE what is NOT here: the result of the probe's sendto(). On Linux netfilter
 * a dropped output packet returns EPERM to the socket, so the original daemon
 * could use that as proof. pf does not report a drop to the sender at all --
 * measured on FreeBSD 16.0, 10 datagrams sent at a canary held in a referenced,
 * enforcing table: `sends=10 refused=0`. A canary that treated "sent silently"
 * as "not blocked" would report NOT_ENFORCED for a perfectly enforcing
 * firewall, and an operator who learns to ignore that verdict has lost the one
 * signal this mechanism exists to give. So the verdict rests on `pfctl -vvsT`
 * instead.
 */
struct pf_canary_obs {
	bool table_exists;    /* `pfctl -t <t> -T show` succeeded */
	bool add_accepted;    /* `pfctl -t <t> -T add <canary>` returned 0 */
	bool held_in_table;   /* the address appears in `-T show` afterwards */
	bool probe_ran;       /* datagrams were sent and pf's counters were then readable */
	bool referenced_by_rule; /* -vvsT reports a non-zero Rules: count for the table */
	bool cleanup_ok;      /* the address is gone after `-T delete` */
};

const char *pf_canary_str(enum pf_canary_result r);
const char *pf_canary_token(enum pf_canary_result r);

/*
 * Derive the verdict from the observations. PURE -- no I/O, no root, no pf.
 *
 * Order matters and is asserted by the tests: the first thing that is wrong is
 * what gets reported, because a later symptom of an earlier fault is not the
 * fault. A missing table, for instance, also means the add will fail; reporting
 * ADD_REJECTED there would send an operator to the wrong place.
 */
enum pf_canary_result pf_canary_classify(const struct pf_canary_obs *o);

/* True only for PF_CANARY_ENFORCED. Everything else, including INCONCLUSIVE,
 * is not a pass -- "I could not check" must never read as "it works". */
bool pf_canary_passed(enum pf_canary_result r);

const char *pf_canary_addr(bool v6);

/*
 * Probe whether the firewall is actually in the path for the canary, by sending
 * datagrams at it and then reading pf's own per-table counters.
 *
 * Returns the number of datagrams the kernel accepted, or -1 if the address
 * could not be used.
 *
 * THE RETURN VALUE IS NOT A VERDICT. pf discards a blocked packet silently, so
 * this reports success whether or not enforcement exists -- unlike Linux
 * netfilter, which returns EPERM to the socket. Measured on FreeBSD 16.0:
 * `sends=10 refused=0` against a canary held in a table with a live blocking
 * rule. Treating that as "not blocked" would libel a working firewall.
 */
int pf_canary_probe_blocked(const char *addr, bool v6);

/*
 * True if the MAIN ruleset text references `<table>`.
 *
 * PURE. This, not the reference count, is the enforcement evidence.
 *
 * WHY THE OBVIOUS CHECK IS WRONG. `pfctl -vvsT` reports per-table
 * `References: [ Anchors: N  Rules: M ]`, and a non-zero M looks like proof.
 * It is not: M counts rules that mention the table ANYWHERE, including inside an
 * anchor that the main ruleset never calls. Measured on FreeBSD 16.0, with a
 * stale anchor holding one rule:
 *
 *     References:  [ Anchors: 1   Rules: 2  ]
 *     pfctl -s rules | grep -c aisense_rep4   ->  0
 *
 * Nothing in the live path referenced the table and not one packet could have
 * died, yet the count said 2. Reporting ENFORCED there is a FALSE POSITIVE --
 * claiming protection that does not exist -- which is worse than reporting
 * nothing, because it is the answer an operator stops double-checking.
 *
 * So enforcement requires the reference to be visible in the main ruleset, which
 * is also exactly the shape AIsense relies on: a table registered as an OPNsense
 * static alias gets its rule generated into the main ruleset, and OPNsense emits
 * zero anchors (measured on 26.7.2_2).
 *
 * This errs toward a false NEGATIVE for a hand-written configuration that
 * legitimately enforces from a called anchor. That trade is deliberate: a
 * missed enforcement is a prompt to look, an invented one is not.
 */
bool pf_canary_ruleset_references(const char *main_rules, const char *table);

/*
 * Run the whole check against a live pf table. Impure half.
 *
 * Always attempts cleanup on every path, including failures: a canary left in a
 * production table is a small leak but still a leak, and CLEANUP_FAILED says so
 * rather than hiding it behind an otherwise-passing result.
 *
 * Returns PF_CANARY_INCONCLUSIVE if `table` is NULL.
 */
enum pf_canary_result pf_canary_run(const char *table, bool v6);

/*
 * Write the verdict where the uplink will find it, as NDJSON into a spool
 * directory, written to a .partial and renamed so a consumer never reads half a
 * record.
 *
 * Emitted on EVERY run, not only when the verdict changes: the controller
 * treats an absent verdict as an alarm, so the steady stream of passes is not
 * noise, it is the heartbeat that makes silence meaningful.
 *
 * The prose meaning is deliberately NOT sent -- the controller has its own
 * wording and shipping ours would leave two descriptions of one state drifting
 * apart. `serial` may be NULL or empty; the key is omitted rather than sent
 * empty so an unidentified device cannot key a row on "".
 */
int pf_canary_report(const char *spool_dir, const char *serial,
                     enum pf_canary_result r, const char *table, bool v6);

#endif /* AETHER_SENSORD_CANARY_PF_H */
