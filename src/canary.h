/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Proving that enforcement actually enforces.
 *
 * WHY THIS EXISTS. On 2026-08-22 this daemon ran on a BPI-R4 reporting
 * "set declaration installed" and "Reputation enforcement is live" while
 * `nft list sets` showed no aether sets at all. The include had been written
 * to a directory fw4 does not read, and later to one it reads but in a format
 * it rejects. Nothing errored. Every counter agreed. 624 host tests passed --
 * they asserted the rendered nftables text was well-formed, never that fw4
 * accepted it or that a set appeared.
 *
 * Configuration state is not enforcement. This measures enforcement.
 *
 * WHAT IT DOES. Puts a canary address into the live set, checks the kernel
 * really holds it, sends one packet at it, and requires that packet to be
 * refused. Then removes it and checks it is gone. Every step can fail
 * separately and each failure means something different:
 *
 *   SET_MISSING      the set does not exist -- the include never landed
 *   ADD_REJECTED     nft refused the element
 *   NOT_HELD         nft accepted it and the kernel does not have it
 *   NOT_ENFORCED     the kernel holds it and the packet went out anyway,
 *                    i.e. the set exists but no rule references it
 *   ENFORCED         a packet was actually stopped
 *   CLEANUP_FAILED   enforcement works but the canary is still in the set
 *
 * NOT_ENFORCED is the state this whole file exists to catch. It is
 * indistinguishable from success by every other signal we have.
 *
 * THE ADDRESS IS DOCUMENTATION SPACE. 192.0.2.0/24 is TEST-NET-1 and
 * 2001:db8::/32 is the v6 documentation prefix. Neither can carry real
 * traffic, so a canary left behind by a crash blocks nothing a subscriber
 * would miss -- and obs_addr_is_private() already refuses both, so the
 * reputation feed can never legitimately contain one.
 */

#ifndef AETHER_SENSORD_CANARY_H
#define AETHER_SENSORD_CANARY_H

#include "apply.h"
#include "nft.h"

#include <stdbool.h>
#include <stdint.h>

enum canary_result {
	CANARY_ENFORCED = 0,   /* proven: a packet was stopped */
	CANARY_SET_MISSING,
	CANARY_ADD_REJECTED,
	CANARY_NOT_HELD,
	CANARY_NOT_ENFORCED,   /* the dangerous one */
	CANARY_CLEANUP_FAILED,
	CANARY_INCONCLUSIVE    /* could not run the test at all */
};

const char *canary_result_str(enum canary_result r);

/*
 * The same verdict as a stable wire token.
 *
 * Deliberately NOT canary_result_str(): that returns prose for a human reading
 * syslog ("enforced (a packet was stopped)"), and the controller parses this
 * one. Reusing the prose would send an unparseable string to a cloud that
 * treats unknown verdicts as unusable -- and the whole fleet would read as
 * "never reported" while every device was reporting correctly.
 *
 * These tokens match enum Verdict in aether-aegis::proof. Changing one without
 * the other is the failure mode; there is no shared header to enforce it, so
 * the pairing is written down in both places.
 */
const char *canary_result_token(enum canary_result r);

/*
 * Write the verdict where the uplink will find it.
 *
 * Same mechanism the sense batches use: an NDJSON line into a spool directory,
 * written to a .partial and renamed, so a consumer never reads half a record.
 *
 * Emitted on EVERY run, not only when the verdict changes. The controller
 * treats an absent verdict as an alarm -- correctly, because a device that
 * stopped checking looks exactly like a healthy one -- so the steady stream of
 * passes is not noise, it is the heartbeat that makes silence meaningful.
 *
 * `serial` may be NULL or empty: this daemon has no cloud identity of its own
 * and the uplink supplies one. The key is omitted rather than sent empty, so an
 * unidentified device cannot collect its verdicts into a row keyed on "".
 *
 * Returns 0 on success, -1 on failure. A failure to report is logged and does
 * not affect enforcement: the check has already happened.
 */
int canary_report(const char *spool_dir, const char *serial,
                  enum canary_result r, const char *target, bool v6);

/*
 * How many verdict files to keep.
 *
 * The uplink only ever forwards the newest, so older ones are dead weight --
 * but keeping a few means a reader scanning the directory when a new verdict
 * lands still finds a complete record rather than an empty spool.
 */
#define CANARY_KEEP 8u

/* True only for CANARY_ENFORCED. Everything else, including INCONCLUSIVE,
 * is not a pass -- "I could not check" must never read as "it works". */
bool canary_passed(enum canary_result r);

/*
 * The canary address, as text. IPv4 unless `v6`.
 *
 * Exposed so a caller can log which address it used, and so a test can assert
 * it is documentation space rather than something that could carry traffic.
 */
const char *canary_addr(bool v6);

/*
 * Probe whether a packet to `addr` is refused by the local firewall.
 *
 * Returns 1 if refused (EPERM/EACCES from the socket layer), 0 if it was
 * allowed out, and -1 if the probe could not be performed. Split out so the
 * "was it actually blocked" decision is testable without nftables or root.
 *
 * A UDP sendto is used deliberately: it is connectionless, so nothing is
 * retried, nothing is left half-open, and the answer arrives immediately.
 */
int canary_probe_blocked(const char *addr, bool v6);

/*
 * Run the whole check against a live set.
 *
 * Adds, verifies, probes, removes, verifies removal. Always attempts cleanup,
 * including on the failure paths -- a canary left in a production set is a
 * small leak but it is still a leak, and CLEANUP_FAILED says so rather than
 * hiding it behind an otherwise-passing result.
 */
enum canary_result canary_run(struct apply_ctx *c, const struct nft_target *t,
                              bool v6);

#endif /* AETHER_SENSORD_CANARY_H */
