/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * The aether-sensord daemon on FreeBSD/OPNsense.
 *
 * WHAT THIS IS. The shell around the datapath: it watches a spool directory for
 * reputation messages delivered by the transport, folds each one through the
 * UNMODIFIED feed protocol (src/feed.c), applies it to a pf table, and verifies
 * the result. That is the minimum shape that actually enforces.
 *
 * WHAT IT DELIBERATELY LEAVES OUT of the OpenWrt daemon, and why each omission is
 * not a gap to be filled later:
 *
 *   NFLOG sensing and flow logging   the nftables daemon binds an NFLOG group to
 *                                    observe drops and classify flows. The
 *                                    FreeBSD equivalent is pflog, which is a
 *                                    different capture model, and on OPNsense
 *                                    there is already flow tooling. Building it
 *                                    in before there is a consumer would be
 *                                    code in search of a use. Sensing is also
 *                                    SEPARATELY CONSENTED on OpenWrt (it
 *                                    reports attacker addresses, which are
 *                                    personal data) and merging it in is a
 *                                    consent decision, not a porting one.
 *
 *   app-block / signature matching  needs libndpi and the appdb; classification,
 *                                    not enforcement. Out of the first cut.
 *
 *   the aether-af name-hash half    a Linux kernel module. FreeBSD has no
 *                                    equivalent hook, so there is nothing to
 *                                    port. Address enforcement via pf is
 *                                    unaffected.
 *
 * CONFIG SURFACE. OpenWrt uses UCI at /etc/config/aether-sensord. The equivalent
 * here is a plain KEY=VALUE file, because the values are a handful of scalars and
 * OPNsense's own model is an XML document this daemon has no business editing --
 * the package's model/controller writes this file. Refusing to grow a UCI parser
 * for seven keys is deliberate: a bespoke parser is a liability with no payoff.
 *
 * THE POINT OF THE WHOLE THING, restated because the code is shaped by it:
 * "it applied successfully" is not evidence that anything is enforced. Every
 * successful apply here is followed by reading pf's own view back, and the
 * daemon exits non-zero on a fatal configuration error rather than running while
 * unable to enforce.
 */

#ifndef AETHER_SENSORD_DAEMON_PF_H
#define AETHER_SENSORD_DAEMON_PF_H

#include "apply_pf.h"
#include "canary_pf.h"
#include "feed.h"
#include "policy.h"
#include "sigdb.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Bounds. Deliberately generous for a firewall but finite: a config file is
 * operator input and an unbounded read is a way to make the daemon fail
 * confusingly.
 */
#define DPF_PATH_MAX 512
#define DPF_CONFIG_MAX 16384

/*
 * Effective configuration. Every field has a documented default, because a
 * firewall that enforces nothing because a key was misspelled is exactly the
 * failure this project keeps trying to eliminate.
 */
struct dpf_config {
	/* Where feed messages appear. The transport drops .json files here. */
	char spool_dir[DPF_PATH_MAX];
	/* The pf table the reputation set lives in. Must be registered as an
	 * OPNsense static alias, or nothing will be enforced. */
	char table[PF_TABLE_NAME_MAX];
	/* IPv6 table. Empty disables v6 handling rather than guessing a name. */
	char table_v6[PF_TABLE_NAME_MAX];
	/* Poll interval for the spool, seconds. */
	unsigned interval_sec;
	/* Where canary verdicts are written for the uplink. Empty disables it. */
	char spool_out[DPF_PATH_MAX];
	/* This device's identity for the uplink. May be empty; the transport
	 * owns identity in the OpenWrt design and an empty serial is omitted
	 * from the verdict rather than sent as "". */
	char serial[128];
	/* Run the enforcement canary each interval. */
	bool canary_enabled;
	/* Keep running when a single apply fails. When false, a failed apply is
	 * fatal -- which is the right default on a firewall, because a daemon
	 * that is running but not enforcing is worse than one that is down: the
	 * down one gets noticed. */
	bool tolerant;

	/*
	 * THE LOCAL CAPTURE PATH.
	 *
	 * These are the settings for looking at traffic THIS DEVICE sees, as
	 * opposed to the reputation feed, which is the cloud telling it what to
	 * block. The two are independent: the feed can arrive with local
	 * capture turned off entirely, and vice versa.
	 */

	/* Table that addresses observed locally go into. DELIBERATELY SEPARATE
	 * from `table`, which holds feed reputation.
	 *
	 * The two have different lifetimes and different consequences. A feed
	 * prefix is a considered judgement about a network and can persist for
	 * hours. A local detection is one observation of one destination, and
	 * it should expire quickly. Mixing them in one table means either the
	 * detections never expire or the reputation does -- and neither is
	 * something an operator asked for. Empty disables local blocking. */
	char table_local[PF_TABLE_NAME_MAX];

	/* Interface to capture on. Empty disables local capture. NEVER name the
	 * interface carrying the management session: the capture reattaches it,
	 * and a failure mid-attach takes the session with it. */
	char capture_iface[64];

	/* Enforce, or only report. Defaults to FALSE and the default is the
	 * safe direction: observe mode runs the entire pipeline, including the
	 * pf decision, and simply does not write. Turning this on is the one
	 * choice that can interrupt traffic. */
	bool capture_enforce;

	/* Flows to drain from the capture per pass before moving on. Bounded so
	 * a busy interface cannot make a pass run for ever and starve the feed. */
	unsigned capture_max_flows;

	/* The signature database to match against, when local capture is on. */
	char sigdb_path[DPF_PATH_MAX];

	/* The policy file defining subjects and rules. */
	char policy_path[DPF_PATH_MAX];
};

void dpf_config_defaults(struct dpf_config *cfg);

enum dpf_cfg_result {
	DPF_CFG_OK = 0,
	DPF_CFG_MISSING,   /* file not found -- defaults apply */
	DPF_CFG_UNREADABLE,
	DPF_CFG_TOO_LARGE,
	/* A key was recognised but its value was unusable. Reported rather than
	 * ignored: silently keeping the default for a typo'd key is how a
	 * firewall ends up enforcing into the wrong table. */
	DPF_CFG_BAD_VALUE,
	DPF_CFG_UNKNOWN_KEY
};

const char *dpf_cfg_result_str(enum dpf_cfg_result r);

/*
 * Load config from a path into an already-defaulted struct.
 *
 * Returns DPF_CFG_MISSING when the file does not exist and leaves the defaults
 * in place; that is not an error, because a fresh install legitimately has no
 * config yet. Any other failure means the operator wrote something we could not
 * honour, and the caller must decide whether to refuse to start -- a config that
 * was partially applied is more dangerous than one that was rejected whole.
 *
 * `line_no` receives the offending line for BAD_VALUE and UNKNOWN_KEY.
 */
enum dpf_cfg_result dpf_config_load(struct dpf_config *cfg, const char *path,
                                    unsigned *line_no);

/*
 * Parse config from text. PURE and host-testable; the file wrapper is a thin
 * read around this.
 */
enum dpf_cfg_result dpf_config_parse(struct dpf_config *cfg, const char *text,
                                     size_t len, unsigned *line_no);

/*
 * Does this configuration have any chance of enforcing?
 *
 * False when the table name is unusable or the spool is unset. Checked before
 * the loop starts, because a daemon that cannot enforce must say so at startup
 * rather than run quietly forever.
 */
bool dpf_config_can_enforce(const struct dpf_config *cfg);

/*
 * What to do at startup, given what the canary found.
 *
 * A PURE FUNCTION, and it is pure because this decision is where a real mistake
 * was made: an early version treated "the table does not exist" as survivable
 * ("the first apply will create it"). It will -- `pfctl -t <undeclared> -T add`
 * CREATES the table and returns 0 -- so the daemon would run, apply every message
 * successfully, and block nothing, forever, while logging that it applied. Being
 * a tested function rather than a branch inside main() is what makes that
 * regression visible.
 */
enum dpf_gate {
	/* Proceed. */
	DPF_GATE_PROCEED = 0,
	/* Proceed, but the state could not be confirmed -- say so, never
	 * imply health. */
	DPF_GATE_PROCEED_UNVERIFIED,
	/* Refuse: the table exists but no rule references it, so nothing would
	 * ever be dropped. */
	DPF_GATE_REFUSE_NOT_REFERENCED,
	/* Refuse: the table does not exist. Applying would create it silently. */
	DPF_GATE_REFUSE_TABLE_MISSING
};

enum dpf_gate dpf_startup_gate(enum pf_canary_result verdict,
                               bool canary_enabled);

const char *dpf_gate_str(enum dpf_gate g);

/*
 * One pass over the spool: process every message, return the number applied and
 * verified.
 *
 * Ordering matters and is not alphabetical-with-luck: files are processed in
 * lexicographic order of name after sorting, because the transport names them so
 * that this orders them by serial. A pass that applied a higher serial first
 * would make the lower one STALE and silently drop it.
 *
 * Exposed so a test can drive it without a loop.
 */
struct dpf_pass_stats {
	uint32_t seen;
	uint32_t applied;
	uint32_t stale;
	uint32_t resync;
	uint32_t unusable;
	uint32_t failed;
	uint32_t retained;
};

/*
 * The LOCAL half of a pass, separated so its arithmetic is reportable on its
 * own.
 *
 * Deliberately NOT folded into the feed counters above. A feed pass that
 * applied 40 prefixes and a local pass that blocked 2 destinations are
 * different statements about what the firewall is doing, and an operator
 * reading "applied=42" would have no way to know which half was responsible
 * for a given block.
 */
struct dpf_local_stats {
	uint32_t available;   /* the capture path was usable this pass */
	uint32_t flows;       /* flows drained from the capture */
	uint32_t decided;     /* block verdicts reached */
	uint32_t applied;     /* elements CONFIRMED in the table */
	uint32_t failed;      /* attempted, not confirmed */
	uint32_t truncated;   /* capture had more; drain was bounded */
	uint32_t skipped;     /* capture unavailable (not an error by itself) */
};

/*
 * A captured flow, as the daemon's local pass consumes it. The capture layer
 * produces these; keeping the type here (rather than taking a struct ng_sni)
 * is what lets the daemon pass be exercised on Linux, where netgraph does not
 * exist.
 */
struct dpf_local_flow {
	char host[256];
	uint8_t proto;
	uint16_t dport;
	uint8_t daddr[16];
	uint8_t daddr_family;
	bool have_daddr;
	uint8_t smac[6];
	bool have_smac;
};

int dpf_run_pass(struct dpf_config *cfg, struct pf_apply_ctx *ap,
                 struct feed_client *fc, struct dpf_pass_stats *out);

/*
 * Where local flows come from. A function pointer, so a test can supply flows
 * directly and the production path can ask the netgraph capture.
 *
 * Returns the number written (0 when there are none), or -1 for a capture error
 * the caller should count rather than treat as "no traffic" -- an interface that
 * has stopped passing traffic and an interface with nothing to say are very
 * different, and a single 0 for both is how a dead capture looks healthy.
 */
typedef int (*dpf_flow_source_fn)(void *user, struct dpf_local_flow *out,
                                  size_t cap);

/*
 * Run the local half of a pass: drain the capture, decide, apply.
 *
 * `src` NULL means local capture is not configured: the function returns
 * immediately with skipped set, and touches no pf state.
 *
 * Returns the number of elements CONFIRMED, or -1 on a bad argument. A false
 * return of 0 here is ambiguous between "nothing to block" and "nothing was
 * attempted", which is why the caller must read the stats rather than the
 * return value to find out. That ambiguity is inherent (they really are both
 * zero blocks) but it must not be papered over with a different number.
 */
int dpf_run_local(struct dpf_config *cfg, struct pf_apply_ctx *ap,
                  const struct sig_db *db, const struct pol_db *pol,
                  dpf_flow_source_fn src, void *src_user,
                  struct dpf_local_stats *out);

/*
 * Flows drained from the capture per pass. Bounded: a busy interface would
 * otherwise let the local half of a pass run indefinitely and starve the feed,
 * so the bound is a fairness property, not a memory one. Hitting it sets
 * `truncated` in the stats -- the traffic is not dropped, it waits for the next
 * pass.
 */
#define DPF_LOCAL_MAX_FLOWS 256

#endif /* AETHER_SENSORD_DAEMON_PF_H */
