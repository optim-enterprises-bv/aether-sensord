/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * aether-sensord-pf: the daemon entry point.
 *
 * Usage: aether-sensord-pf [-c /path/config] [-n] [-t]
 *
 *   -c PATH   configuration file (default /usr/local/etc/aether-sensord.conf)
 *   -n        one pass over the spool, then exit (for cron and for tests)
 *   -t        check the configuration and the enforcement state, then exit
 *
 * IT DOES NOT DAEMONISE ITSELF, and that is deliberate. The rc.d script
 * supervises it with daemon(8), which owns the pidfile; a program that also
 * calls daemon() forks a SECOND time, so daemon(8)'s child exits immediately,
 * the pidfile is removed, and `service aether_sensord stop` can never find the
 * process. That failure was found here by testing, not by reasoning.
 *
 * Exit status contract, matching the canary's so a monitor can treat both the
 * same way:
 *
 *   0  ran and, if asked to enforce, verified enforcement
 *   1  configuration refused, or an apply failed under tolerant=false
 *   2  usage error
 *
 * A daemon that cannot enforce exits non-zero rather than running quietly. The
 * whole project rests on "it is running" not being evidence of anything.
 */

#include "capture_source.h"
#include "daemon_pf.h"

#include "canary_pf.h"
#include "local_decide.h"
#include "polcfg.h"
#include "policy.h"
#include "sigdb.h"
#include "feed.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_CONFIG "/usr/local/etc/aether-sensord.conf"

/*
 * getopt/optarg/daemon are POSIX, not C11, so a strict `-std=c11` build does not
 * declare them -- which is a hard error under -Werror, not a warning. Declared
 * explicitly rather than reached via a feature-test macro, matching how the rest
 * of this port handles the same gap (dup_str, mkdtemp): the declarations belong
 * where they are used, and a _DEFAULT_SOURCE define is glibc-specific and would
 * be wrong on the target.
 */
int getopt(int argc, char *const argv[], const char *optstring);
extern char *optarg;
extern int optind;

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
}

static void usage(const char *a0)
{
	fprintf(stderr,
	        "usage: %s [-c config] [-n] [-t]\n"
	        "  -c PATH  configuration file (default %s)\n"
	        "  -n       one pass over the spool, then exit\n"
	        "  -t       check config and enforcement state, then exit\n",
	        a0, DEFAULT_CONFIG);
}

/*
 * Verify the table the daemon will enforce into is actually referenced.
 *
 * WHY THIS IS NOT PARANOIA. `pfctl -t <undeclared> -T add` CREATES the table and
 * returns success (measured on FreeBSD 16.0). So the daemon can start, apply
 * every message "successfully", and drop nothing at all -- and it will do it
 * while logging that it applied. Checking the ruleset ONCE at startup turns that
 * into a refusal with an actionable message instead of a silent non-enforcement.
 *
 * Per-apply, apply_pf_and_verify already checks this; this is the startup gate so
 * the operator learns immediately rather than after the first feed message.
 */
static bool startup_enforcement_check(const struct dpf_config *cfg)
{
	enum pf_canary_result v;
	enum dpf_gate g;

	if (!cfg->canary_enabled)
		return true;

	/*
	 * The canary is the stronger check: it writes a documentation-space
	 * address, then requires the MAIN ruleset to reference the table.
	 */
	v = pf_canary_run(cfg->table, false);
	g = dpf_startup_gate(v, cfg->canary_enabled);

	switch (g) {
	case DPF_GATE_PROCEED:
		syslog(LOG_INFO, "startup: table %s is referenced -- enforcing",
		       cfg->table);
		return true;
	case DPF_GATE_REFUSE_NOT_REFERENCED:
		syslog(LOG_ERR,
		       "startup: table %s holds entries but NO RULE references it "
		       "-- this daemon would apply messages and block nothing. "
		       "Register it as an OPNsense static alias "
		       "(Firewall > Aliases, type external).",
		       cfg->table);
		return false;
	case DPF_GATE_REFUSE_TABLE_MISSING:
		syslog(LOG_ERR,
		       "startup: table %s does not exist. Register it as an "
		       "OPNsense static alias (Firewall > Aliases, type external) "
		       "before starting -- refusing to run, because applying into "
		       "an undeclared table would create it and enforce nothing.",
		       cfg->table);
		return false;
	case DPF_GATE_PROCEED_UNVERIFIED:
	default:
		/* Say so rather than implying health. */
		syslog(LOG_WARNING,
		       "startup: could not confirm enforcement for table %s "
		       "(canary: %s) -- running, but the state is unverified",
		       cfg->table, pf_canary_token(v));
		return true;
	}
}

int main(int argc, char **argv)
{
	struct dpf_config cfg;
	struct pf_apply_ctx ap;
	struct feed_client fc;
	struct capture_source *cs = NULL;
	struct sig_db db;
	struct pol_db pol;
	struct polcfg_stats pcs;
	unsigned n_local_checked = 0;
	const char *config_path = DEFAULT_CONFIG;
	bool once = false;
	bool check_only = false;
	enum dpf_cfg_result cr;
	unsigned line = 0;
	int opt;

	while ((opt = getopt(argc, argv, "c:nt")) != -1) {
		switch (opt) {
		case 'c':
			config_path = optarg;
			break;
		case 'n':
			once = true;
			break;
		case 't':
			check_only = true;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	sig_db_init(&db);
	pol_db_init(&pol);
	memset(&pcs, 0, sizeof pcs);

	dpf_config_defaults(&cfg);
	cr = dpf_config_load(&cfg, config_path, &line);
	if (cr != DPF_CFG_OK && cr != DPF_CFG_MISSING) {
		openlog("aether-sensord-pf", LOG_PID, LOG_DAEMON);
		syslog(LOG_ERR, "config %s:%u: %s -- refusing to start",
		       config_path, line, dpf_cfg_result_str(cr));
		closelog();
		fprintf(stderr, "config %s:%u: %s\n", config_path, line,
		        dpf_cfg_result_str(cr));
		/*
		 * Refuse rather than continue with partial config. A firewall
		 * enforcing into the wrong table, or into no table, is worse than
		 * one that is not running: the second gets noticed.
		 */
		return 1;
	}

	if (!dpf_config_can_enforce(&cfg)) {
		fprintf(stderr,
		        "config %s: not capable of enforcing (spool_dir or table "
		        "unusable)\n",
		        config_path);
		return 1;
	}

	if (!once)
		openlog("aether-sensord-pf", LOG_PID, LOG_DAEMON);

	/*
	 * SIGPIPE MUST BE IGNORED.
	 *
	 * A netgraph control-socket write to a graph that has gone away raises
	 * SIGPIPE, whose default action kills the process WITHOUT any output.
	 * For this daemon that means a transient error terminates the thing that
	 * is supposed to be enforcing, and the machine reports enforcement right
	 * up to the moment it stopped. Measured rc=141 (128+13) with an empty
	 * log.
	 */
	signal(SIGPIPE, SIG_IGN);

	pf_apply_ctx_init(&ap, pf_apply_exec_posix, NULL);
	feed_client_init(&fc);

	if (!startup_enforcement_check(&cfg)) {
		/* Fatal under the default posture: a daemon that cannot enforce
		 * must not sit there looking healthy. */
		if (!cfg.tolerant)
			return 1;
	}

	/*
	 * THE LOCAL CAPTURE SOURCE, when configured.
	 *
	 * Held open across passes on purpose: the reassembly table lives in the
	 * capture handle, and reopening it every pass would reset the state and
	 * make every multi-segment ClientHello unparseable. That is the same
	 * class of bug already fixed once in the transport layer.
	 *
	 * NULL means capture is off OR it could not attach. The two are told
	 * apart below, because "capture is not configured" and "capture is
	 * configured and broken" must not look the same in the log.
	 */
	if (cfg.capture_iface[0] != '\0' && cfg.table_local[0] != '\0') {
		cs = capture_source_open(cfg.capture_iface);
		if (!cs) {
			syslog(LOG_ERR, "capture: cannot attach to %s -- local "
			       "blocking is NOT running", cfg.capture_iface);
			if (!cfg.tolerant)
				return 1;
		} else if (!capture_source_is_healthy(cs)) {
			/*
			 * Wired but not passing: on a real interface this is the
			 * failure that cannot be recovered remotely, because the
			 * interface is out of the kernel's path.
			 */
			syslog(LOG_CRIT, "capture: %s attached but NOT passing "
			       "traffic (reinjection failed) -- tearing down",
			       cfg.capture_iface);
			capture_source_close(cs);
			cs = NULL;
			if (!cfg.tolerant)
				return 1;
		} else {
			syslog(LOG_INFO, "capture: attached to %s, table=%s "
			       "enforce=%s", cfg.capture_iface, cfg.table_local,
			       cfg.capture_enforce ? "yes" : "no (observe)");
		}
	}

	/*
	 * The signature database and policy are loaded ONCE. A policy file that
	 * will not parse is a fault, not an empty policy -- an empty policy
	 * silently allows everything while looking configured.
	 */
	if (cs) {
		if (sig_db_load_path(&db, cfg.sigdb_path) <= 0) {
			syslog(LOG_ERR, "capture: cannot load signature db %s",
			       cfg.sigdb_path);
			capture_source_close(cs);
			cs = NULL;
			if (!cfg.tolerant)
				return 1;
		} else if (polcfg_load_file(&pol, &db, cfg.policy_path,
		                            &pcs) < 0) {
			syslog(LOG_ERR, "capture: cannot load policy %s -- "
			       "refusing to run local blocking with no policy",
			       cfg.policy_path);
			capture_source_close(cs);
			cs = NULL;
			if (!cfg.tolerant)
				return 1;
		} else {
			syslog(LOG_INFO, "capture: %zu signature apps, %zu "
			       "subjects, %zu rules", db.n_apps, pol.n_subjects,
			       pol.n_rules);
		}
	}

	if (check_only) {
		/* The verdict is the output; the caller reads the exit status. */
		printf("config ok: table=%s spool=%s canary=%s\n", cfg.table,
		       cfg.spool_dir, cfg.canary_enabled ? "on" : "off");
		return 0;
	}

	signal(SIGTERM, on_signal);
	signal(SIGINT, on_signal);

	syslog(LOG_INFO, "started: table=%s spool=%s interval=%us canary=%s",
	       cfg.table, cfg.spool_dir, cfg.interval_sec,
	       cfg.canary_enabled ? "on" : "off");

	do {
		struct dpf_pass_stats st;
		struct dpf_local_stats lst;
		int applied = dpf_run_pass(&cfg, &ap, &fc, &st);
		int n_local;

		if (applied < 0) {
			syslog(LOG_ERR, "spool pass failed");
			if (!cfg.tolerant)
				return 1;
		}

		/*
		 * THE LOCAL HALF OF THE PASS.
		 *
		 * This runs every interval and is the whole point of the local
		 * path: traffic seen on this device becomes a pf decision without
		 * waiting for a remote feed to say anything. Runs with cs == NULL
		 * when capture is not configured, which dpf_run_local reports as
		 * skipped rather than as zero flows.
		 */
		n_local = dpf_run_local(&cfg, &ap, cs ? &db : NULL,
		                        cs ? &pol : NULL, capture_source_drain,
		                        cs, &lst);

		/*
		 * A negative return with a configured capture is a FAULT, and on
		 * a firewall it must not be quietly absorbed: the daemon would
		 * keep reporting healthy counters while blocking nothing. The
		 * `tolerant` posture decides whether it is fatal, exactly as for
		 * a failed feed apply.
		 */
		if (n_local < 0 && cs) {
			syslog(LOG_ERR, "local pass failed (flows=%u decided=%u "
			       "applied=%u failed=%u)", lst.flows, lst.decided,
			       lst.applied, lst.failed);
			if (!cfg.tolerant)
				return 1;
		}

		/*
		 * PERIODIC HEALTH CHECK on the capture, and it is not optional.
		 *
		 * A capture that has silently stopped passing traffic and one with
		 * nothing to say produce the same zero verdicts. On a real
		 * interface the failure this catches is the one that cannot be
		 * recovered remotely, because the interface is out of the kernel's
		 * path and the session used it.
		 */
		if (cs && (++n_local_checked % 12u == 0u) &&
		    !capture_source_is_healthy(cs)) {
			syslog(LOG_CRIT, "capture: %s is no longer passing traffic "
			       "-- local blocking has stopped",
			       cfg.capture_iface);
			if (!cfg.tolerant)
				return 1;
		}

		if (once) {
			/* In one-shot mode the exit status IS the report, so print
			 * rather than log. */
			printf("seen=%u applied=%u stale=%u resync=%u unusable=%u "
			       "failed=%u retained=%u\n",
			       st.seen, st.applied, st.stale, st.resync,
			       st.unusable, st.failed, st.retained);
			/*
			 * The local half is reported SEPARATELY and always, even
			 * when capture is off. Folding it into the feed numbers
			 * would make "the fed applied 40 prefixes" and "the
			 * capture blocked 2 destinations" the same sentence, and
			 * an operator could not tell which half blocked what.
			 */
			printf("local: available=%u flows=%u decided=%u "
			       "applied=%u failed=%u truncated=%u skipped=%u\n",
			       lst.available, lst.flows, lst.decided,
			       lst.applied, lst.failed, lst.truncated,
			       lst.skipped);
			if (st.failed > 0 && !cfg.tolerant)
				return 1;
			return 0;
		}

		if (cfg.canary_enabled) {
			enum pf_canary_result v = pf_canary_run(cfg.table, false);
			if (!pf_canary_passed(v))
				syslog(LOG_WARNING, "canary: %s (%s)",
				       pf_canary_token(v), pf_canary_str(v));
			if (cfg.spool_out[0])
				pf_canary_report(cfg.spool_out, cfg.serial, v,
				                 cfg.table, false);
		}

		/*
		 * Sleep in short slices so SIGTERM is handled promptly. A daemon
		 * that ignores a stop signal for a whole interval delays every
		 * service restart, which is how operators learn to SIGKILL.
		 */
		for (unsigned slept = 0;
		     slept < cfg.interval_sec && !g_stop; slept++)
			sleep(1);
	} while (!g_stop);

	syslog(LOG_INFO, "stopping");
	closelog();
	return 0;
}
