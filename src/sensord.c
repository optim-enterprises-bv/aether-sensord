/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * aether-sensord -- device-side security service (ADR-020).
 *
 * ONE DAEMON, SEVERAL SOURCES. ADR-020 decision 1: this replaces oafd, nDPId
 * and the former standalone aether-fwlogs. A single poll() loop watches the
 * NFLOG socket and the feed spool, so there is one config surface, one
 * identity, one uplink and one health surface rather than four.
 *
 * WHAT IS WIRED IN THIS BUILD: the attacker-reputation path, end to end, and
 * firewall-drop sensing.
 * Feed messages arrive as files in a spool directory, are parsed, folded into
 * the delta/serial state machine, rendered to nftables commands, applied, and
 * then VERIFIED against the kernel's own view of the set.
 *
 * WHAT IS NOT: capture, nDPI dissection and classification. The signature
 * database and matcher are loaded and reported here so the load can be
 * confirmed on-device, but nothing feeds them traffic yet, so no application
 * is classified and no app policy is enforced.
 *
 * `oaf.ko` continues to do app filtering, and IN THIS BUILD this daemon does
 * not talk to it. That is a statement about how far the work has got, not the
 * end state: ADR-020 decision 1 has aether-sensord replacing `oafd`, and
 * `oafd`'s entire job is driving `oaf.ko` over netlink id 29. So when the app
 * path is wired, this daemon WILL drive the module -- that is what replacing
 * the daemon means. What stays untouched is the kernel module itself, which
 * is consumed from upstream v6.1.8 rather than forked or renamed (ADR-020
 * decision 2): it is free, current, and does the in-kernel first-packet drop
 * that a userspace classifier cannot.
 *
 * That split is stated plainly rather than implied, because a daemon that
 * starts cleanly while enforcing nothing is the exact failure this project
 * keeps finding.
 *
 * The daemon does NOT talk to the network. Feed messages are delivered into
 * the spool by ac-client, which already holds the device's mTLS identity
 * (ADR-018); a second daemon with a second certificate store would be a second
 * thing to get wrong.
 */

#include "afpush.h"
#include "nflog_raw.h"
#include "observe.h"
#include "apply.h"
#include "feed.h"
#include "match.h"
#include "nft.h"
#include "polcfg.h"
#include "policy.h"
#include "sigdb.h"

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <poll.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_DB "/etc/appfilter/feature_en.cfg"
#define DEFAULT_SPOOL "/var/spool/aether-sensord/feed"
#define DEFAULT_NFT_INCLUDE \
	"/usr/share/nftables.d/table-pre/inet/fw4/10-aether-sensord.nft"
#define DEFAULT_INTERVAL 30
#define DEFAULT_TIMEOUT_SEC 604800 /* 7 days, matching the scorer's half-life */

#define CMD_BUF 65536

static volatile sig_atomic_t running = 1;

static void on_signal(int sig)
{
	(void)sig;
	running = 0;
}

struct config {
	const char *db_path;
	const char *spool_dir;
	const char *nft_include;
	unsigned interval;
	uint32_t set_timeout;
	int foreground;
	int once;
	/* Overridable so the whole apply+verify path can be exercised against a
	 * stub without root, a device, or a real ruleset. */
	const char *nft_path;
	/* Push compiled app rules to the aether-af kernel module. Off by
	 * default: the module may not be loaded, and a daemon that fails to
	 * start because an optional consumer is absent is worse than one that
	 * says so and carries on. */
	int push_af;

	/*
	 * Firewall-drop sensing, formerly the separate aether-fwlogs daemon.
	 *
	 * OFF BY DEFAULT and separately consented, unlike everything else here.
	 * The rest of this daemon BLOCKS hostile inbound and collects nothing
	 * about the subscriber; this component REPORTS attacker addresses,
	 * which are personal data under GDPR. Merging the daemons must not
	 * merge their consent, so the flag stays its own (ADR-019 section 9).
	 */
	int sense_enabled;
	unsigned sense_group;
	size_t sense_capacity;
	uint32_t sense_scan_ports;
	/* UCI policy file compiled into kernel rules when -k is given. */
	const char *policy_path;
	const char *sense_spool;
	unsigned sense_max_batches;
};

/*
 * Write the set declarations to an fw4 include.
 *
 * Not `nft add set`: fw4 rebuilds its ruleset on every reload and an
 * imperatively-created set is destroyed the next time anything touches the
 * firewall. Writing to the include directory is what makes the set survive,
 * and it is an explicit ADR-020 gate item.
 */
static bool install_set_decl(const struct config *cfg,
                             const struct nft_target *t)
{
	char decl[4096];
	if (nft_render_set_decl(t, cfg->set_timeout, decl, sizeof(decl)) == 0) {
		syslog(LOG_ERR, "set declaration did not fit its buffer");
		return false;
	}

	char tmp[512];
	snprintf(tmp, sizeof(tmp), "%s.partial", cfg->nft_include);

	FILE *fp = fopen(tmp, "w");
	if (!fp) {
		syslog(LOG_ERR, "cannot write %s: %s -- is nftables.d present?", tmp,
		       strerror(errno));
		return false;
	}
	fputs(decl, fp);
	int err = ferror(fp);
	if (fclose(fp) != 0 || err) {
		syslog(LOG_ERR, "write failed for %s", tmp);
		unlink(tmp);
		return false;
	}
	/* Rename only after a complete write, so fw4 never reads a half file. */
	if (rename(tmp, cfg->nft_include) != 0) {
		syslog(LOG_ERR, "cannot install %s: %s", cfg->nft_include,
		       strerror(errno));
		unlink(tmp);
		return false;
	}
	return true;
}

/* Apply one parsed message. Returns true when the set was verified afterwards. */
static bool apply_message(struct apply_ctx *ap, const struct nft_target *t,
                          const struct feed_msg *msg, bool is_list)
{
	char cmds[CMD_BUF];
	size_t used = 0;
	size_t rendered = 0;
	char err[512];

	if (is_list) {
		size_t n = nft_render_flush(t, cmds, sizeof(cmds));
		if (n == 0)
			return false;
		used = n;
	}

	if (msg->n_remove > 0) {
		size_t n = nft_render_del(t, msg->remove, msg->n_remove, cmds + used,
		                          sizeof(cmds) - used, &rendered);
		if (n == 0 && msg->n_remove > 0) {
			syslog(LOG_WARNING, "removal batch did not fit; skipping batch");
			return false;
		}
		used += n;
	}

	size_t added = 0;
	if (msg->n_add > 0) {
		size_t n = nft_render_add(t, msg->add, msg->n_add, cmds + used,
		                          sizeof(cmds) - used, &added);
		if (n == 0) {
			syslog(LOG_WARNING, "addition batch did not fit; skipping batch");
			return false;
		}
		used += n;
	}

	if (used == 0)
		return true; /* nothing to do */

	/*
	 * Verify against a FLOOR, not an exact count: auto-merge legitimately
	 * collapses overlapping prefixes. For a delta we cannot predict the
	 * resulting total at all, so we only assert the set is readable and
	 * non-empty when we just added to it.
	 */
	long expect = (added > 0) ? 1 : 0;
	if (!apply_and_verify(ap, t, cmds, false, expect, err, sizeof(err))) {
		syslog(LOG_ERR, "reputation set NOT enforced: %s", err);
		return false;
	}
	return true;
}

/* Read one spool file, apply it, and remove it on success. */
static void process_file(const struct config *cfg, struct feed_client *fc,
                         struct apply_ctx *ap, const struct nft_target *t,
                         const char *path)
{
	FILE *fp = fopen(path, "r");
	if (!fp) {
		syslog(LOG_WARNING, "cannot open %s: %s", path, strerror(errno));
		return;
	}
	static char buf[CMD_BUF];
	size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
	fclose(fp);
	buf[n] = '\0';
	if (n == 0) {
		unlink(path);
		return;
	}

	struct feed_msg msg;
	if (!feed_parse(buf, n, &msg)) {
		syslog(LOG_WARNING, "unusable feed message %s -- discarding", path);
		unlink(path);
		return;
	}
	if (msg.rejected || msg.overflowed)
		syslog(LOG_WARNING,
		       "feed serial %llu: %u elements refused, %u over capacity",
		       (unsigned long long)msg.serial, msg.rejected, msg.overflowed);

	enum feed_outcome o = feed_client_accept(fc, &msg);
	switch (o) {
	case FEED_STALE:
		unlink(path);
		return;
	case FEED_RESYNC_REQUIRED:
		/*
		 * Leave the set alone. Applying across a gap diverges the device
		 * from the controller invisibly from both ends.
		 */
		syslog(LOG_WARNING,
		       "feed gap at serial %llu (have %llu, missed %u) -- set left "
		       "untouched, awaiting a snapshot",
		       (unsigned long long)msg.serial,
		       (unsigned long long)fc->serial, fc->missed);
		unlink(path);
		return;
	case FEED_APPLIED:
		break;
	}

	if (apply_message(ap, t, &msg, msg.type == FEED_MSG_LIST)) {
		syslog(LOG_INFO, "feed serial %llu applied and verified (+%zu -%zu)",
		       (unsigned long long)msg.serial, msg.n_add, msg.n_remove);
		unlink(path);
	} else {
		/*
		 * Leave the file in place: the serial has advanced in memory but
		 * the kernel did not take it, so a restart should retry rather
		 * than skip. Losing the message here would leave a permanent
		 * silent divergence.
		 */
		syslog(LOG_ERR, "feed serial %llu retained for retry",
		       (unsigned long long)msg.serial);
	}
	(void)cfg;
}

static void scan_spool(const struct config *cfg, struct feed_client *fc,
                       struct apply_ctx *ap, const struct nft_target *t)
{
	DIR *d = opendir(cfg->spool_dir);
	if (!d)
		return;
	struct dirent *ent;
	while ((ent = readdir(d)) != NULL) {
		if (ent->d_name[0] == '.')
			continue;
		size_t len = strlen(ent->d_name);
		if (len < 6 || strcmp(ent->d_name + len - 5, ".json") != 0)
			continue;
		char path[1024];
		snprintf(path, sizeof(path), "%s/%s", cfg->spool_dir, ent->d_name);
		process_file(cfg, fc, ap, t, path);
	}
	closedir(d);
}

/*
 * Firewall-drop sensing, formerly the aether-fwlogs daemon.
 *
 * A packet the firewall dropped is a packet nobody wanted, so recording its
 * source costs the subscriber nothing and tells the fleet who is knocking.
 * Private sources are discarded here rather than at report time -- a
 * misconfigured LAN host must never be published as an attacker.
 */
struct sense_ctx {
	struct obs_table tbl;
	uint64_t seen;
	uint64_t undecodable;
};

static void on_sensed_packet(const uint8_t *pkt, uint32_t len, void *user)
{
	struct sense_ctx *sc = user;
	struct obs_addr src;
	uint16_t dport = 0;

	if (!sc || len > (uint32_t)INT_MAX)
		return;
	if (obs_decode(pkt, (int)len, &src, &dport) != 0) {
		sc->undecodable++;
		return;
	}
	sc->seen++;
	/* obs_record is the single owner of the private-source rule and counts
	 * its own refusals. Re-checking here would give two counters that can
	 * disagree, and the one reported would be the one nobody trusts. */
	obs_record(&sc->tbl, &src, dport, (int64_t)time(NULL));
}

/* Keep at most `max_batches` spool files, deleting oldest first. */
static void sense_prune(const struct config *cfg)
{
	char cmd[640];

	snprintf(cmd, sizeof(cmd),
	         "ls -1t '%s'/batch-*.ndjson 2>/dev/null | tail -n +%u | "
	         "xargs -r rm -f",
	         cfg->sense_spool, cfg->sense_max_batches + 1);
	if (system(cmd) != 0)
		syslog(LOG_DEBUG, "sense spool prune returned non-zero");
}

/*
 * Write one NDJSON batch and reset the table.
 *
 * ac-client ships the spool; this daemon opens no network socket. The batch
 * carries the table's own refusal counters, so the backend can tell a quiet
 * network from an overwhelmed sensor or a mis-scoped firewall rule. A sensor
 * that hides its own degradation is worse than no sensor (ADR-017).
 */
static void sense_flush(const struct config *cfg, struct sense_ctx *sc)
{
	char path[512], tmp[540];
	time_t now;
	FILE *f;
	long n;
	int err;

	if (sc->tbl.used == 0 && sc->tbl.dropped_full == 0 &&
	    sc->tbl.dropped_private == 0)
		return;

	now = time(NULL);
	snprintf(path, sizeof(path), "%s/batch-%lld.ndjson", cfg->sense_spool,
	         (long long)now);
	snprintf(tmp, sizeof(tmp), "%s.partial", path);

	f = fopen(tmp, "w");
	if (!f) {
		syslog(LOG_ERR, "cannot open sense spool %s: %s", tmp,
		       strerror(errno));
		return;
	}

	n = obs_write_ndjson(&sc->tbl, f);
	fprintf(f,
	        "{\"meta\":true,\"sources\":%ld,\"dropped_full\":%llu,"
	        "\"dropped_private\":%llu,\"undecodable\":%llu,"
	        "\"interval\":%u,\"emitted_at\":%lld}\n",
	        n < 0 ? 0 : n, (unsigned long long)sc->tbl.dropped_full,
	        (unsigned long long)sc->tbl.dropped_private,
	        (unsigned long long)sc->undecodable, cfg->interval,
	        (long long)now);

	err = ferror(f);
	if (fclose(f) != 0 || err || n < 0) {
		syslog(LOG_ERR, "sense spool write failed, discarding batch");
		unlink(tmp);
		obs_table_reset(&sc->tbl);
		return;
	}

	/* Rename only after a complete write, so a consumer never sees a
	 * half-written batch. */
	if (rename(tmp, path) != 0) {
		syslog(LOG_ERR, "cannot rename %s: %s", tmp, strerror(errno));
		unlink(tmp);
	} else {
		syslog(LOG_INFO, "sensing: wrote %ld source records to %s", n,
		       path);
		if (sc->tbl.dropped_private > 0)
			syslog(LOG_WARNING,
			       "sensing: %llu private-source records refused -- "
			       "the NFLOG rule is logging LAN traffic and should "
			       "be WAN-scoped",
			       (unsigned long long)sc->tbl.dropped_private);
		if (sc->tbl.dropped_full > 0)
			syslog(LOG_WARNING,
			       "sensing: %llu records dropped, table full "
			       "(capacity %zu)",
			       (unsigned long long)sc->tbl.dropped_full,
			       sc->tbl.capacity);
	}

	sense_prune(cfg);
	obs_table_reset(&sc->tbl);
}

/* polcfg reports through a callback so it stays free of syslog. */
static void policy_emit(void *user, const char *line)
{
	(void)user;
	syslog(LOG_INFO, "%s", line);
}

static void usage(const char *a0)
{
	fprintf(stderr,
	        "usage: %s [-d db] [-s spool] [-n nft-include] [-i interval]\n"
	        "          [-T set-timeout-sec] [-N nft-path] [-k] [-f] [-1]\n"
	        "          [-S] [-g nflog-group] [-c capacity] [-p scan-ports]\n"
	        "          [-D sense-spool] [-b sense-max-batches] [-P policy]\n"
	        "  -k  push compiled app rules to the aether-af kernel module\n"
	        "  -S  enable firewall-drop sensing (OFF by default: reports\n"
	        "      attacker addresses, which is separately consented)\n",
	        a0);
}

int main(int argc, char **argv)
{
	struct config cfg = {
		.db_path = DEFAULT_DB,
		.spool_dir = DEFAULT_SPOOL,
		.nft_include = DEFAULT_NFT_INCLUDE,
		.interval = DEFAULT_INTERVAL,
		.set_timeout = DEFAULT_TIMEOUT_SEC,
		.foreground = 0,
		.once = 0,
		.nft_path = NULL,
		.push_af = 0,
		.sense_enabled = 0,
		.sense_group = 5,
		.sense_capacity = 4096,
		.sense_scan_ports = 8,
		.policy_path = "/etc/config/aether-policy",
		.sense_spool = "/var/spool/aether-sensord/sense",
		.sense_max_batches = 32,
	};

	int opt;
	while ((opt = getopt(argc, argv, "d:s:n:i:T:N:g:c:p:D:b:P:f1kSh")) != -1) {
		switch (opt) {
		case 'd': cfg.db_path = optarg; break;
		case 's': cfg.spool_dir = optarg; break;
		case 'n': cfg.nft_include = optarg; break;
		case 'i': cfg.interval = (unsigned)strtoul(optarg, NULL, 10); break;
		case 'T': cfg.set_timeout = (uint32_t)strtoul(optarg, NULL, 10); break;
		case 'N': cfg.nft_path = optarg; break;
		case 'k': cfg.push_af = 1; break;
		case 'S': cfg.sense_enabled = 1; break;
		case 'g': cfg.sense_group = (unsigned)strtoul(optarg, NULL, 10); break;
		case 'c': cfg.sense_capacity = (size_t)strtoul(optarg, NULL, 10); break;
		case 'p': cfg.sense_scan_ports = (uint32_t)strtoul(optarg, NULL, 10); break;
		case 'P': cfg.policy_path = optarg; break;
		case 'D': cfg.sense_spool = optarg; break;
		case 'b': cfg.sense_max_batches = (unsigned)strtoul(optarg, NULL, 10); break;
		case 'f': cfg.foreground = 1; break;
		case '1': cfg.once = 1; break;
		default: usage(argv[0]); return 2;
		}
	}
	if (cfg.interval == 0)
		cfg.interval = DEFAULT_INTERVAL;

	openlog("aether-sensord", cfg.foreground ? LOG_PERROR : 0, LOG_DAEMON);

	/*
	 * Load the signature database and report what was ACCEPTED. Nothing
	 * classifies traffic in this build, but the load is reported here so the
	 * ADR-020 gate item is checkable on a running device rather than only
	 * through aether-sigtool.
	 */
	struct sig_db sigs;
	if (!sig_db_init(&sigs)) {
		syslog(LOG_ERR, "cannot allocate signature tables");
		return 1;
	}
	long n_apps = sig_db_load_path(&sigs, cfg.db_path);
	if (n_apps < 0) {
		syslog(LOG_WARNING,
		       "signature database %s unreadable -- reputation enforcement "
		       "continues, application classification would not",
		       cfg.db_path);
	} else {
		syslog(LOG_INFO,
		       "signatures: %ld apps, %zu rules accepted, %u merged by tag, "
		       "%u malformed, %u refused for capacity (format %s)",
		       n_apps, sigs.n_rules, sigs.merged_by_tag,
		       sigs.rejected_malformed,
		       sigs.rejected_apps_full + sigs.rejected_rules_full,
		       sigs.format[0] ? sigs.format : "undeclared");
		if (sigs.rejected_apps_full || sigs.rejected_rules_full)
			syslog(LOG_ERR,
			       "SIGNATURES REFUSED FOR CAPACITY -- coverage is reduced "
			       "and this is not a warning to ignore");
	}

	/*
	 * Push app rules to the kernel module, if asked and if it is there.
	 *
	 * This is the boundary in practice: everything above stays here in
	 * BSD userspace, and what crosses is a list of hashes. The module
	 * cannot reconstruct a signature from one.
	 */
	/*
	 * Load the policy BEFORE deciding whether the module is reachable.
	 *
	 * A malformed policy file is the operator's problem whether or not
	 * aether-af happens to be loaded, and burying the report inside the
	 * module branch would hide it on exactly the devices where nothing is
	 * being enforced anyway.
	 */
	struct pol_db pol;
	struct polcfg_stats pst;
	long np;

	pol_db_init(&pol);
	np = polcfg_load_file(&pol, &sigs, cfg.policy_path, &pst);
	if (np < 0) {
		/* A device with no parental policy configured is an ordinary
		 * device. Not an error, and not silence either. */
		syslog(LOG_INFO, "policy: %s not readable; no app rules",
		       cfg.policy_path);
	} else {
		polcfg_report(&pst, policy_emit, NULL);
	}

	if (cfg.push_af) {
		static uint64_t hashes[AFPUSH_MAX_MSG];
		struct afpush_conn afc;
		size_t collisions = 0;
		long nh;

		/*
		 * Compile before checking for the module.
		 *
		 * The compile is where policy meets the signature database, and
		 * its result -- how many patterns a rule set actually resolves
		 * to -- is worth reporting even with nothing to push it to. A
		 * policy that names two applications and compiles to zero
		 * hashes is a coverage gap, and it should be visible on a
		 * device where the module was never loaded rather than only on
		 * one where it was.
		 */
		nh = afpush_compile(&pol, &sigs, hashes,
		                    sizeof(hashes) / sizeof(hashes[0]),
		                    &collisions);
		if (nh < 0)
			syslog(LOG_ERR, "rule compilation failed");
		else
			syslog(LOG_INFO,
			       "aether-af: %ld host patterns compiled from %zu "
			       "policy rules (%zu duplicates collapsed)",
			       nh, pol.n_rules, collisions);

		if (nh == 0 && pol.n_rules > 0)
			syslog(LOG_WARNING,
			       "aether-af: %zu policy rules compiled to NO host "
			       "patterns -- nothing will be blocked. Check that "
			       "the rules are BLOCK and name apps the signature "
			       "database defines.",
			       pol.n_rules);

		if (!afpush_open(&afc)) {
			syslog(LOG_WARNING,
			       "aether-af module not reachable on netlink unit %d "
			       "-- %ld app rules NOT pushed. Reputation "
			       "enforcement is unaffected.",
			       AFPUSH_NETLINK_UNIT, nh < 0 ? 0 : nh);
		} else {

			if (nh >= 0) {
				uint8_t msg[AFPUSH_MAX_MSG];
				size_t n, written = 0;

				n = afpush_build_hello(msg, sizeof(msg));
				if (n)
					afpush_send(&afc, msg, n);

				n = afpush_build_simple(msg, sizeof(msg),
				                        AFPUSH_RULES_BEGIN);
				if (n)
					afpush_send(&afc, msg, n);

				/*
				 * Send in as many messages as it takes.
				 *
				 * The module accumulates every RULE_ADD into a
				 * staging set and only swaps it in on COMMIT,
				 * so a rule set larger than one message is a
				 * sender-side loop and nothing more.
				 *
				 * That same property is what makes aborting
				 * safe: if any batch fails we return without
				 * committing, and the module keeps enforcing
				 * the ruleset it already had. Committing what
				 * we managed to send would silently enforce
				 * less than the controller believes -- the
				 * failure this loop exists to remove.
				 */
				bool complete = true;
				unsigned batches = 0;

				while (written < (size_t)nh) {
					size_t chunk = 0;

					n = afpush_build_rules(
					        msg, sizeof(msg), hashes + written,
					        NULL, NULL, (size_t)nh - written,
					        &chunk);
					if (n == 0 || chunk == 0) {
						/* A single rule that will not
						 * fit an empty message means
						 * the two sides disagree about
						 * the wire format. Looping
						 * would spin forever. */
						syslog(LOG_ERR,
						       "aether-af: no rule fits an "
						       "empty message at offset %zu; "
						       "wire format mismatch, "
						       "NOT committing",
						       written);
						complete = false;
						break;
					}
					if (!afpush_send(&afc, msg, n)) {
						syslog(LOG_ERR,
						       "aether-af: batch %u failed "
						       "after %zu of %ld rules (%s); "
						       "NOT committing, module keeps "
						       "its previous ruleset",
						       batches, written, nh,
						       strerror(errno));
						complete = false;
						break;
					}
					written += chunk;
					batches++;
				}

				if (!complete) {
					/* Leave staging behind deliberately.
					 * The next successful BEGIN frees it,
					 * and until then the live ruleset is
					 * the last one that committed whole. */
					syslog(LOG_ERR,
					       "aether-af: app rule push ABANDONED; "
					       "enforcement is whatever committed "
					       "last, not what was just compiled");
				} else {
					n = afpush_build_simple(
					        msg, sizeof(msg),
					        AFPUSH_RULES_COMMIT);
					if (n && afpush_send(&afc, msg, n))
						syslog(LOG_INFO,
						       "aether-af: pushed %zu of %ld "
						       "app rule hashes in %u "
						       "batch(es) (%zu duplicate "
						       "patterns collapsed)",
						       written, nh, batches,
						       collisions);
					else
						syslog(LOG_ERR,
						       "aether-af: %zu rules sent but "
						       "COMMIT failed; none are live",
						       written);
				}
			}
			afpush_close(&afc);
		}
	}
	pol_db_free(&pol);

	struct nft_target target = { "inet", "fw4", "aether_rep4", "aether_rep6" };

	if (!install_set_decl(&cfg, &target)) {
		syslog(LOG_ERR, "cannot install nftables set declaration; refusing to "
		                "start rather than run with nowhere to enforce");
		sig_db_free(&sigs);
		return 1;
	}
	syslog(LOG_INFO, "set declaration installed at %s (run `fw4 reload` if the "
	                 "sets are not present yet)", cfg.nft_include);

	mkdir(cfg.spool_dir, 0750);

	/*
	 * Serial state is deliberately NOT persisted across restarts.
	 *
	 * On start we have no baseline, so the first delta triggers a resync and
	 * the controller sends a snapshot. That costs one extra message and is
	 * the correct behaviour, not merely the safe one: after a restart we do
	 * not know whether the nftables set survived. An `fw4 reload`, a
	 * firmware upgrade or a crash can empty it while a persisted serial
	 * would claim we are up to date -- and we would then apply deltas onto
	 * an empty set and believe the fleet was protected.
	 *
	 * Failing toward a snapshot trades a message for the guarantee that
	 * what the controller thinks is enforced actually is.
	 */
	struct feed_client fc;
	feed_client_init(&fc);

	struct apply_ctx ap;
	apply_ctx_init(&ap, apply_exec_posix, NULL);
	if (cfg.nft_path)
		ap.nft_path = cfg.nft_path;

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	struct sense_ctx sense;
	struct nfr_conn nfr;
	int sense_live = 0;

	memset(&sense, 0, sizeof(sense));
	memset(&nfr, 0, sizeof(nfr));
	nfr.fd = -1;
	if (cfg.sense_enabled) {
		if (!obs_table_init(&sense.tbl, cfg.sense_capacity,
		                    cfg.sense_scan_ports)) {
			/* obs_table_init refuses a threshold it cannot honour
			 * rather than silently disabling scan detection. */
			syslog(LOG_ERR, "sensing: refusing capacity=%zu "
			                "scan_ports=%u; sensing NOT started",
			       cfg.sense_capacity, cfg.sense_scan_ports);
		} else if (!nfr_open(&nfr, (uint16_t)cfg.sense_group, 128)) {
			syslog(LOG_WARNING,
			       "sensing: cannot bind NFLOG group %u (%s) -- "
			       "sensing NOT started. Reputation enforcement is "
			       "unaffected.",
			       cfg.sense_group, strerror(errno));
			obs_table_free(&sense.tbl);
		} else {
			sense_live = 1;
			mkdir(cfg.sense_spool, 0750);
			syslog(LOG_INFO,
			       "sensing: live on NFLOG group %u, capacity %zu, "
			       "scan threshold %u ports",
			       cfg.sense_group, cfg.sense_capacity,
			       cfg.sense_scan_ports);
		}
	}

	syslog(LOG_INFO,
	       "started: spool=%s interval=%us set_timeout=%us sensing=%s. "
	       "Reputation enforcement is live; application classification is "
	       "NOT wired in this build.",
	       cfg.spool_dir, cfg.interval, cfg.set_timeout,
	       sense_live ? "live" : (cfg.sense_enabled ? "FAILED" : "off"));

	do {
		scan_spool(&cfg, &fc, &ap, &target);

		/* Emit before waiting, so `-1` produces a batch too. */
		if (sense_live)
			sense_flush(&cfg, &sense);

		if (feed_client_needs_resync(&fc))
			syslog(LOG_WARNING,
			       "awaiting a full snapshot: %u updates missed since serial "
			       "%llu",
			       fc.missed, (unsigned long long)fc.serial);

		if (cfg.once)
			break;

		/*
		 * One loop, two sources. Waiting on the NFLOG socket rather
		 * than sleeping means a burst of drops is drained as it
		 * arrives instead of accumulating in the socket buffer for a
		 * whole interval -- an overflowed NFLOG buffer loses packets
		 * silently, which is exactly the failure this daemon exists to
		 * report.
		 *
		 * When sensing is off this degenerates to an interruptible
		 * sleep, which is still better than sleep(1) in a loop.
		 */
		{
			struct pollfd pfd;
			unsigned waited = 0;

			while (running && waited < cfg.interval) {
				int timeout_ms = 1000;
				int rc;

				if (!sense_live) {
					sleep(1);
					waited++;
					continue;
				}
				pfd.fd = nfr.fd;
				pfd.events = POLLIN;
				pfd.revents = 0;
				rc = poll(&pfd, 1, timeout_ms);
				if (rc < 0) {
					if (errno == EINTR)
						continue; /* signal; re-test running */
					syslog(LOG_ERR, "poll: %s", strerror(errno));
					break;
				}
				if (rc == 0) {
					waited++;
					continue;
				}
				if (pfd.revents & POLLIN) {
					long got = nfr_dispatch(&nfr,
					                        on_sensed_packet,
					                        &sense);
					if (got < 0)
						syslog(LOG_WARNING,
						       "sensing: dispatch error, "
						       "packets may have been lost");
				}
				if (pfd.revents & (POLLERR | POLLHUP)) {
					syslog(LOG_ERR, "sensing: NFLOG socket "
					                "error; sensing stops, "
					                "enforcement continues");
					nfr_close(&nfr);
					sense_live = 0;
				}
			}
		}
	} while (running);

	if (sense_live) {
		/* Do not discard a partial interval on shutdown: those records
		 * were observed and are as real as any other. */
		sense_flush(&cfg, &sense);
		/* Report what was and was not counted. A silent zero is
		 * indistinguishable from "nobody attacked us", so the discards
		 * and the full-table refusals are stated alongside the total.
		 *
		 * Read BEFORE the free, and only on the path where the table
		 * was actually initialised -- the failure branches above have
		 * already freed or never built it. */
		syslog(LOG_INFO,
		       "sensing: %llu packets decoded, %llu undecodable, "
		       "%llu private sources discarded, %llu refused (table "
		       "full), %zu distinct sources held",
		       (unsigned long long)sense.seen,
		       (unsigned long long)sense.undecodable,
		       (unsigned long long)sense.tbl.dropped_private,
		       (unsigned long long)sense.tbl.dropped_full,
		       sense.tbl.used);
		nfr_close(&nfr);
		obs_table_free(&sense.tbl);
	} else if (cfg.sense_enabled) {
		syslog(LOG_WARNING, "sensing: was requested but never ran; "
		                    "nothing was observed this session");
	}

	syslog(LOG_INFO,
	       "stopping: %llu deltas, %llu snapshots applied, %llu resyncs, "
	       "%llu batches applied, %llu failed, %llu verify mismatches",
	       (unsigned long long)fc.applied_deltas,
	       (unsigned long long)fc.applied_lists,
	       (unsigned long long)fc.resyncs,
	       (unsigned long long)ap.applied_batches,
	       (unsigned long long)ap.failed_batches,
	       (unsigned long long)ap.verify_mismatches);

	sig_db_free(&sigs);
	closelog();
	return 0;
}
