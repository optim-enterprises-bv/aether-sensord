/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * The aether-sensord daemon shell for FreeBSD/OPNsense. See daemon_pf.h for what
 * it does and, more importantly, what it deliberately leaves out.
 *
 * Built on the same principle as the rest of the port: the datapath pieces are
 * reused, not reimplemented. The feed protocol is the UNMODIFIED src/feed.c
 * (compiled for pf via feed_pf.h), and applying is apply_pf.c. What lives here is
 * only the config surface and the spool loop -- the parts that genuinely differ
 * between OpenWrt and FreeBSD.
 */

#include <time.h>

#include "daemon_pf.h"
#include "local_decide.h"
#include "local_enforce.h"

#include "canary_pf.h"
#include "feed.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Config                                                              */
/* ------------------------------------------------------------------ */

void dpf_config_defaults(struct dpf_config *cfg)
{
	if (!cfg)
		return;
	memset(cfg, 0, sizeof(*cfg));

	/*
	 * The spool path matches the OpenWrt daemon's, so a transport that knows
	 * one deployment's layout works on the other. The table name matches
	 * PF_TABLE_NAME_DEFAULT so the canary and the daemon cannot disagree about
	 * which table is being checked.
	 */
	snprintf(cfg->spool_dir, sizeof(cfg->spool_dir), "/var/spool/aether/in");
	snprintf(cfg->table, sizeof(cfg->table), "%s", PF_TABLE_NAME_DEFAULT);
	snprintf(cfg->table_v6, sizeof(cfg->table_v6), "aisense_rep6");
	cfg->interval_sec = 5;
	snprintf(cfg->spool_out, sizeof(cfg->spool_out), "/var/spool/aether/out");
	cfg->serial[0] = '\0';
	cfg->canary_enabled = true;

	/*
	 * LOCAL CAPTURE DEFAULTS TO OFF, and that is the safe direction.
	 *
	 * Enabling it is the only setting here that can interrupt traffic, and it
	 * involves reattaching a live interface. A default of "on" would mean an
	 * upgrade silently starts touching the datapath of a firewall whose
	 * operator only ever wanted the reputation feed.
	 */
	cfg->table_local[0] = '\0';
	cfg->capture_iface[0] = '\0';
	cfg->capture_enforce = false;
	cfg->capture_max_flows = DPF_LOCAL_MAX_FLOWS;
	snprintf(cfg->sigdb_path, sizeof(cfg->sigdb_path),
	         "/usr/local/share/aisense/appdb.cfg");
	snprintf(cfg->policy_path, sizeof(cfg->policy_path),
	         "/usr/local/etc/aisense/policy.conf");
	/*
	 * Tolerant defaults to FALSE: a failed apply stops the daemon. A running
	 * daemon that is not enforcing is worse than a stopped one, because only
	 * the stopped one gets investigated.
	 */
	cfg->tolerant = false;
}

const char *dpf_cfg_result_str(enum dpf_cfg_result r)
{
	switch (r) {
	case DPF_CFG_OK:
		return "ok";
	case DPF_CFG_MISSING:
		return "file not found (defaults apply)";
	case DPF_CFG_UNREADABLE:
		return "unreadable";
	case DPF_CFG_TOO_LARGE:
		return "too large";
	case DPF_CFG_BAD_VALUE:
		return "value unusable";
	case DPF_CFG_UNKNOWN_KEY:
		return "unknown key";
	default:
		return "?";
	}
}

/* Trim leading and trailing whitespace in place, returning the start. */
static char *trim(char *s)
{
	char *end;
	while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
		s++;
	end = s + strlen(s);
	while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' ||
	                   end[-1] == '\n'))
		*--end = '\0';
	return s;
}

/* Strip surrounding double quotes, so `table = "aisense_rep4"` works. */
static char *unquote(char *v)
{
	size_t n = strlen(v);
	if (n >= 2 && v[0] == '"' && v[n - 1] == '"') {
		v[n - 1] = '\0';
		return v + 1;
	}
	return v;
}

static bool parse_bool(const char *v, bool *out)
{
	if (!v || !out)
		return false;
	if (strcmp(v, "1") == 0 || strcmp(v, "true") == 0 ||
	    strcmp(v, "yes") == 0 || strcmp(v, "on") == 0) {
		*out = true;
		return true;
	}
	if (strcmp(v, "0") == 0 || strcmp(v, "false") == 0 ||
	    strcmp(v, "no") == 0 || strcmp(v, "off") == 0) {
		*out = false;
		return true;
	}
	return false;
}

/* Copy a value into a fixed buffer, refusing rather than truncating. */
static bool copy_bounded(char *dst, size_t dst_len, const char *src)
{
	size_t n;
	if (!dst || !src || dst_len == 0)
		return false;
	n = strlen(src);
	if (n >= dst_len)
		return false; /* truncation would silently change the table name */
	memcpy(dst, src, n + 1);
	return true;
}

enum dpf_cfg_result dpf_config_parse(struct dpf_config *cfg, const char *text,
                                     size_t len, unsigned *line_no)
{
	unsigned line = 0;
	const char *p;
	const char *end;
	enum dpf_cfg_result worst = DPF_CFG_OK;
	unsigned worst_line = 0;

	if (!cfg || !text)
		return DPF_CFG_UNREADABLE;
	if (len > DPF_CONFIG_MAX)
		return DPF_CFG_TOO_LARGE;

	end = text + len;
	for (p = text; p < end; ) {
		const char *nl = memchr(p, '\n', (size_t)(end - p));
		size_t line_len = nl ? (size_t)(nl - p) : (size_t)(end - p);
		char buf[DPF_PATH_MAX + 256];
		char *s;
		char *eq;
		char *key;
		char *val;

		line++;

		if (line_len >= sizeof(buf))
			line_len = sizeof(buf) - 1;
		memcpy(buf, p, line_len);
		buf[line_len] = '\0';
		p += nl ? (line_len + 1) : line_len;

		s = trim(buf);
		if (*s == '\0' || *s == '#' || *s == ';')
			continue; /* blank or comment */

		eq = strchr(s, '=');
		if (!eq) {
			/*
			 * A line with no '='. Refuse it rather than skipping: an
			 * operator who wrote `table aisense_rep4` believes they
			 * configured something, and silently ignoring it leaves
			 * the default enforcing into the wrong table.
			 */
			if (worst == DPF_CFG_OK) {
				worst = DPF_CFG_BAD_VALUE;
				worst_line = line;
			}
			continue;
		}

		*eq = '\0';
		key = trim(s);
		val = unquote(trim(eq + 1));

		if (strcmp(key, "spool_dir") == 0) {
			if (!copy_bounded(cfg->spool_dir, sizeof(cfg->spool_dir), val))
				goto bad;
		} else if (strcmp(key, "table") == 0) {
			if (!copy_bounded(cfg->table, sizeof(cfg->table), val))
				goto bad;
		} else if (strcmp(key, "table_v6") == 0) {
			if (!copy_bounded(cfg->table_v6, sizeof(cfg->table_v6), val))
				goto bad;
		} else if (strcmp(key, "spool_out") == 0) {
			if (!copy_bounded(cfg->spool_out, sizeof(cfg->spool_out), val))
				goto bad;
		} else if (strcmp(key, "serial") == 0) {
			if (!copy_bounded(cfg->serial, sizeof(cfg->serial), val))
				goto bad;
		} else if (strcmp(key, "interval_sec") == 0) {
			char *endp = NULL;
			long v = strtol(val, &endp, 10);
			if (!endp || *endp != '\0' || v < 1 || v > 3600)
				goto bad;
			cfg->interval_sec = (unsigned)v;
		} else if (strcmp(key, "canary") == 0 ||
		           strcmp(key, "canary_enabled") == 0) {
			if (!parse_bool(val, &cfg->canary_enabled))
				goto bad;
		} else if (strcmp(key, "tolerant") == 0) {
			if (!parse_bool(val, &cfg->tolerant))
				goto bad;
		} else if (strcmp(key, "table_local") == 0) {
			if (!copy_bounded(cfg->table_local,
			                  sizeof(cfg->table_local), val))
				goto bad;
			/*
			 * THE TABLE NAME IS VALIDATED HERE, not at apply time.
			 *
			 * A malformed name reaches pfctl as an argument and fails
			 * there, which is late -- the capture would already be
			 * attached and reading. Refusing it at parse time means a
			 * typo is a config error the operator sees on start, not a
			 * silent failure a week later.
			 */
			if (val[0] != '\0' && !pf_table_name_ok(cfg->table_local))
				goto bad;
		} else if (strcmp(key, "capture_iface") == 0) {
			if (!copy_bounded(cfg->capture_iface,
			                  sizeof(cfg->capture_iface), val))
				goto bad;
		} else if (strcmp(key, "capture_enforce") == 0) {
			if (!parse_bool(val, &cfg->capture_enforce))
				goto bad;
		} else if (strcmp(key, "capture_max_flows") == 0) {
			char *endp = NULL;
			long v = strtol(val, &endp, 10);
			if (!endp || *endp != '\0' || v < 1 ||
			    v > DPF_LOCAL_MAX_FLOWS)
				goto bad;
			cfg->capture_max_flows = (unsigned)v;
		} else if (strcmp(key, "sigdb_path") == 0) {
			if (!copy_bounded(cfg->sigdb_path,
			                  sizeof(cfg->sigdb_path), val))
				goto bad;
		} else if (strcmp(key, "policy_path") == 0) {
			if (!copy_bounded(cfg->policy_path,
			                  sizeof(cfg->policy_path), val))
				goto bad;
		} else {
			if (worst == DPF_CFG_OK) {
				worst = DPF_CFG_UNKNOWN_KEY;
				worst_line = line;
			}
			continue;
		}
		continue;

bad:
		if (worst == DPF_CFG_OK) {
			worst = DPF_CFG_BAD_VALUE;
			worst_line = line;
		}
	}

	if (line_no)
		*line_no = worst_line;
	return worst;
}

enum dpf_cfg_result dpf_config_load(struct dpf_config *cfg, const char *path,
                                    unsigned *line_no)
{
	FILE *fp;
	char buf[DPF_CONFIG_MAX + 1];
	size_t n;

	if (line_no)
		*line_no = 0;
	if (!cfg || !path)
		return DPF_CFG_UNREADABLE;

	fp = fopen(path, "r");
	if (!fp)
		return (errno == ENOENT) ? DPF_CFG_MISSING : DPF_CFG_UNREADABLE;

	n = fread(buf, 1, sizeof(buf) - 1, fp);
	buf[n] = '\0';
	if (ferror(fp)) {
		fclose(fp);
		return DPF_CFG_UNREADABLE;
	}
	fclose(fp);

	if (n >= DPF_CONFIG_MAX)
		return DPF_CFG_TOO_LARGE;

	return dpf_config_parse(cfg, buf, n, line_no);
}

bool dpf_config_can_enforce(const struct dpf_config *cfg)
{
	if (!cfg)
		return false;
	if (cfg->spool_dir[0] == '\0')
		return false;
	return pf_table_name_ok(cfg->table);
}

enum dpf_gate dpf_startup_gate(enum pf_canary_result verdict,
                               bool canary_enabled)
{
	if (!canary_enabled)
		return DPF_GATE_PROCEED;

	switch (verdict) {
	case PF_CANARY_ENFORCED:
		return DPF_GATE_PROCEED;
	case PF_CANARY_NOT_ENFORCED:
		return DPF_GATE_REFUSE_NOT_REFERENCED;
	case PF_CANARY_TABLE_MISSING:
		/*
		 * Refused, not tolerated. `pfctl -t <undeclared> -T add` CREATES
		 * the table and returns 0 (measured on FreeBSD 16.0), so
		 * proceeding would give a daemon that applies every message
		 * successfully and drops nothing -- the exact silent
		 * non-enforcement this whole port exists to make impossible.
		 */
		return DPF_GATE_REFUSE_TABLE_MISSING;
	default:
		/* ADD_REJECTED, NOT_HELD, CLEANUP_FAILED, INCONCLUSIVE: the state
		 * is not known to be bad, and it is not known to be good. Proceed
		 * and SAY SO rather than reporting health. */
		return DPF_GATE_PROCEED_UNVERIFIED;
	}
}

const char *dpf_gate_str(enum dpf_gate g)
{
	switch (g) {
	case DPF_GATE_PROCEED:
		return "proceed";
	case DPF_GATE_PROCEED_UNVERIFIED:
		return "proceed (enforcement unverified)";
	case DPF_GATE_REFUSE_NOT_REFERENCED:
		return "refused (table is not referenced by any rule)";
	case DPF_GATE_REFUSE_TABLE_MISSING:
		return "refused (table does not exist)";
	default:
		return "?";
	}
}

/* ------------------------------------------------------------------ */
/* The spool pass                                                      */
/* ------------------------------------------------------------------ */

struct spool_entry {
	char name[256];
};

static int entry_cmp(const void *a, const void *b)
{
	const struct spool_entry *x = a;
	const struct spool_entry *y = b;
	return strcmp(x->name, y->name);
}

/*
 * Apply one message. Split out so the interesting decisions -- resync, retention,
 * what counts as applied -- are readable in one place.
 */
static void process_file(struct dpf_config *cfg, struct pf_apply_ctx *ap,
                         struct feed_client *fc, const char *path,
                         struct dpf_pass_stats *st)
{
	FILE *fp;
	static char buf[1024 * 1024];
	size_t n;
	struct feed_msg msg;
	enum feed_outcome o;
	const char *table;
	char err[512];

	fp = fopen(path, "r");
	if (!fp) {
		syslog(LOG_WARNING, "cannot open %s: %s", path, strerror(errno));
		st->unusable++;
		return;
	}
	n = fread(buf, 1, sizeof(buf) - 1, fp);
	fclose(fp);
	buf[n] = '\0';

	if (n == 0) {
		/* An empty file is a transport artefact, not a message. Remove it
		 * rather than retrying forever. */
		unlink(path);
		return;
	}

	if (!feed_parse(buf, n, &msg)) {
		/*
		 * Unparseable. Discard rather than retain: retrying a message we
		 * cannot parse would block every later one behind it, and the
		 * resync protocol is what recovers a lost update -- the transport
		 * will resend a snapshot.
		 */
		syslog(LOG_WARNING, "unusable feed message %s -- discarding", path);
		unlink(path);
		st->unusable++;
		return;
	}

	if (msg.rejected || msg.overflowed)
		syslog(LOG_WARNING,
		       "feed serial %llu: %u elements refused, %u over capacity",
		       (unsigned long long)msg.serial, msg.rejected, msg.overflowed);

	o = feed_client_accept(fc, &msg);
	switch (o) {
	case FEED_STALE:
		unlink(path);
		st->stale++;
		return;
	case FEED_RESYNC_REQUIRED:
		/*
		 * LEAVE THE TABLE ALONE. Applying across a gap diverges the device
		 * from the controller, and the divergence is invisible from both
		 * ends: the controller believes it pushed, the device believes it
		 * applied. Refusing and awaiting a snapshot is the only outcome
		 * where a missed update is recoverable.
		 */
		syslog(LOG_WARNING,
		       "feed gap at serial %llu (have %llu, missed %u) -- table "
		       "left untouched, awaiting a snapshot",
		       (unsigned long long)msg.serial,
		       (unsigned long long)fc->serial, fc->missed);
		unlink(path);
		st->resync++;
		return;
	case FEED_APPLIED:
		break;
	}

	table = cfg->table;

	if (msg.type == FEED_MSG_LIST) {
		/*
		 * A snapshot is authoritative, so the table must end up matching it
		 * exactly. Flush first, otherwise entries the controller has since
		 * dropped would linger and keep blocking addresses nobody scored
		 * hostile any more.
		 */
		if (pf_apply_flush(ap, table, err, sizeof(err)) != PF_APPLY_OK) {
			syslog(LOG_ERR, "cannot flush %s for a snapshot: %s", table,
			       err);
			st->failed++;
			/* Retain: the serial has advanced in memory, so a restart
			 * must retry rather than skip. */
			st->retained++;
			return;
		}
	}

	if (msg.n_add > 0 &&
	    !pf_apply_and_verify(ap, table, msg.add, msg.n_add, err, sizeof(err))) {
		syslog(LOG_ERR, "feed serial %llu not applied: %s",
		       (unsigned long long)msg.serial, err);
		st->failed++;
		st->retained++;
		return;
	}

	if (msg.n_remove > 0) {
		enum pf_apply_result r = pf_apply_del(ap, table, msg.remove,
		                                      msg.n_remove, err, sizeof(err));
		if (r != PF_APPLY_OK)
			syslog(LOG_WARNING,
			       "feed serial %llu: removals not applied: %s",
			       (unsigned long long)msg.serial, err);
	}

	syslog(LOG_INFO, "feed serial %llu applied and verified (+%zu -%zu)",
	       (unsigned long long)msg.serial, msg.n_add, msg.n_remove);
	unlink(path);
	st->applied++;
}

/*
 * The local half of a pass.
 *
 * Reads flows from `src`, decides against the signature database and policy, and
 * applies what survives. The enforcement proof is locef_apply's: elements are
 * only counted as applied when they are READ BACK from the table, so an add that
 * pfctl accepted but did not store is a failure here, not a success.
 *
 * OBSERVE MODE STILL RUNS THE WHOLE DECISION. It is not a dry run in the sense of
 * "pretend nothing happened" -- every flow is matched, every policy rule is
 * evaluated, and the would_block counts are real. What it does not do is write.
 * That is what makes it useful for answering "what would this block" before
 * anyone agrees to let it block.
 */
int dpf_run_local(struct dpf_config *cfg, struct pf_apply_ctx *ap,
                  const struct sig_db *db, const struct pol_db *pol,
                  dpf_flow_source_fn src, void *src_user,
                  struct dpf_local_stats *out)
{
	struct dpf_local_flow flows[DPF_LOCAL_MAX_FLOWS];
	struct locdec_flow lf[DPF_LOCAL_MAX_FLOWS];
	struct locdec_block blocks[LOCDEC_MAX_BLOCKS];
	struct locdec_stats dstats;
	struct locef_stats estats;
	struct pol_time now;
	int got, i, n_blocks;

	if (out)
		memset(out, 0, sizeof *out);
	if (!cfg || !ap)
		return -1;

	/*
	 * "NOT CONFIGURED" and "CONFIGURED BUT BROKEN" are different states and
	 * must not share a counter.
	 *
	 * An earlier version folded `!db || !pol` into this same branch, and the
	 * consequence was that a daemon configured to capture but unable to load
	 * its signature database reported `skipped` -- identical to capture
	 * being switched off. That is the failure direction this project
	 * forbids: a misconfiguration that silently reads as a deliberate
	 * choice. It also made a test pass for the wrong reason, which is how
	 * the flaw was found.
	 */
	if (!src || cfg->table_local[0] == '\0' || cfg->capture_iface[0] == '\0') {
		if (out)
			out->skipped = 1;
		return 0;
	}

	/*
	 * From here the operator HAS asked for local capture, so a missing
	 * database or policy is a fault, reported as such. Returning -1 rather
	 * than 0 means a caller running with `tolerant=false` can refuse to
	 * claim it is enforcing.
	 */
	if (!db || !pol) {
		if (out) {
			out->available = 1;
			out->failed++;
		}
		return -1;
	}

	if (out)
		out->available = 1;

	got = src(src_user, flows, DPF_LOCAL_MAX_FLOWS);
	if (got < 0) {
		/*
		 * A capture error is NOT "no traffic". Reporting it as zero flows
		 * would make a dead capture indistinguishable from an idle
		 * interface.
		 */
		if (out)
			out->skipped = 1;
		return 0;
	}
	if ((size_t)got > DPF_LOCAL_MAX_FLOWS)
		got = (int)DPF_LOCAL_MAX_FLOWS;

	/* The capture filled the buffer: more is waiting. Say so. */
	if (out && (size_t)got == DPF_LOCAL_MAX_FLOWS)
		out->truncated = 1;

	for (i = 0; i < got; i++) {
		memset(&lf[i], 0, sizeof lf[i]);
		lf[i].host = flows[i].host;
		lf[i].proto = flows[i].proto;
		lf[i].dport = flows[i].dport;
		memcpy(lf[i].daddr, flows[i].daddr, sizeof lf[i].daddr);
		lf[i].daddr_family = flows[i].daddr_family;
		lf[i].have_daddr = flows[i].have_daddr;
		memcpy(lf[i].smac, flows[i].smac, sizeof lf[i].smac);
		lf[i].have_smac = flows[i].have_smac;
	}

	/*
	 * Time comes from the clock, not from a parameter: this IS the
	 * production caller, and the policy layer needs wall time for its
	 * windows and quotas. Tests of the decision logic call locdec_fold
	 * directly with a supplied time.
	 */
	memset(&now, 0, sizeof now);
	{
		time_t t = time(NULL);
		struct tm lt;

		if (localtime_r(&t, &lt) != NULL) {
			/*
			 * pol_time.wday matches struct tm exactly (0 = Sunday),
			 * and min_of_day is minutes since midnight -- NOT seconds.
			 * Passing seconds here would put every flow outside every
			 * window, so the whole local path would silently allow
			 * everything during hours where a block rule was meant to
			 * apply. It is a two-character mistake with the failure
			 * direction that matters.
			 */
			now.wday = lt.tm_wday;
			now.min_of_day =
			    (uint16_t)(lt.tm_hour * 60 + lt.tm_min);
		}
	}

	n_blocks = locdec_fold(db, pol, lf, (size_t)got, now, 0,
	                       cfg->capture_enforce, blocks,
	                       sizeof blocks / sizeof blocks[0], &dstats, NULL, 0,
	                       NULL);
	if (n_blocks < 0) {
		if (out)
			out->failed++;
		return -1;
	}

	if (out) {
		out->flows = dstats.flows;
		out->decided = dstats.blocked;
	}

	if (n_blocks == 0)
		return 0;

	/*
	 * Apply. In observe mode locef_apply writes nothing and returns true,
	 * so the confirmed count stays 0 and the caller cannot mistake this for
	 * enforcement.
	 */
	if (!locef_apply(ap, cfg->table_local, blocks, (size_t)n_blocks,
	                 cfg->capture_enforce, cfg->capture_enforce, &estats)) {
		if (out) {
			out->failed += estats.failed;
			out->applied += estats.confirmed;
		}
		return -1;
	}

	if (out) {
		out->applied = estats.confirmed;
		out->failed += estats.failed;
	}
	return (int)estats.confirmed;
}

int dpf_run_pass(struct dpf_config *cfg, struct pf_apply_ctx *ap,
                 struct feed_client *fc, struct dpf_pass_stats *out)
{
	DIR *d;
	struct dirent *ent;
	struct spool_entry *entries = NULL;
	size_t n_entries = 0;
	size_t cap = 0;

	if (out)
		memset(out, 0, sizeof(*out));
	if (!cfg || !ap || !fc)
		return -1;

	d = opendir(cfg->spool_dir);
	if (!d)
		return 0; /* no spool yet is not an error */

	/*
	 * Collect first, then SORT. readdir order is filesystem order, and the
	 * transport names files so that lexicographic order is serial order. If a
	 * higher serial were applied first, the lower one would arrive next and be
	 * classified STALE -- so the update would be silently dropped. This is the
	 * one place where "just loop over the directory" is wrong.
	 */
	while ((ent = readdir(d)) != NULL) {
		size_t len;
		if (ent->d_name[0] == '.')
			continue;
		len = strlen(ent->d_name);
		if (len < 6 || strcmp(ent->d_name + len - 5, ".json") != 0)
			continue;
		if (n_entries == cap) {
			size_t ncap = cap ? cap * 2 : 16;
			struct spool_entry *ne = realloc(entries, ncap * sizeof(*ne));
			if (!ne)
				break;
			entries = ne;
			cap = ncap;
		}
		{
			size_t need = strlen(ent->d_name) + 1;
			if (need > sizeof(entries[n_entries].name))
				continue; /* nameless in this spool: skip, do not truncate */
			memcpy(entries[n_entries].name, ent->d_name, need);
		}
		n_entries++;
	}
	closedir(d);

	if (n_entries > 1)
		qsort(entries, n_entries, sizeof(*entries), entry_cmp);

	for (size_t i = 0; i < n_entries; i++) {
		char path[DPF_PATH_MAX * 2];
		if (out)
			out->seen++;
		snprintf(path, sizeof(path), "%s/%s", cfg->spool_dir,
		         entries[i].name);
		process_file(cfg, ap, fc, path, out);
	}

	free(entries);
	return out ? (int)out->applied : 0;
}
