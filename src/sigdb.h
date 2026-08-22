/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Signature database for aether-sensord (ADR-020 decisions 4 and 8).
 *
 * Loads the application signature file this feed ships -- currently 1,347
 * entries, against upstream Open App Filter's 87. The database is the asset;
 * the engines are commodity.
 *
 * Two defects in the reference implementation are designed out here rather
 * than inherited (see optim-wrt 21967be):
 *
 *   1. `init_app_name_table()` fills a fixed 1024-entry array with no index
 *      check. Entry 1025 corrupts BSS and the process segfaults around 1098
 *      *during traffic*, which reads as a deliberate capacity cliff. Here the
 *      table is bounded, overflow is REFUSED and COUNTED, and the loader
 *      reports what it accepted -- never what it was offered.
 *
 *   2. Apps are addressed by numeric id across a cloud/device boundary, so a
 *      controller mapping YouTube to 39037 blocks Samba on a device whose
 *      database calls 11001 Samba. Every app therefore carries a STABLE TAG
 *      derived from its name, and the tag is the controller-facing identifier.
 *      Numeric ids never leave this file.
 *
 * Free of netlink, nDPI and socket includes so it builds and unit-tests on the
 * host with plain gcc.
 *
 * Wire format, from the file's own third header line:
 *   #id name:[proto;sport;dport;host url;request;dict]
 * e.g.
 *   10001 jPush:[tcp;;;docs.jiguang.cn;;],
 *   13005 samba:[tcp;;445;;;]                        <- port-only, no host
 *   13003 WindowsUpdate:[tcp;;80;a.com;;,tcp;;;b.com;;]  <- two rules
 */

#ifndef AETHER_SENSORD_SIGDB_H
#define AETHER_SENSORD_SIGDB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Sized for what we ship plus headroom, not for what upstream ships. Exceeding
 * it is refused and counted, never written past. */
#define SIG_MAX_APPS 4096
#define SIG_MAX_RULES 16384

#define SIG_NAME_LEN 64
#define SIG_TAG_LEN 64
#define SIG_HOST_LEN 128

/* Protocols a rule can pin. 0 means "any". */
enum sig_proto { SIG_PROTO_ANY = 0, SIG_PROTO_TCP = 6, SIG_PROTO_UDP = 17 };

struct sig_app {
	uint32_t id;       /* native numeric id, e.g. 39037 -- device-local only */
	/*
	 * The DATABASE'S OWN `#class` number (id / 1000), range 10..42.
	 *
	 * NOT the `class_list` array index, range 0..31, which is what ubus
	 * reports and what aether has vendored. The two numberings disagree for
	 * every app in the database -- id 10001 is class NUMBER 10 and class
	 * INDEX 0 -- and conflating them is exactly what produced the
	 * divide-by-1000 defect on the controller side.
	 *
	 * Deliberately not called `class_id`: that name invites mapping it
	 * straight onto a controller category. If aether-sensord ever emits a
	 * category northbound it must send the class_list INDEX or the app id,
	 * never this field.
	 */
	uint16_t db_class;
	char name[SIG_NAME_LEN]; /* as written in the file, e.g. "WindowsUpdate" */
	char tag[SIG_TAG_LEN];   /* stable controller-facing id, e.g. "windowsupdate" */
};

struct sig_rule {
	uint16_t app_index; /* index into sig_db.apps */
	uint16_t sport;     /* 0 = any */
	uint16_t dport;     /* 0 = any */
	uint8_t proto;      /* enum sig_proto */
	/* Host/SNI pattern. Empty means this is a port-only rule (e.g. samba on
	 * 445), which matches on transport alone and must never match a
	 * hostname lookup by accident. */
	char host[SIG_HOST_LEN];
};

struct sig_db {
	struct sig_app *apps;
	size_t n_apps;
	struct sig_rule *rules;
	size_t n_rules;

	/* Declared by the data file itself (`#format v2.0`), not by config.
	 * An engine that reads the declaration from the file it is parsing does
	 * not need a UCI value, and a UCI value that disagreed would be the more
	 * dangerous state (ADR-017). */
	char format[16];
	char version[32];

	/* Refusals. Reported with the data so a truncated or malformed database
	 * is visible rather than presenting as reduced coverage. */
	uint32_t rejected_apps_full;
	uint32_t rejected_rules_full;
	uint32_t rejected_malformed;
	/* Lines whose tag already existed, folded into the first record. Not a
	 * failure: the database legitimately describes one app under several
	 * numeric ids. Counted so the difference between lines read and apps
	 * exposed is always explainable. */
	uint32_t merged_by_tag;
};

bool sig_db_init(struct sig_db *db);
void sig_db_free(struct sig_db *db);

/*
 * Load signatures from an open stream. Additive: may be called more than once.
 *
 * Returns the number of apps ACCEPTED, or -1 on unusable input. Never
 * partially writes past a bound; refusals land in the counters above.
 */
long sig_db_load(struct sig_db *db, FILE *fp);

/* Convenience wrapper around sig_db_load. */
long sig_db_load_path(struct sig_db *db, const char *path);

/*
 * Normalise an app name into a stable tag: lowercase, and anything that is
 * not [a-z0-9] folded to '-', with runs collapsed and edges trimmed.
 *
 * "WindowsUpdate" -> "windowsupdate", "Google Play" -> "google-play".
 * Stability matters more than beauty: this string is a contract with the
 * controller, so the rule is deliberately dull and total.
 */
void sig_tag_normalise(const char *name, char *out, size_t out_len);

const struct sig_app *sig_db_by_tag(const struct sig_db *db, const char *tag);
const struct sig_app *sig_db_by_id(const struct sig_db *db, uint32_t id);
const struct sig_app *sig_db_app_at(const struct sig_db *db, size_t index);

#endif /* AETHER_SENSORD_SIGDB_H */
