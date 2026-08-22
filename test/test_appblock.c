/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Tests for the enforcement decision.
 *
 * Two properties here fail SILENTLY if wrong, which is why they get most of
 * the coverage:
 *
 *   1. A QUIC flow must never produce ACT_HASH. That hash would be pushed,
 *      never match, and the application would not be blocked -- while every
 *      counter reported success.
 *
 *   2. An address block must land on the PEER, never on the subscriber's own
 *      device. Getting it backwards blocks the LAN host that was browsing.
 */

#include "../src/appblock.h"
#include "../src/afpush.h"

#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

#include <ndpi/ndpi_typedefs.h>

/*
 * Fixture addresses must be GENUINELY public.
 *
 * 203.0.113.0/24 is TEST-NET-3 and obs_addr_is_private() refuses it, so a
 * fixture built from it makes pick_peer() see two private endpoints and
 * decline -- which reads as a bug in the code under test rather than in the
 * test. 93.184.216.34 (example.com) is real public space.
 */
static int checks, failures;
#define CHECK(cond, msg)                                                       \
	do {                                                                   \
		checks++;                                                      \
		if (!(cond)) {                                                 \
			failures++;                                            \
			printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);  \
		}                                                              \
	} while (0)

static const uint8_t MAC[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

/* Load a database from a literal, the same way test_sigdb does. */
static void db_from(struct sig_db *db, const char *text)
{
	FILE *fp = fmemopen((void *)text, strlen(text), "r");

	sig_db_init(db);
	if (fp) {
		sig_db_load(db, fp);
		fclose(fp);
	}
}

/* A signature database with one unambiguous app. */
static void db_init(struct sig_db *db)
{
	db_from(db,
	        "#format v2.0\n"
	        "#class video 11 Video\n"
	        "11001 YouTube:[tcp;;;youtube.example;;]\n");
}

static void pol_init_block(struct pol_db *p, const struct sig_db *sigs,
                           const char *tag)
{
	struct pol_rule r;

	pol_db_init(p);
	pol_add_subject(p, MAC, "kid");
	memset(&r, 0, sizeof(r));
	r.subject_index = 0;
	r.target = POL_TARGET_APP;
	r.action = POL_BLOCK;
	snprintf(r.tag, sizeof(r.tag), "%s", tag);
	pol_add_rule(p, sigs, &r);
}

static struct dpi_result mkflow(const char *host, uint8_t l4,
                                enum dpi_verdict_scope scope,
                                const char *lan_v4, const char *wan_v4)
{
	struct dpi_result f;

	memset(&f, 0, sizeof(f));
	f.classified = true;
	f.have_host = host != NULL;
	if (host)
		snprintf(f.host, sizeof(f.host), "%s", host);
	f.l4proto = l4;
	f.scope = scope;
	f.dport = 443;
	obs_addr_parse(&f.src, lan_v4);
	obs_addr_parse(&f.dst, wan_v4);
	return f;
}

static struct pol_time NOW = { .wday = 3, .min_of_day = 600 };

/* ---- the scope split ---------------------------------------------------- */

static void test_tcp_tls_uses_hash(void)
{
	struct sig_db s;
	struct pol_db p;
	struct dpi_result f;
	struct appblock_decision d;

	db_init(&s);
	pol_init_block(&p, &s, "youtube");
	f = mkflow("youtube.example", IPPROTO_TCP, DPI_SCOPE_NAME_HASH,
	           "192.168.1.50", "93.184.216.34");

	d = appblock_decide(&f, &s, &p, MAC, NOW, 0, 3600);
	CHECK(d.action == ACT_HASH, "TCP/TLS is enforced by name hash");
	CHECK(d.reason == ABR_ENFORCED, "and reported as enforced");
	CHECK(strcmp(d.app_tag, "youtube") == 0, "app tag resolved");
	CHECK(d.name_hash == afpush_hash_name("youtube.example", 15),
	      "the hash matches what the module will compute");
	pol_db_free(&p);
	sig_db_free(&s);
}

static void test_quic_never_uses_hash(void)
{
	struct sig_db s;
	struct pol_db p;
	struct dpi_result f;
	struct appblock_decision d;

	db_init(&s);
	pol_init_block(&p, &s, "youtube");
	f = mkflow("youtube.example", IPPROTO_UDP, DPI_SCOPE_ADDRESS,
	           "192.168.1.50", "93.184.216.34");

	d = appblock_decide(&f, &s, &p, MAC, NOW, 0, 3600);
	CHECK(d.action == ACT_ADDR,
	      "QUIC is enforced by address, NEVER by a hash the kernel cannot match");
	CHECK(d.action != ACT_HASH, "explicitly: not a hash");
	CHECK(d.elem.family == 4, "IPv4 element");
	CHECK(d.elem.prefix == 32, "single host, not a range");
	CHECK(d.elem.timeout_sec == 3600, "carries the timeout it was given");
	pol_db_free(&p);
	sig_db_free(&s);
}

/* ---- the block must land on the peer ------------------------------------ */

static void test_block_targets_the_peer_not_the_subscriber(void)
{
	struct sig_db s;
	struct pol_db p;
	struct dpi_result f;
	struct appblock_decision d;
	uint8_t expect[4] = { 93, 184, 216, 34 };

	db_init(&s);
	pol_init_block(&p, &s, "youtube");

	/* LAN -> WAN */
	f = mkflow("youtube.example", IPPROTO_UDP, DPI_SCOPE_ADDRESS,
	           "192.168.1.50", "93.184.216.34");
	d = appblock_decide(&f, &s, &p, MAC, NOW, 0, 3600);
	CHECK(d.action == ACT_ADDR, "outbound flow enforced");
	CHECK(memcmp(d.elem.addr, expect, 4) == 0,
	      "blocks the WAN peer, not the LAN device");

	/* WAN -> LAN: the peer is now the SOURCE. */
	f = mkflow("youtube.example", IPPROTO_UDP, DPI_SCOPE_ADDRESS,
	           "93.184.216.34", "192.168.1.50");
	d = appblock_decide(&f, &s, &p, MAC, NOW, 0, 3600);
	CHECK(d.action == ACT_ADDR, "inbound direction also enforced");
	CHECK(memcmp(d.elem.addr, expect, 4) == 0,
	      "still blocks the WAN peer when the direction reverses");

	/* Both private: refuse. Guessing would block a LAN host. */
	f = mkflow("youtube.example", IPPROTO_UDP, DPI_SCOPE_ADDRESS,
	           "192.168.1.50", "192.168.1.60");
	d = appblock_decide(&f, &s, &p, MAC, NOW, 0, 3600);
	CHECK(d.action == ACT_NONE,
	      "LAN-to-LAN is refused rather than blocking a local device");

	pol_db_free(&p);
	sig_db_free(&s);
}

/* ---- refusals ----------------------------------------------------------- */

static void test_refusals_are_distinguishable(void)
{
	struct sig_db s;
	struct pol_db p;
	struct dpi_result f;
	struct appblock_decision d;

	db_init(&s);
	pol_init_block(&p, &s, "youtube");

	/* No hostname: a protocol is not an application. */
	f = mkflow(NULL, IPPROTO_TCP, DPI_SCOPE_NAME_HASH, "192.168.1.50",
	           "93.184.216.34");
	d = appblock_decide(&f, &s, &p, MAC, NOW, 0, 3600);
	CHECK(d.action == ACT_NONE && d.reason == ABR_NO_HOST,
	      "no server name is its own reason");

	/* Unknown host. */
	f = mkflow("nothing.example", IPPROTO_TCP, DPI_SCOPE_NAME_HASH,
	           "192.168.1.50", "93.184.216.34");
	d = appblock_decide(&f, &s, &p, MAC, NOW, 0, 3600);
	CHECK(d.reason == ABR_UNKNOWN_APP, "unknown app is distinct from allowed");

	/* Unattributed flow: must NOT apply another device's policy. */
	f = mkflow("youtube.example", IPPROTO_TCP, DPI_SCOPE_NAME_HASH,
	           "192.168.1.50", "93.184.216.34");
	d = appblock_decide(&f, &s, &p, NULL, NOW, 0, 3600);
	CHECK(d.action == ACT_NONE && d.reason == ABR_NO_SUBJECT,
	      "an unattributable flow is refused, not judged");

	/* Zero timeout must not become a permanent block. */
	f = mkflow("youtube.example", IPPROTO_UDP, DPI_SCOPE_ADDRESS,
	           "192.168.1.50", "93.184.216.34");
	d = appblock_decide(&f, &s, &p, MAC, NOW, 0, 0);
	CHECK(d.action == ACT_NONE,
	      "a zero timeout is refused, not read as 'block forever'");

	/* Unclassified flow. */
	memset(&f, 0, sizeof(f));
	d = appblock_decide(&f, &s, &p, MAC, NOW, 0, 3600);
	CHECK(d.action == ACT_NONE, "an unclassified flow enforces nothing");

	/* NULL arguments. */
	d = appblock_decide(NULL, &s, &p, MAC, NOW, 0, 3600);
	CHECK(d.action == ACT_NONE, "NULL flow is safe");
	d = appblock_decide(&f, NULL, &p, MAC, NOW, 0, 3600);
	CHECK(d.action == ACT_NONE, "NULL sigdb is safe");

	pol_db_free(&p);
	sig_db_free(&s);
}

static void test_allowed_is_not_a_failure(void)
{
	struct sig_db s;
	struct pol_db p;
	struct dpi_result f;
	struct appblock_decision d;

	db_init(&s);
	pol_db_init(&p);
	pol_add_subject(&p, MAC, "kid"); /* no rules: nothing blocked */

	f = mkflow("youtube.example", IPPROTO_TCP, DPI_SCOPE_NAME_HASH,
	           "192.168.1.50", "93.184.216.34");
	d = appblock_decide(&f, &s, &p, MAC, NOW, 0, 3600);
	CHECK(d.action == ACT_NONE && d.reason == ABR_ALLOWED,
	      "permitted traffic reports ALLOWED, not a refusal");
	CHECK(strcmp(d.app_tag, "youtube") == 0,
	      "the app is still identified even when permitted");

	pol_db_free(&p);
	sig_db_free(&s);
}

/*
 * An ambiguous hostname must not be acted on.
 *
 * 30 patterns in the shipped database are claimed by more than one app;
 * en.wikipedia.org resolves to a Malware-class signature among six claimants.
 * Blocking on an arbitrary winner enforces a rule nobody wrote.
 */
static void test_ambiguous_host_is_refused(void)
{
	struct sig_db s;
	struct pol_db p;
	struct dpi_result f;
	struct appblock_decision d;

	db_from(&s,
	        "#format v2.0\n"
	        "#class video 11 Video\n"
	        "#class malware 31 Malware\n"
	        "11001 YouTube:[tcp;;;shared.example;;]\n"
	        "31001 Conduit-Toolbar:[tcp;;;shared.example;;]\n");
	pol_init_block(&p, &s, "youtube");

	f = mkflow("shared.example", IPPROTO_TCP, DPI_SCOPE_NAME_HASH,
	           "192.168.1.50", "93.184.216.34");
	d = appblock_decide(&f, &s, &p, MAC, NOW, 0, 3600);
	CHECK(d.action == ACT_NONE,
	      "a hostname claimed by several apps enforces nothing");
	CHECK(d.reason == ABR_AMBIGUOUS,
	      "and says so, rather than looking like an unknown app");

	pol_db_free(&p);
	sig_db_free(&s);
}

static void test_ipv6_peer(void)
{
	struct sig_db s;
	struct pol_db p;
	struct dpi_result f;
	struct appblock_decision d;

	db_init(&s);
	pol_init_block(&p, &s, "youtube");

	memset(&f, 0, sizeof(f));
	f.classified = true;
	f.have_host = true;
	snprintf(f.host, sizeof(f.host), "youtube.example");
	f.l4proto = IPPROTO_UDP;
	f.scope = DPI_SCOPE_ADDRESS;
	obs_addr_parse(&f.src, "fd00::1");        /* ULA: private */
	obs_addr_parse(&f.dst, "2606:4700::1111"); /* public */

	d = appblock_decide(&f, &s, &p, MAC, NOW, 0, 900);
	CHECK(d.action == ACT_ADDR, "IPv6 flow enforced by address");
	CHECK(d.elem.family == 6, "recorded as v6");
	CHECK(d.elem.prefix == 128, "single host");
	pol_db_free(&p);
	sig_db_free(&s);
}

static void test_reason_strings(void)
{
	CHECK(strlen(appblock_reason_str(ABR_ENFORCED)) > 0, "enforced");
	CHECK(strlen(appblock_reason_str(ABR_NO_HOST)) > 0, "no host");
	CHECK(strlen(appblock_reason_str(ABR_AMBIGUOUS)) > 0, "ambiguous");
	CHECK(strcmp(appblock_reason_str((enum appblock_reason)99), "?") == 0,
	      "an unknown reason does not read as a real one");
}

int main(void)
{
	test_tcp_tls_uses_hash();
	test_quic_never_uses_hash();
	test_block_targets_the_peer_not_the_subscriber();
	test_refusals_are_distinguishable();
	test_allowed_is_not_a_failure();
	test_ambiguous_host_is_refused();
	test_ipv6_peer();
	test_reason_strings();
	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
