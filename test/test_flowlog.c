/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Tests for the classified-flow producer.
 *
 * The classifier worked for weeks and its output reached nothing but a
 * rate-limited syslog line capped at 25 rows per run. These assert the record
 * is shaped for a consumer and that the sensor reports its own losses -- a
 * flow record that vanishes makes the controller's per-app totals quietly
 * wrong, and nothing downstream could tell.
 */

#include "../src/flowlog.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int checks, failures;
#define CHECK(c, msg)                                                          \
	do {                                                                   \
		checks++;                                                      \
		if (!(c)) {                                                    \
			failures++;                                            \
			printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, msg); \
		}                                                              \
	} while (0)

static struct dpi_result mkflow(const char *host, const char *proto)
{
	struct dpi_result f;

	memset(&f, 0, sizeof(f));
	f.l4proto = 6;
	f.dport = 443;
	f.dst.len = 4;
	f.dst.bytes[0] = 93;
	f.dst.bytes[1] = 184;
	f.dst.bytes[2] = 216;
	f.dst.bytes[3] = 34;
	snprintf(f.proto_name, sizeof(f.proto_name), "%s", proto);
	if (host) {
		f.have_host = true;
		snprintf(f.host, sizeof(f.host), "%s", host);
	}
	f.scope = DPI_SCOPE_NAME_HASH;
	return f;
}

static struct appblock_decision mkdec(const char *tag, enum appblock_reason r,
                                      enum appblock_action a)
{
	struct appblock_decision d;

	memset(&d, 0, sizeof(d));
	d.reason = r;
	d.action = a;
	if (tag)
		snprintf(d.app_tag, sizeof(d.app_tag), "%s", tag);
	return d;
}

static char *slurp(const char *dir)
{
	static char buf[8192];
	DIR *dp = opendir(dir);
	struct dirent *e;
	char path[600];
	FILE *f;
	size_t n;

	buf[0] = '\0';
	if (!dp)
		return buf;
	while ((e = readdir(dp))) {
		if (strncmp(e->d_name, "flows-", 6) != 0)
			continue;
		if (strstr(e->d_name, ".partial"))
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
		f = fopen(path, "r");
		if (f) {
			n = fread(buf, 1, sizeof(buf) - 1, f);
			buf[n] = '\0';
			fclose(f);
		}
		break;
	}
	closedir(dp);
	return buf;
}

static void test_record_is_shaped_for_a_consumer(void)
{
	char dir[] = "/tmp/aether-flowlog-XXXXXX";
	struct flowlog fl;
	struct dpi_result f;
	struct appblock_decision d;
	static const uint8_t mac[6] = { 0xa0, 0xd7, 0xf3, 0x11, 0x22, 0x33 };
	char *out;

	if (!mkdtemp(dir)) {
		CHECK(0, "tempdir");
		return;
	}
	CHECK(flowlog_init(&fl, dir), "init");

	f = mkflow("www.youtube.com", "TLS");
	d = mkdec("youtube", ABR_ENFORCED, ACT_HASH);
	flowlog_record(&fl, &f, &d, mac);
	flowlog_flush(&fl);

	out = slurp(dir);
	CHECK(strstr(out, "\"hostname\":\"www.youtube.com\"") != NULL, "carries the name");
	/* The rollup is keyed per (client, app). A record without a client is
	 * rejected as MissingClient -- 520 were, before this was noticed. */
	CHECK(strstr(out, "\"client_mac\":\"a0:d7:f3:11:22:33\"") != NULL,
	      "carries the subject so the flow can be attributed");
	CHECK(strstr(out, "\"app\":\"youtube\"") != NULL, "carries the app tag");
	CHECK(strstr(out, "\"action\":\"blocked_name\"") != NULL, "carries the decision");
	CHECK(strstr(out, "\"reason\":\"enforced\"") != NULL, "carries the wire reason");
	CHECK(strstr(out, "\"proto\":\"TLS\"") != NULL, "carries the protocol");
	/* The prose form must never reach the wire -- the controller has its
	 * own wording and two descriptions of one state drift apart. */
	CHECK(strstr(out, "a packet") == NULL, "no prose on the wire");
}

static void test_an_unrecovered_name_is_null_not_empty(void)
{
	char dir[] = "/tmp/aether-flowlog-XXXXXX";
	struct flowlog fl;
	struct dpi_result f;
	struct appblock_decision d;
	char *out;

	if (!mkdtemp(dir)) {
		CHECK(0, "tempdir");
		return;
	}
	flowlog_init(&fl, dir);

	/* QUIC with no SNI recovered: nDPI named the protocol and not the
	 * host. "no name in this flow" and "the name was empty" are different
	 * failures and the consumer must be able to tell them apart. */
	f = mkflow(NULL, "QUIC");
	d = mkdec(NULL, ABR_NO_HOST, ACT_NONE);
	flowlog_record(&fl, &f, &d, NULL);
	flowlog_flush(&fl);

	out = slurp(dir);
	CHECK(strstr(out, "\"hostname\":null") != NULL, "absent name is null");
	CHECK(strstr(out, "\"hostname\":\"\"") == NULL, "never an empty string");
	/* Unattributable: null, never 00:00:00:00:00:00 -- a zeroed MAC is a
	 * plausible value that would attribute every unattributed flow on the
	 * network to one fictional client. */
	CHECK(strstr(out, "\"client_mac\":null") != NULL, "no subject is null");
	CHECK(strstr(out, "00:00:00:00:00:00") == NULL, "never a zeroed MAC");
	CHECK(strstr(out, "\"app\":null") != NULL, "absent app is null");
	CHECK(strstr(out, "\"reason\":\"no_host\"") != NULL, "reason survives");
}

static void test_the_batch_reports_its_own_losses(void)
{
	char dir[] = "/tmp/aether-flowlog-XXXXXX";
	struct flowlog fl;
	struct dpi_result f;
	struct appblock_decision d;
	static const uint8_t mac[6] = { 0xa0, 0xd7, 0xf3, 0x11, 0x22, 0x33 };
	char *out;
	int i;

	if (!mkdtemp(dir)) {
		CHECK(0, "tempdir");
		return;
	}
	flowlog_init(&fl, dir);

	f = mkflow("example.com", "TLS");
	d = mkdec("web", ABR_ALLOWED, ACT_NONE);
	/* One past a full batch: the flush at capacity empties the buffer, so
	 * this exercises the boundary rather than the drop path. */
	for (i = 0; i < FLOWLOG_BATCH_ROWS + 1; i++)
		flowlog_record(&fl, &f, &d, mac);
	flowlog_flush(&fl);

	out = slurp(dir);
	CHECK(strstr(out, "\"meta\":true") != NULL, "batch carries a meta line");
	CHECK(strstr(out, "\"dropped\":") != NULL,
	      "a sensor that hides its own losses makes the totals silently wrong");
	CHECK(strstr(out, "\"rows\":") != NULL, "meta names the row count");
}

static void test_nothing_is_written_without_a_spool(void)
{
	struct flowlog fl;
	struct dpi_result f = mkflow("example.com", "TLS");
	struct appblock_decision d = mkdec("web", ABR_ALLOWED, ACT_NONE);

	static const uint8_t mac[6] = { 1, 2, 3, 4, 5, 6 };

	memset(&fl, 0, sizeof(fl));
	/* Classification is separately consented. A device that has not opted
	 * in never gets a spool, and recording must be a silent no-op rather
	 * than an error per packet. */
	flowlog_record(&fl, &f, &d, mac);
	flowlog_flush(&fl);
	CHECK(fl.written == 0, "no spool, nothing written");
	CHECK(fl.n_pending == 0, "and nothing buffered");
}

static void test_wire_reasons_are_stable(void)
{
	CHECK(!strcmp(appblock_reason_wire(ABR_ENFORCED), "enforced"), "enforced");
	CHECK(!strcmp(appblock_reason_wire(ABR_NO_HOST), "no_host"), "no_host");
	CHECK(!strcmp(appblock_reason_wire(ABR_UNKNOWN_APP), "unknown_app"), "unknown_app");
	CHECK(!strcmp(appblock_reason_wire(ABR_NO_SUBJECT), "no_subject"), "no_subject");
	CHECK(!strcmp(appblock_reason_wire(ABR_ALLOWED), "allowed"), "allowed");
	CHECK(!strcmp(appblock_reason_wire(ABR_AMBIGUOUS), "ambiguous"), "ambiguous");
	/* Wire token and syslog prose must not be the same string. */
	CHECK(strcmp(appblock_reason_wire(ABR_AMBIGUOUS),
	             appblock_reason_str(ABR_AMBIGUOUS)) != 0,
	      "the wire token is not the prose");
}

int main(void)
{
	test_record_is_shaped_for_a_consumer();
	test_an_unrecovered_name_is_null_not_empty();
	test_the_batch_reports_its_own_losses();
	test_nothing_is_written_without_a_spool();
	test_wire_reasons_are_stable();
	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
