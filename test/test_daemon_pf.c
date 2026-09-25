/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Host tests for the daemon shell: config parsing and the spool pass.
 *
 * The config tests are about a specific failure: a key that was written wrongly
 * and silently ignored leaves the daemon enforcing into the WRONG TABLE, which
 * looks identical to working from every counter. So refusals are asserted, and
 * the default for a typo'd key is NOT "quietly keep the default".
 *
 * The spool tests are about ORDER. The transport names files so that
 * lexicographic order is serial order; applying a higher serial first makes the
 * lower one STALE and silently drops it. A daemon that looped in readdir order
 * would work most of the time, which is the worst kind of bug here.
 */

#include "../src/daemon_pf.h"
#include "../src/feed_pf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * The spool pass creates its temp directory with mkdtemp, which is POSIX rather
 * than C11. Declared here so the strict-c11 build works on both glibc and
 * FreeBSD without depending on a feature-test macro.
 */
char *mkdtemp(char *template);

/* The sequence of elements the fake was asked to add, in call order. */
static char g_applied[16][64];
static size_t g_applied_n;

static int failures;
static int checks;

#define CHECK(cond, msg)                                                       \
	do {                                                                   \
		checks++;                                                      \
		if (!(cond)) {                                                 \
			failures++;                                            \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__,          \
			        __LINE__, (msg));                              \
		}                                                              \
	} while (0)

/* ----------------------------------------------------------- config --- */

static void test_defaults_are_safe(void)
{
	struct dpf_config c;
	dpf_config_defaults(&c);

	CHECK(strcmp(c.table, PF_TABLE_NAME_DEFAULT) == 0,
	      "the default table matches the canary's, so the two cannot disagree");
	CHECK(c.spool_dir[0] != '\0', "a default spool exists");
	CHECK(c.interval_sec >= 1, "a sane poll interval");
	CHECK(c.canary_enabled, "the canary is on by default");
	CHECK(!c.tolerant,
	      "intolerant by default: a running daemon that is not enforcing is "
	      "worse than a stopped one, because only the stopped one is noticed");
	CHECK(dpf_config_can_enforce(&c), "the defaults can enforce");
}

static void test_config_parses_the_documented_keys(void)
{
	struct dpf_config c;
	unsigned line = 0;
	static const char *text =
		"# a config\n"
		"\n"
		"spool_dir = /tmp/in\n"
		"table = \"aisense_rep4\"\n"
		"table_v6 = aisense_rep6\n"
		"spool_out = /tmp/out\n"
		"serial = TEST-1\n"
		"interval_sec = 30\n"
		"canary = off\n"
		"tolerant = true\n";

	dpf_config_defaults(&c);
	CHECK(dpf_config_parse(&c, text, strlen(text), &line) == DPF_CFG_OK,
	      "the documented keys all parse");
	CHECK(strcmp(c.spool_dir, "/tmp/in") == 0, "spool_dir");
	CHECK(strcmp(c.table, "aisense_rep4") == 0, "table, quotes stripped");
	CHECK(strcmp(c.table_v6, "aisense_rep6") == 0, "table_v6");
	CHECK(strcmp(c.spool_out, "/tmp/out") == 0, "spool_out");
	CHECK(strcmp(c.serial, "TEST-1") == 0, "serial");
	CHECK(c.interval_sec == 30, "interval_sec");
	CHECK(!c.canary_enabled, "canary off");
	CHECK(c.tolerant, "tolerant on");
}

static void test_a_typo_is_reported_not_ignored(void)
{
	/*
	 * THE failure this exists for. `tabel = aisense_x` would otherwise leave
	 * the default in place and the daemon would enforce into a table nobody
	 * declared -- reported as healthy by every counter.
	 */
	struct dpf_config c;
	unsigned line = 0;
	static const char *text = "tabel = aisense_rep4\n";

	dpf_config_defaults(&c);
	CHECK(dpf_config_parse(&c, text, strlen(text), &line) == DPF_CFG_UNKNOWN_KEY,
	      "a misspelled key is refused");
	CHECK(line == 1, "and the line is reported");

	/* A missing '=' is the other shape of the same mistake. */
	line = 0;
	CHECK(dpf_config_parse(&c, "table aisense_rep4\n", 20, &line) ==
	      DPF_CFG_BAD_VALUE, "a line with no '=' is refused");
	CHECK(line == 1, "and the line is reported");
}

static void test_unusable_values_are_refused(void)
{
	struct dpf_config c;
	unsigned line = 0;

	dpf_config_defaults(&c);
	CHECK(dpf_config_parse(&c, "interval_sec = 0\n", 17, &line) ==
	      DPF_CFG_BAD_VALUE, "interval 0 refused");
	CHECK(dpf_config_parse(&c, "interval_sec = 99999\n", 20, &line) ==
	      DPF_CFG_BAD_VALUE, "absurd interval refused");
	CHECK(dpf_config_parse(&c, "interval_sec = abc\n", 18, &line) ==
	      DPF_CFG_BAD_VALUE, "non-numeric interval refused");
	CHECK(dpf_config_parse(&c, "canary = maybe\n", 15, &line) ==
	      DPF_CFG_BAD_VALUE, "non-boolean refused");
	CHECK(dpf_config_parse(&c, "tolerant = perhaps\n", 18, &line) ==
	      DPF_CFG_BAD_VALUE, "non-boolean refused");
}

static void test_an_over_long_value_is_refused_not_truncated(void)
{
	/*
	 * Truncating the table name would change which table is enforced into,
	 * and the result would still be a valid name -- so nothing downstream
	 * could notice. Refuse instead.
	 */
	struct dpf_config c;
	unsigned line = 0;
	char text[512];
	char value[400];

	memset(value, 'a', sizeof(value) - 1);
	value[sizeof(value) - 1] = '\0';
	snprintf(text, sizeof(text), "table = %s\n", value);

	dpf_config_defaults(&c);
	CHECK(dpf_config_parse(&c, text, strlen(text), &line) == DPF_CFG_BAD_VALUE,
	      "an over-long table name is refused, not truncated");
	CHECK(strcmp(c.table, PF_TABLE_NAME_DEFAULT) == 0,
	      "and the old value is left intact rather than half-replaced");
}

static void test_can_enforce_reflects_reality(void)
{
	struct dpf_config c;

	dpf_config_defaults(&c);
	CHECK(dpf_config_can_enforce(&c), "defaults can enforce");

	snprintf(c.table, sizeof(c.table), "bad name");
	CHECK(!dpf_config_can_enforce(&c),
	      "a table name that pfctl would reject means we cannot enforce");

	dpf_config_defaults(&c);
	c.spool_dir[0] = '\0';
	CHECK(!dpf_config_can_enforce(&c), "no spool means nothing to apply");
}

/* ------------------------------------------------------- spool pass --- */

/* A fake pfctl for the pass tests: enough to make an apply succeed. */
static int pass_fake_exec(const char *argv0, const char *const *argv, char *out,
                          size_t out_len, void *ctx)
{
	size_t argc = 0;
	const char *verb = NULL;
	(void)argv0;
	(void)ctx;

	for (size_t i = 0; argv[i]; i++)
		argc++;
	if (argc >= 5)
		verb = argv[4];

	if (out && out_len)
		out[0] = '\0';

	if (argc == 3 && strcmp(argv[1], "-s") == 0) {
		/* The ruleset references the table, so verification passes. */
		if (out && out_len)
			snprintf(out, out_len,
			         "block drop quick from <aisense_rep4> to any\n");
		return 0;
	}

	if (verb && strcmp(verb, "add") == 0 && argc > 5) {
		/* Record the ELEMENT applied, so a test can prove the order. */
		if (g_applied_n < sizeof(g_applied) / sizeof(g_applied[0]))
			snprintf(g_applied[g_applied_n++], sizeof(g_applied[0]),
			         "%s", argv[5]);
	}

	if (verb && strcmp(verb, "show") == 0) {
		if (out && out_len)
			snprintf(out, out_len,
			         "192.0.2.0/24\n198.51.100.0/24\n203.0.113.0/24\n");
		return 0;
	}
	return 0;
}


static bool make_dir(char *out, size_t out_len)
{
	/*
	 * Fresh template each time: mkdtemp rewrites its argument in place, so a
	 * shared template is destroyed by the first call and every later test gets
	 * a directory that does not exist.
	 */
	snprintf(out, out_len, "/tmp/dpftestXXXXXX");
	return mkdtemp(out) != NULL;
}

static void write_msg(const char *dir, const char *name, const char *body)
{
	char path[512];
	FILE *f;
	snprintf(path, sizeof(path), "%s/%s", dir, name);
	f = fopen(path, "w");
	if (!f)
		return;
	fputs(body, f);
	fclose(f);
}

static bool exists(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0;
}

static void test_startup_gate_refuses_silent_non_enforcement(void)
{
	/*
	 * THE regression this function exists for. An early version treated
	 * "table does not exist" as survivable, reasoning that the first apply
	 * would create it. It does -- `pfctl -t <undeclared> -T add` returns 0
	 * and creates the table -- so the daemon would run, log that it applied
	 * every message, and drop nothing at all.
	 */
	CHECK(dpf_startup_gate(PF_CANARY_TABLE_MISSING, true) ==
	      DPF_GATE_REFUSE_TABLE_MISSING,
	      "a missing table is refused, not tolerated -- applying would create "
	      "it silently and enforce nothing");
	CHECK(dpf_startup_gate(PF_CANARY_NOT_ENFORCED, true) ==
	      DPF_GATE_REFUSE_NOT_REFERENCED,
	      "a referenced-less table is refused");
	CHECK(dpf_startup_gate(PF_CANARY_ENFORCED, true) == DPF_GATE_PROCEED,
	      "a proven-enforcing table proceeds");

	/* Not proven bad, not proven good: proceed, but never claim health. */
	CHECK(dpf_startup_gate(PF_CANARY_INCONCLUSIVE, true) ==
	      DPF_GATE_PROCEED_UNVERIFIED,
	      "an inconclusive canary proceeds as UNVERIFIED");
	CHECK(dpf_startup_gate(PF_CANARY_ADD_REJECTED, true) ==
	      DPF_GATE_PROCEED_UNVERIFIED,
	      "a rejected canary write proceeds as UNVERIFIED");
	CHECK(dpf_startup_gate(PF_CANARY_NOT_HELD, true) ==
	      DPF_GATE_PROCEED_UNVERIFIED,
	      "elements that did not land proceed as UNVERIFIED");

	/* With the canary off there is no verdict to act on. */
	CHECK(dpf_startup_gate(PF_CANARY_NOT_ENFORCED, false) ==
	      DPF_GATE_PROCEED,
	      "canary off means no gate, whatever the verdict says");

	/* Every refusal must be distinguishable in a log line. */
	CHECK(strcmp(dpf_gate_str(DPF_GATE_REFUSE_TABLE_MISSING),
	             dpf_gate_str(DPF_GATE_REFUSE_NOT_REFERENCED)) != 0,
	      "the two refusals read differently, because the fixes differ");
	CHECK(strstr(dpf_gate_str(DPF_GATE_PROCEED_UNVERIFIED), "unverified") !=
	      NULL,
	      "'unverified' says what it is rather than implying health");
}

static void test_a_pass_applies_and_removes_the_file(void)
{
	char dir[256];
	struct dpf_config c;
	struct pf_apply_ctx ap;
	struct feed_client fc;
	struct dpf_pass_stats st;
	char path[512];

	CHECK(make_dir(dir, sizeof(dir)), "temp dir");

	dpf_config_defaults(&c);
	snprintf(c.spool_dir, sizeof(c.spool_dir), "%s", dir);
	pf_apply_ctx_init(&ap, pass_fake_exec, NULL);
	feed_client_init(&fc);

	write_msg(dir, "000000001.json",
	          "{\"type\":\"list\",\"serial\":1,\"entries\":[\"192.0.2.0/24\"]}");

	CHECK(dpf_run_pass(&c, &ap, &fc, &st) == 1, "one message applied");
	CHECK(st.seen == 1, "one seen");
	CHECK(st.applied == 1, "one applied");
	CHECK(st.stale == 0 && st.resync == 0, "no skips");

	snprintf(path, sizeof(path), "%s/000000001.json", dir);
	CHECK(!exists(path), "an applied message is removed from the spool");

	rmdir(dir);
}

static void test_files_are_applied_in_serial_order_not_readdir_order(void)
{
	/*
	 * THE ordering test, and it has to assert the SEQUENCE rather than a
	 * count: all three messages apply either way, so a count cannot tell a
	 * sorted pass from an unsorted one.
	 *
	 * Measured: readdir returns a hash order (for these names it happened to
	 * be 10, 5, 1), and the transport names files so lexicographic order is
	 * serial order. Applying serial 3 before 1 would classify the later
	 * arrival (serial 1) as STALE and silently drop an update -- and every
	 * counter would still read "applied", which is why this is a silent
	 * failure rather than a visible one.
	 */
	char dir[256];
	struct dpf_config c;
	struct pf_apply_ctx ap;
	struct feed_client fc;
	struct dpf_pass_stats st;

	CHECK(make_dir(dir, sizeof(dir)), "temp dir");
	memset(g_applied, 0, sizeof(g_applied));
	g_applied_n = 0;

	dpf_config_defaults(&c);
	snprintf(c.spool_dir, sizeof(c.spool_dir), "%s", dir);
	pf_apply_ctx_init(&ap, pass_fake_exec, NULL);
	feed_client_init(&fc);

	/* Created in jumbled order; the serial each file carries is in its name. */
	write_msg(dir, "000000010.json",
	          "{\"type\":\"delta\",\"serial\":3,\"add\":[\"203.0.113.0/24\"]}");
	write_msg(dir, "000000001.json",
	          "{\"type\":\"list\",\"serial\":1,\"entries\":[\"192.0.2.0/24\"]}");
	write_msg(dir, "000000005.json",
	          "{\"type\":\"delta\",\"serial\":2,\"add\":[\"198.51.100.0/24\"]}");

	dpf_run_pass(&c, &ap, &fc, &st);

	CHECK(st.applied == 3, "all three apply");
	CHECK(st.stale == 0, "and none is classified stale");
	CHECK(fc.serial == 3, "the client ends at the highest serial");

	/* THE assertion: serial order, not directory order. */
	CHECK(g_applied_n == 3, "three adds were issued");
	CHECK(g_applied_n == 3 && strcmp(g_applied[0], "192.0.2.0/24") == 0,
	      "serial 1's element went first");
	CHECK(g_applied_n == 3 && strcmp(g_applied[1], "198.51.100.0/24") == 0,
	      "then serial 2's");
	CHECK(g_applied_n == 3 && strcmp(g_applied[2], "203.0.113.0/24") == 0,
	      "then serial 3's -- i.e. sorted, not the filesystem's order");
}

static void test_an_out_of_order_file_is_stale_not_reapplied(void)
{
	/*
	 * The consequence of getting the order wrong, isolated: a message whose
	 * serial is BELOW what has already been applied is ignored. That is
	 * correct for a re-delivery, and it is exactly why the sort matters --
	 * drop the sort and this outcome swallows a genuinely new update.
	 */
	char dir[256];
	struct dpf_config c;
	struct pf_apply_ctx ap;
	struct feed_client fc;
	struct dpf_pass_stats st;

	CHECK(make_dir(dir, sizeof(dir)), "temp dir");

	dpf_config_defaults(&c);
	snprintf(c.spool_dir, sizeof(c.spool_dir), "%s", dir);
	pf_apply_ctx_init(&ap, pass_fake_exec, NULL);
	feed_client_init(&fc);

	/* Apply serial 2 first, directly, so the client is ahead. */
	write_msg(dir, "000000002.json",
	          "{\"type\":\"list\",\"serial\":2,\"entries\":[\"192.0.2.0/24\"]}");
	dpf_run_pass(&c, &ap, &fc, &st);
	CHECK(st.applied == 1, "baseline at serial 2");

	/* Now a lower serial arrives -- a re-delivery. */
	write_msg(dir, "000000001.json",
	          "{\"type\":\"delta\",\"serial\":1,\"add\":[\"203.0.113.0/24\"]}");
	dpf_run_pass(&c, &ap, &fc, &st);
	CHECK(st.stale == 1, "a below-watermark serial is stale");
	CHECK(st.applied == 0, "and is not applied");
}

static void test_a_gap_leaves_the_table_alone(void)
{
	char dir[256];
	struct dpf_config c;
	struct pf_apply_ctx ap;
	struct feed_client fc;
	struct dpf_pass_stats st;
	uint64_t batches_before;

	CHECK(make_dir(dir, sizeof(dir)), "temp dir");

	dpf_config_defaults(&c);
	snprintf(c.spool_dir, sizeof(c.spool_dir), "%s", dir);
	pf_apply_ctx_init(&ap, pass_fake_exec, NULL);
	feed_client_init(&fc);

	/* Establish a baseline, then jump a serial: a gap. */
	write_msg(dir, "000000001.json",
	          "{\"type\":\"list\",\"serial\":1,\"entries\":[\"192.0.2.0/24\"]}");
	dpf_run_pass(&c, &ap, &fc, &st);
	CHECK(st.applied == 1, "baseline applied");

	batches_before = ap.applied_batches;
	write_msg(dir, "000000050.json",
	          "{\"type\":\"delta\",\"serial\":50,\"add\":[\"203.0.113.0/24\"]}");
	dpf_run_pass(&c, &ap, &fc, &st);

	CHECK(st.resync == 1, "the gap demands a resync");
	CHECK(st.applied == 0, "nothing from the gapped message is applied");
	CHECK(ap.applied_batches == batches_before,
	      "no batch was written -- the table is left untouched");
	CHECK(fc.missed > 0, "the miss is recorded so silence is not mistaken "
	                     "for agreement");
}

static void test_unparseable_is_discarded_not_retried(void)
{
	/*
	 * Retrying an unparseable message would block every later one behind it.
	 * The resync protocol is what recovers a lost update.
	 */
	char dir[256];
	struct dpf_config c;
	struct pf_apply_ctx ap;
	struct feed_client fc;
	struct dpf_pass_stats st;
	char path[512];

	CHECK(make_dir(dir, sizeof(dir)), "temp dir");

	dpf_config_defaults(&c);
	snprintf(c.spool_dir, sizeof(c.spool_dir), "%s", dir);
	pf_apply_ctx_init(&ap, pass_fake_exec, NULL);
	feed_client_init(&fc);

	write_msg(dir, "000000001.json", "this is not json at all");
	dpf_run_pass(&c, &ap, &fc, &st);

	CHECK(st.unusable == 1, "counted as unusable");
	snprintf(path, sizeof(path), "%s/000000001.json", dir);
	CHECK(!exists(path), "and removed, so it cannot block the queue");
}

static void test_a_failed_apply_retains_the_file(void)
{
	/*
	 * The serial advanced in memory but the kernel did not take it, so a
	 * restart must retry rather than skip. Losing it here would leave a
	 * permanent silent divergence from the controller.
	 */
	char dir[256];
	struct dpf_config c;
	struct pf_apply_ctx ap;
	struct feed_client fc;
	struct dpf_pass_stats st;
	char path[512];

	CHECK(make_dir(dir, sizeof(dir)), "temp dir");

	dpf_config_defaults(&c);
	snprintf(c.spool_dir, sizeof(c.spool_dir), "%s", dir);
	/* An exec that refuses everything. */
	pf_apply_ctx_init(&ap, NULL, NULL); /* no exec -> UNAVAILABLE */
	feed_client_init(&fc);

	write_msg(dir, "000000001.json",
	          "{\"type\":\"list\",\"serial\":1,\"entries\":[\"192.0.2.0/24\"]}");
	dpf_run_pass(&c, &ap, &fc, &st);

	CHECK(st.failed == 1, "the apply failed");
	CHECK(st.retained == 1, "and the message is retained");
	snprintf(path, sizeof(path), "%s/000000001.json", dir);
	CHECK(exists(path), "the file is still there for a retry");
}

static void test_ignores_non_json_and_dotfiles(void)
{
	char dir[256];
	struct dpf_config c;
	struct pf_apply_ctx ap;
	struct feed_client fc;
	struct dpf_pass_stats st;

	CHECK(make_dir(dir, sizeof(dir)), "temp dir");

	dpf_config_defaults(&c);
	snprintf(c.spool_dir, sizeof(c.spool_dir), "%s", dir);
	pf_apply_ctx_init(&ap, pass_fake_exec, NULL);
	feed_client_init(&fc);

	write_msg(dir, ".partial", "{\"type\":\"list\",\"serial\":9}");
	write_msg(dir, "notes.txt", "hello");
	write_msg(dir, "000000001.json",
	          "{\"type\":\"list\",\"serial\":1,\"entries\":[\"192.0.2.0/24\"]}");

	dpf_run_pass(&c, &ap, &fc, &st);
	CHECK(st.seen == 1, "only the .json file is considered");
	CHECK(st.applied == 1, "and it applied");
}

static void test_missing_spool_is_not_an_error(void)
{
	struct dpf_config c;
	struct pf_apply_ctx ap;
	struct feed_client fc;
	struct dpf_pass_stats st;

	dpf_config_defaults(&c);
	snprintf(c.spool_dir, sizeof(c.spool_dir), "/nonexistent/spool/dir");
	pf_apply_ctx_init(&ap, pass_fake_exec, NULL);
	feed_client_init(&fc);

	CHECK(dpf_run_pass(&c, &ap, &fc, &st) == 0,
	      "a spool that does not exist yet is not a failure");
	CHECK(st.seen == 0, "nothing seen");
}

int main(void)
{
	test_defaults_are_safe();
	test_config_parses_the_documented_keys();
	test_a_typo_is_reported_not_ignored();
	test_unusable_values_are_refused();
	test_an_over_long_value_is_refused_not_truncated();
	test_can_enforce_reflects_reality();
	test_startup_gate_refuses_silent_non_enforcement();
	test_a_pass_applies_and_removes_the_file();
	test_files_are_applied_in_serial_order_not_readdir_order();
	test_an_out_of_order_file_is_stale_not_reapplied();
	test_a_gap_leaves_the_table_alone();
	test_unparseable_is_discarded_not_retried();
	test_a_failed_apply_retains_the_file();
	test_ignores_non_json_and_dotfiles();
	test_missing_spool_is_not_an_error();

	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
