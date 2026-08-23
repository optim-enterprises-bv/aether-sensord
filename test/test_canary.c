/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Tests for the enforcement canary.
 *
 * The canary exists because on 2026-08-22 this daemon reported "Reputation
 * enforcement is live" on a BPI-R4 whose nftables sets did not exist. So the
 * property that matters most here is that the canary itself cannot fail open:
 * every outcome other than ENFORCED must read as "not proven".
 */
#include "../src/canary.h"

#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <string.h>

static int checks, failures;
#define CHECK(c, m) do { checks++; if (!(c)) { failures++; \
	printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, m); } } while (0)

/* Only ENFORCED is a pass. INCONCLUSIVE especially must not be. */
static void test_only_enforced_passes(void)
{
	CHECK(canary_passed(CANARY_ENFORCED), "ENFORCED is a pass");
	CHECK(!canary_passed(CANARY_INCONCLUSIVE),
	      "'could not check' is NOT a pass -- a guard against a silent "
	      "failure must not itself fail open");
	CHECK(!canary_passed(CANARY_SET_MISSING), "SET_MISSING is not a pass");
	CHECK(!canary_passed(CANARY_ADD_REJECTED), "ADD_REJECTED is not a pass");
	CHECK(!canary_passed(CANARY_NOT_HELD), "NOT_HELD is not a pass");
	CHECK(!canary_passed(CANARY_NOT_ENFORCED),
	      "NOT_ENFORCED is not a pass -- this is the state the whole file "
	      "exists to catch");
	CHECK(!canary_passed(CANARY_CLEANUP_FAILED),
	      "CLEANUP_FAILED is not a pass: the canary is still in the set");
}

/* The canary must never be able to collide with real traffic. */
static void test_addresses_are_documentation_space(void)
{
	const char *v4 = canary_addr(false), *v6 = canary_addr(true);

	CHECK(strncmp(v4, "192.0.2.", 8) == 0,
	      "IPv4 canary is in TEST-NET-1 (192.0.2.0/24)");
	CHECK(strncmp(v6, "2001:db8:", 9) == 0,
	      "IPv6 canary is in the documentation prefix");
	CHECK(strcmp(v4, v6) != 0, "the two families differ");
}

/* Every outcome must be distinguishable in a log. */
static void test_every_result_is_described(void)
{
	enum canary_result all[] = { CANARY_ENFORCED, CANARY_SET_MISSING,
		CANARY_ADD_REJECTED, CANARY_NOT_HELD, CANARY_NOT_ENFORCED,
		CANARY_CLEANUP_FAILED, CANARY_INCONCLUSIVE };
	size_t i, j;

	for (i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
		CHECK(strlen(canary_result_str(all[i])) > 0, "has a description");
		for (j = i + 1; j < sizeof(all) / sizeof(all[0]); j++)
			CHECK(strcmp(canary_result_str(all[i]),
			             canary_result_str(all[j])) != 0,
			      "descriptions are distinct, so a log says which");
	}
	CHECK(strcmp(canary_result_str((enum canary_result)99), "?") == 0,
	      "an unknown value does not read as a real result");
}

static void test_probe_guards(void)
{
	CHECK(canary_probe_blocked(NULL, false) == -1, "NULL address refused");
	CHECK(canary_probe_blocked("not-an-address", false) == -1,
	      "unparseable address is inconclusive, not 'blocked'");
	CHECK(canary_probe_blocked("192.0.2.199", true) == -1,
	      "a v4 literal probed as v6 is inconclusive, not 'blocked'");
}

static void test_run_guards(void)
{
	struct nft_target t = { "inet", "fw4", "aether_rep4", "aether_rep6" };

	CHECK(canary_run(NULL, &t, false) == CANARY_INCONCLUSIVE,
	      "no apply context is inconclusive");
	CHECK(canary_run(NULL, NULL, false) == CANARY_INCONCLUSIVE,
	      "no target is inconclusive");
}

/*
 * The tokens the controller parses.
 *
 * These are a contract with `enum Verdict` in aether-aegis::proof, and there is
 * no shared header to enforce it. A rename on either side makes every device
 * report an unparseable verdict, the controller counts them all as silence, and
 * silence is its alarm state -- so the whole fleet would go red while every
 * device was working correctly. Pinning the strings here is the only guard.
 */
static void test_wire_tokens_are_the_contract(void)
{
	CHECK(!strcmp(canary_result_token(CANARY_ENFORCED), "enforced"), "enforced");
	CHECK(!strcmp(canary_result_token(CANARY_SET_MISSING), "set_missing"),
	      "set_missing");
	CHECK(!strcmp(canary_result_token(CANARY_ADD_REJECTED), "add_rejected"),
	      "add_rejected");
	CHECK(!strcmp(canary_result_token(CANARY_NOT_HELD), "not_held"), "not_held");
	CHECK(!strcmp(canary_result_token(CANARY_NOT_ENFORCED), "not_enforced"),
	      "not_enforced");
	CHECK(!strcmp(canary_result_token(CANARY_CLEANUP_FAILED), "cleanup_failed"),
	      "cleanup_failed");
	CHECK(!strcmp(canary_result_token(CANARY_INCONCLUSIVE), "inconclusive"),
	      "inconclusive");

	/* And the token is NOT the human string: the controller parses one and
	 * a person reads the other. Sending the prose would be unparseable. */
	CHECK(strcmp(canary_result_token(CANARY_ENFORCED),
	             canary_result_str(CANARY_ENFORCED)) != 0,
	      "the wire token is not the syslog prose");
}

static char *slurp_one(const char *dir)
{
	static char buf[1024];
	DIR *d = opendir(dir);
	struct dirent *e;
	char path[600];
	FILE *f;

	buf[0] = '\0';
	if (!d)
		return buf;
	while ((e = readdir(d))) {
		if (strncmp(e->d_name, "canary-", 7) != 0)
			continue;
		/* A .partial must never be picked up -- that is the point of
		 * the rename. */
		if (strstr(e->d_name, ".partial"))
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
		f = fopen(path, "r");
		if (f) {
			if (!fgets(buf, sizeof(buf), f))
				buf[0] = '\0';
			fclose(f);
		}
		break;
	}
	closedir(d);
	return buf;
}

static void test_report_writes_a_parseable_record(void)
{
	char dir[] = "/tmp/aether-canary-testXXXXXX";
	char *line;

	if (!mkdtemp(dir)) {
		CHECK(0, "could not create a temporary spool");
		return;
	}

	CHECK(canary_report(dir, "AP-TEST-1", CANARY_NOT_ENFORCED, "aether_rep4",
	                    false) == 0,
	      "report writes");
	line = slurp_one(dir);
	CHECK(strstr(line, "\"result\":\"not_enforced\"") != NULL,
	      "carries the wire token, not the prose");
	CHECK(strstr(line, "\"serial\":\"AP-TEST-1\"") != NULL, "carries the serial");
	CHECK(strstr(line, "\"family\":4") != NULL, "carries the family");
	CHECK(strstr(line, "(a packet") == NULL,
	      "does not ship our prose -- the controller has its own wording");
}

static void test_an_unknown_serial_is_omitted_not_empty(void)
{
	char dir[] = "/tmp/aether-canary-testXXXXXX";
	char *line;

	if (!mkdtemp(dir)) {
		CHECK(0, "could not create a temporary spool");
		return;
	}

	CHECK(canary_report(dir, NULL, CANARY_ENFORCED, "aether_rep4", false) == 0,
	      "report writes without a serial");
	line = slurp_one(dir);
	/*
	 * An empty serial would key a device row on "" in the controller and
	 * quietly merge every unidentified device's verdicts into one fictional
	 * access point that always looks fine.
	 */
	CHECK(strstr(line, "\"serial\"") == NULL,
	      "the key is absent, not empty");
	CHECK(strstr(line, "\"result\":\"enforced\"") != NULL,
	      "the rest of the record is intact");
}

static void test_report_guards(void)
{
	CHECK(canary_report(NULL, "AP-1", CANARY_ENFORCED, "s", false) == -1,
	      "no spool directory is a failure, not a silent success");
	CHECK(canary_report("/proc/nonexistent-aether", "AP-1", CANARY_ENFORCED,
	                    "s", false) == -1,
	      "an unwritable spool is a failure");
}

int main(void)
{
	test_only_enforced_passes();
	test_addresses_are_documentation_space();
	test_every_result_is_described();
	test_probe_guards();
	test_run_guards();
	test_wire_tokens_are_the_contract();
	test_report_writes_a_parseable_record();
	test_an_unknown_serial_is_omitted_not_empty();
	test_report_guards();
	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
