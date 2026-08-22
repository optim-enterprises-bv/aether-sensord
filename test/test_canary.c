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

int main(void)
{
	test_only_enforced_passes();
	test_addresses_are_documentation_space();
	test_every_result_is_described();
	test_probe_guards();
	test_run_guards();
	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
