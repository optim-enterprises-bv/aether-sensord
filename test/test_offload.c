/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Tests for flow-offload detection.
 *
 * The property that matters: "I could not check" must NEVER be reported as
 * "there is no conflict". The failure being guarded against is itself silent,
 * so a guard that fails open reproduces exactly the bug it exists to catch.
 */

#include "../src/offload.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;
#define CHECK(cond, msg)                                                       \
	do {                                                                   \
		checks++;                                                      \
		if (!(cond)) {                                                 \
			failures++;                                            \
			printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);  \
		}                                                              \
	} while (0)

/* Real `nft list flowtables` output, as captured from a live namespace. */
static const char *WITH_FT =
	"table inet fw4 {\n"
	"\tflowtable ft {\n"
	"\t\thook ingress priority filter\n"
	"\t\tdevices = { v0, v1 }\n"
	"\t\tcounter\n"
	"\t}\n"
	"}\n";

static void test_parse(void)
{
	CHECK(offload_parse(WITH_FT) == OFFLOAD_PRESENT,
	      "a real flowtable is detected");
	CHECK(offload_parse("") == OFFLOAD_ABSENT,
	      "empty output means no flowtable, which is a real answer");
	CHECK(offload_parse("table inet fw4 {\n}\n") == OFFLOAD_ABSENT,
	      "a table with no flowtable is absent");
	CHECK(offload_parse(NULL) == OFFLOAD_UNKNOWN,
	      "NULL is UNKNOWN, never ABSENT");

	/* The distinction the whole file exists for. */
	CHECK(OFFLOAD_UNKNOWN != OFFLOAD_ABSENT,
	      "'could not check' and 'no conflict' are different values");

	CHECK(offload_parse("flowtable ft { }") == OFFLOAD_PRESENT,
	      "detected without a surrounding table block");
}

static void test_probe_guards(void)
{
	/* No context and no exec seam must be UNKNOWN, not ABSENT: a probe
	 * that cannot run has not established that inspection works. */
	CHECK(offload_probe(NULL) == OFFLOAD_UNKNOWN,
	      "a NULL context probes UNKNOWN, not ABSENT");
	{
		struct apply_ctx c;

		memset(&c, 0, sizeof(c));
		CHECK(offload_probe(&c) == OFFLOAD_UNKNOWN,
		      "a context with no exec seam probes UNKNOWN");
	}
}

static void test_strings(void)
{
	CHECK(strcmp(offload_state_str(OFFLOAD_PRESENT), "PRESENT") == 0,
	      "the dangerous state is shouted, not whispered");
	CHECK(strlen(offload_state_str(OFFLOAD_ABSENT)) > 0, "absent");
	CHECK(strlen(offload_state_str(OFFLOAD_UNKNOWN)) > 0, "unknown");
	CHECK(strcmp(offload_state_str((enum offload_state)99), "?") == 0,
	      "an unknown value does not read as a real state");
}

int main(void)
{
	test_parse();
	test_probe_guards();
	test_strings();
	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
