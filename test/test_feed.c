/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Host tests for the reputation feed client.
 *
 * The headline case is that a GAP LEAVES THE SET UNTOUCHED. Applying a delta
 * across a hole diverges the device from the controller invisibly from both
 * ends, which is the failure this protocol exists to prevent.
 */

#include "../src/feed.h"

#include <stdio.h>
#include <string.h>

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

static bool parse(const char *s, struct feed_msg *m)
{
	return feed_parse(s, strlen(s), m);
}

/* --------------------------------------------------------- parsing --- */

static void test_parse_delta(void)
{
	struct feed_msg m;
	CHECK(parse("{\"type\":\"delta\",\"serial\":7,"
	            "\"add\":[\"1.10.16.0/20\",\"2.26.75.0/24\"],"
	            "\"remove\":[\"45.155.0.0/16\"]}",
	            &m),
	      "delta parses");
	CHECK(m.type == FEED_MSG_DELTA, "type");
	CHECK(m.serial == 7, "serial");
	CHECK(m.n_add == 2, "two additions");
	CHECK(m.n_remove == 1, "one removal");
	CHECK(m.rejected == 0, "nothing refused");
}

static void test_parse_list(void)
{
	struct feed_msg m;
	CHECK(parse("{\"type\":\"list\",\"serial\":42,"
	            "\"entries\":[\"1.10.16.0/20\"],"
	            "\"attribution\":[\"(c) 2026 The Spamhaus Project SLU\"]}",
	            &m),
	      "list parses");
	CHECK(m.type == FEED_MSG_LIST, "type");
	CHECK(m.serial == 42, "serial");
	CHECK(m.n_add == 1, "one entry");
	/* The attribution string is not an address and must not be mistaken for
	 * one -- it is simply not collected, and it must not inflate rejected
	 * either, since it is in a different array. */
	CHECK(m.rejected == 0, "attribution text is not scanned as an element");
}

static void test_empty_arrays(void)
{
	struct feed_msg m;
	CHECK(parse("{\"type\":\"delta\",\"serial\":1,\"add\":[],\"remove\":[]}", &m),
	      "empty arrays are normal, not an error");
	CHECK(m.n_add == 0 && m.n_remove == 0, "nothing collected");
}

static void test_bad_elements_are_refused_not_fatal(void)
{
	/* One malformed prefix must not discard an otherwise good update. */
	struct feed_msg m;
	CHECK(parse("{\"type\":\"delta\",\"serial\":3,"
	            "\"add\":[\"1.10.16.0/20\",\"not-an-address\",\"45.0.0.0/8\","
	            "\"2.26.75.0/24\"],\"remove\":[]}",
	            &m),
	      "message still usable");
	CHECK(m.n_add == 2, "the two good elements survive");
	CHECK(m.rejected == 2, "the malformed and the over-broad are counted");
}

static void test_hostile_payload_cannot_inject(void)
{
	/* The feed is attacker-influenced. Every string goes through
	 * nft_elem_parse, so shell and nft metacharacters are refused as
	 * elements rather than carried into a command. */
	struct feed_msg m;
	CHECK(parse("{\"type\":\"delta\",\"serial\":5,"
	            "\"add\":[\"1.2.3.0/24; rm -rf /\",\"$(id)\","
	            "\"1.2.3.0/24 }\\nadd rule inet fw4 input accept\"],"
	            "\"remove\":[]}",
	            &m),
	      "message parses");
	CHECK(m.n_add == 0, "NOTHING hostile is collected");
	CHECK(m.rejected == 3, "all three refused and counted");
}

static void test_unusable_messages(void)
{
	struct feed_msg m;
	CHECK(!parse("{\"serial\":1,\"add\":[]}", &m), "no type");
	CHECK(!parse("{\"type\":\"delta\",\"add\":[]}", &m), "no serial");
	CHECK(!parse("{\"type\":\"nonsense\",\"serial\":1}", &m), "unknown type");
	CHECK(!parse("", &m), "empty input");
	CHECK(!feed_parse(NULL, 10, &m), "null input");
}

/* --------------------------------------------------- serial state --- */

static void test_delta_without_baseline_demands_snapshot(void)
{
	struct feed_client c;
	feed_client_init(&c);

	struct feed_msg m;
	parse("{\"type\":\"delta\",\"serial\":1,\"add\":[\"1.10.16.0/20\"],"
	      "\"remove\":[]}",
	      &m);
	CHECK(feed_client_accept(&c, &m) == FEED_RESYNC_REQUIRED,
	      "no baseline -> resync, never apply");
	CHECK(feed_client_needs_resync(&c), "and it says so");
}

static void test_ordered_deltas_apply(void)
{
	struct feed_client c;
	feed_client_init(&c);
	struct feed_msg m;

	parse("{\"type\":\"list\",\"serial\":1,\"entries\":[\"1.10.16.0/20\"]}", &m);
	CHECK(feed_client_accept(&c, &m) == FEED_APPLIED, "snapshot applies");

	parse("{\"type\":\"delta\",\"serial\":2,\"add\":[\"2.26.75.0/24\"],"
	      "\"remove\":[]}",
	      &m);
	CHECK(feed_client_accept(&c, &m) == FEED_APPLIED, "serial 2 applies");

	parse("{\"type\":\"delta\",\"serial\":3,\"add\":[],"
	      "\"remove\":[\"1.10.16.0/20\"]}",
	      &m);
	CHECK(feed_client_accept(&c, &m) == FEED_APPLIED, "serial 3 applies");
	CHECK(c.serial == 3, "serial tracks");
	CHECK(c.applied_deltas == 2, "counted");
}

static void test_gap_demands_resync_and_changes_nothing(void)
{
	/* THE headline. */
	struct feed_client c;
	feed_client_init(&c);
	struct feed_msg m;

	parse("{\"type\":\"list\",\"serial\":1,\"entries\":[\"1.10.16.0/20\"]}", &m);
	feed_client_accept(&c, &m);

	/* serials 2, 3, 4 missed; 5 arrives */
	parse("{\"type\":\"delta\",\"serial\":5,\"add\":[\"9.9.9.0/24\"],"
	      "\"remove\":[]}",
	      &m);
	CHECK(feed_client_accept(&c, &m) == FEED_RESYNC_REQUIRED, "gap detected");
	CHECK(c.serial == 1, "serial NOT advanced -- the delta was not applied");
	CHECK(c.missed == 3, "three missed counted");
}

static void test_replayed_delta_is_stale(void)
{
	struct feed_client c;
	feed_client_init(&c);
	struct feed_msg m;

	parse("{\"type\":\"list\",\"serial\":5,\"entries\":[]}", &m);
	feed_client_accept(&c, &m);

	parse("{\"type\":\"delta\",\"serial\":3,\"add\":[],\"remove\":[]}", &m);
	CHECK(feed_client_accept(&c, &m) == FEED_STALE, "older serial is stale");
	parse("{\"type\":\"delta\",\"serial\":5,\"add\":[],\"remove\":[]}", &m);
	CHECK(feed_client_accept(&c, &m) == FEED_STALE, "same serial is stale");
	CHECK(c.serial == 5, "serial unmoved");
}

static void test_snapshot_recovers_from_a_long_outage(void)
{
	struct feed_client c;
	feed_client_init(&c);
	struct feed_msg m;

	parse("{\"type\":\"list\",\"serial\":1,\"entries\":[]}", &m);
	feed_client_accept(&c, &m);

	parse("{\"type\":\"delta\",\"serial\":900,\"add\":[],\"remove\":[]}", &m);
	CHECK(feed_client_accept(&c, &m) == FEED_RESYNC_REQUIRED, "huge gap");
	CHECK(c.missed == FEED_MISSING_LIMIT, "missed is clamped, not overflowed");

	parse("{\"type\":\"list\",\"serial\":900,\"entries\":[\"1.10.16.0/20\"]}", &m);
	CHECK(feed_client_accept(&c, &m) == FEED_APPLIED, "snapshot recovers");
	CHECK(c.serial == 900, "converged on the controller's serial");
	CHECK(!feed_client_needs_resync(&c), "no longer needs resync");
}

static void test_overflow_is_counted(void)
{
	/* Build a message with more elements than the bound. */
	static char big[64 * 1024];
	size_t n = (size_t)snprintf(big, sizeof(big),
	                            "{\"type\":\"list\",\"serial\":1,\"entries\":[");
	for (int i = 0; i < FEED_MAX_ELEMS + 20; i++)
		n += (size_t)snprintf(big + n, sizeof(big) - n, "%s\"10.%d.%d.0/24\"",
		                      i ? "," : "", (i / 256) % 256, i % 256);
	snprintf(big + n, sizeof(big) - n, "]}");

	struct feed_msg m;
	CHECK(feed_parse(big, strlen(big), &m), "parses");
	CHECK(m.n_add == FEED_MAX_ELEMS, "bounded at the cap");
	CHECK(m.overflowed == 20, "overflow refused AND counted");
}

int main(void)
{
	test_parse_delta();
	test_parse_list();
	test_empty_arrays();
	test_bad_elements_are_refused_not_fatal();
	test_hostile_payload_cannot_inject();
	test_unusable_messages();
	test_delta_without_baseline_demands_snapshot();
	test_ordered_deltas_apply();
	test_gap_demands_resync_and_changes_nothing();
	test_replayed_delta_is_stale();
	test_snapshot_recovers_from_a_long_outage();
	test_overflow_is_counted();

	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
