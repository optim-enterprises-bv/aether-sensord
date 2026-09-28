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

/*
 * A newer controller may add keys this build does not know. It must keep
 * working: the alternative is that every device that has not been reflashed
 * discards the message, and the controller reports successful delivery while
 * nothing is applied.
 *
 * `advisory` is the first such key and the one worth an explicit case, because
 * it is a prefix of `add`. find_key matches `"add"` including the closing quote,
 * so `"advisory"` cannot be mistaken for it -- but if that ever changed, the
 * advisory list would be applied as ENFORCED addresses, which is the exact
 * inverse of what the class means. This test is what makes that visible.
 */
static void test_unknown_keys_are_ignored_and_advisory_is_not_add(void)
{
	struct feed_msg m;

	/* A delta carrying an advisory class: the enforced set is `add` alone. */
	CHECK(parse("{\"type\":\"delta\",\"serial\":9,"
	            "\"add\":[\"1.10.16.0/20\"],\"remove\":[],"
	            "\"advisory\":[\"45.155.205.233/32\"]}", &m),
	      "a message with an unknown key still parses");
	CHECK(m.n_add == 1, "one enforced addition");
	CHECK(m.n_remove == 0, "no removals");
	/* The element is a binary address, not the string: compare the parsed
	 * form, so this checks what the kernel would be handed. */
	CHECK(m.add[0].family == 4 && m.add[0].prefix == 20 &&
	          m.add[0].addr[0] == 1 && m.add[0].addr[1] == 10 &&
	          m.add[0].addr[2] == 16 && m.add[0].addr[3] == 0,
	      "the enforced element is the one under `add`, not the advisory one");

	/* The prefix hazard, stated directly: an advisory list must not be read as
	 * an addition list, in either key order. */
	CHECK(parse("{\"type\":\"delta\",\"serial\":10,\"advisory\":[],"
	            "\"add\":[],\"remove\":[]}", &m),
	      "an empty advisory array is harmless");
	CHECK(m.n_add == 0, "an empty advisory is not an empty `add` either way");

	/* And a message made only of keys this build has never seen must still be
	 * usable rather than discarded. */
	CHECK(parse("{\"type\":\"list\",\"serial\":11,\"entries\":[],"
	            "\"something_new\":[1,2,3],\"another\":{\"a\":1}}", &m),
	      "unknown top-level keys do not make a message unusable");
	CHECK(m.type == FEED_MSG_LIST, "and the known parts still parse");
}


/*
 * The advisory class: the counts the apply path depends on.
 *
 * The isolation between `add` and `advisory` is covered by
 * test_unknown_keys_are_ignored_and_advisory_is_not_add. What follows is the
 * rest of the contract the daemon reads: how many elements each class carries
 * on each message type, and that a malformed element is counted rather than
 * silently dropped -- a class that quietly loses entries reads as a class that
 * is empty, and "nothing named" and "everything refused" are not the same
 * statement about the feed.
 */
static void test_advisory_counts_on_both_message_types(void)
{
	struct feed_msg m;
	CHECK(parse("{\"type\":\"delta\",\"serial\":20,"
	            "\"add\":[\"203.0.113.0/24\"],\"remove\":[],"
	            "\"advisory\":[\"198.51.100.0/24\",\"192.0.2.0/24\"]}", &m),
	      "an advisory delta parses");
	CHECK(m.n_add == 1, "one enforced entry");
	CHECK(m.n_advisory == 2, "two advisory entries");

	/* A snapshot carries the class too, and it is the whole class rather than
	 * a delta -- the daemon flushes the advisory table on a snapshot for
	 * exactly that reason. */
	struct feed_msg l;
	CHECK(parse("{\"type\":\"list\",\"serial\":21,"
	            "\"entries\":[\"203.0.113.0/24\"],"
	            "\"advisory\":[\"198.51.100.0/24\"]}", &l),
	      "an advisory snapshot parses");
	CHECK(l.n_add == 1 && l.n_advisory == 1, "one of each");
}

static void test_an_absent_advisory_class_is_zero_not_garbage(void)
{
	struct feed_msg m;
	CHECK(parse("{\"type\":\"delta\",\"serial\":22,\"add\":[],\"remove\":[]}", &m),
	      "a message without the key parses");
	CHECK(m.n_advisory == 0,
	      "an absent class is zero -- reading an uninitialised count here "
	      "would hand the apply path elements nobody sent");
}

static void test_a_bad_advisory_element_is_counted_not_applied(void)
{
	struct feed_msg m;
	CHECK(parse("{\"type\":\"delta\",\"serial\":23,\"add\":[],\"remove\":[],"
	            "\"advisory\":[\"not-an-address\",\"198.51.100.0/24\"]}", &m),
	      "the message parses");
	CHECK(m.n_advisory == 1, "only the valid element is collected");
	CHECK(m.rejected == 1, "the malformed one is counted, not silently dropped");
}


/*
 * The local class: an operator's own block decision.
 *
 * Three properties are load-bearing and each is a way this can go wrong
 * silently:
 *
 *   1. It must not land in `add`. That is the enforced reputation set, and an
 *      operator block is not a fleet observation; merging them would make one
 *      address that an operator chose indistinguishable from one our sensors
 *      scored.
 *   2. It must not land in `advisory`. Advisory is precisely the class nothing
 *      enforces, and a block an operator asked for is meant to be enforced --
 *      putting it in the advisory table would record the decision and never
 *      apply it.
 *   3. `local_remove` must not land in `remove`. `remove` deletes from the
 *      reputation table, so a mis-parse there would unblock an address the
 *      fleet scored hostile while the operator's own un-block was applied to
 *      the wrong table.
 */
static void test_local_class_is_its_own(void)
{
	struct feed_msg m;
	static const char *json =
	    "{\"type\":\"delta\",\"serial\":7,"
	    "\"add\":[\"203.0.113.9\"],"
	    "\"local\":[\"192.168.20.84\"],"
	    "\"local_remove\":[\"192.168.20.99\"]}";

	CHECK(parse(json, &m), "the message parses");
	CHECK(m.n_add == 1, "one enforced element");
	CHECK(m.n_local == 1, "one local element");
	CHECK(m.n_local_remove == 1, "one local removal");
	CHECK(m.n_advisory == 0, "local is not the advisory class");
	CHECK(m.n_remove == 0, "local_remove is not the reputation removal set");

	/* And the addresses themselves went to the right arrays, not merely the
	 * right counts -- a swap between two arrays of the same length would
	 * pass every check above. */
	CHECK(m.local[0].family == 4 && m.local[0].addr[0] == 192 &&
	          m.local[0].addr[1] == 168 && m.local[0].addr[2] == 20 &&
	          m.local[0].addr[3] == 84,
	      "the local element is the local address");
	CHECK(m.add[0].addr[0] == 203 && m.add[0].addr[3] == 9,
	      "the enforced element is the enforced address");
	CHECK(m.local_remove[0].addr[2] == 20 && m.local_remove[0].addr[3] == 99,
	      "the local removal is the local_remove address");
}

/*
 * A device that does not know the key must be unaffected by it.
 *
 * This is what makes the class safe to send before the fleet is reflashed: the
 * controller ships one message shape to every device, and an older daemon must
 * apply the reputation update exactly as it would have and ignore the rest.
 */
static void test_local_class_is_forward_compatible(void)
{
	struct feed_msg m;
	static const char *json =
	    "{\"type\":\"delta\",\"serial\":8,"
	    "\"add\":[\"198.51.100.4\"],"
	    "\"local\":[\"10.0.0.5\"],"
	    "\"unknown_future_key\":[\"10.0.0.6\"],"
	    "\"advisory\":[\"203.0.113.77\"]}";

	CHECK(parse(json, &m), "the message parses");
	CHECK(m.n_add == 1, "the enforced update is unaffected");
	CHECK(m.add[0].addr[0] == 198 && m.add[0].addr[3] == 4,
	      "and it is the right address");
	CHECK(m.n_local == 1, "the local class is read");
	CHECK(m.n_advisory == 1, "the advisory class is read");
	CHECK(m.n_local_remove == 0, "an absent local_remove is zero, not garbage");
}

/*
 * A snapshot carries the whole local class.
 *
 * `list` is the type the controller sends after a gap, and it is authoritative.
 * The local class must survive it -- a snapshot that silently dropped an
 * operator's blocks would unblock them on the next reconnect, and the operator
 * would never be told.
 */
static void test_local_class_rides_a_snapshot(void)
{
	struct feed_msg m;
	static const char *json =
	    "{\"type\":\"list\",\"serial\":9,"
	    "\"entries\":[\"203.0.113.10\"],"
	    "\"local\":[\"192.168.20.84\",\"192.168.20.85\"]}";

	CHECK(parse(json, &m), "the snapshot parses");
	CHECK(m.type == FEED_MSG_LIST, "it is a snapshot");
	/* n_add counts `entries` alone: the local class is deliberately NOT
	 * folded in, so a snapshot cannot inflate the enforced set with
	 * operator decisions. */
	CHECK(m.n_add == 1, "the entries are the enforced set, local excluded");
	CHECK(m.n_local == 2, "and the local class is carried whole");
}

/*
 * `local_remove` is not `local`, and a prefix-pair key must not alias.
 *
 * find_key matches the closing quote, so "local" is not satisfied by
 * "local_remove". If that ever changed, every local removal would also be
 * ADDED as a block -- an operator unblocking a device would block it harder.
 */
static void test_local_remove_does_not_alias_local(void)
{
	struct feed_msg m;
	static const char *json =
	    "{\"type\":\"delta\",\"serial\":10,"
	    "\"local_remove\":[\"192.168.20.99\"]}";

	CHECK(parse(json, &m), "the message parses");
	CHECK(m.n_local == 0, "a local_remove alone adds nothing to local");
	CHECK(m.n_local_remove == 1, "and is counted as a removal");
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
	test_unknown_keys_are_ignored_and_advisory_is_not_add();
	test_local_class_is_its_own();
	test_local_class_is_forward_compatible();
	test_local_class_rides_a_snapshot();
	test_local_remove_does_not_alias_local();
	test_advisory_counts_on_both_message_types();
	test_an_absent_advisory_class_is_zero_not_garbage();
	test_a_bad_advisory_element_is_counted_not_applied();

	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
