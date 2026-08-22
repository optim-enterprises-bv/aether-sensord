/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Host tests for apply + verify, with a fake exec.
 *
 * The headline case: nft returning 0 must NOT be sufficient. Every test here
 * that matters drives a fake nft which succeeds while the kernel holds nothing,
 * because that is precisely the shape ADR-017 says a successful config push
 * cannot be distinguished from.
 */

#include "../src/apply.h"

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

static const struct nft_target TGT = { "inet", "fw4", "aether_rep4",
	                               "aether_rep6" };

/* A scriptable fake nft. */
struct fake {
	int apply_status;   /* what `nft -f -` returns */
	int list_status;    /* what `nft list set` returns */
	const char *list_output;
	char last_stdin[4096];
	int apply_calls;
	int list_calls;
};

static int fake_exec(const char *argv0, const char *const *argv,
                     const char *stdin_data, char *out, size_t out_len,
                     void *ctx)
{
	struct fake *f = ctx;
	(void)argv0;
	bool is_list = argv[1] && strcmp(argv[1], "list") == 0;

	if (is_list) {
		f->list_calls++;
		if (out && out_len && f->list_output)
			snprintf(out, out_len, "%s", f->list_output);
		return f->list_status;
	}

	f->apply_calls++;
	if (stdin_data)
		snprintf(f->last_stdin, sizeof(f->last_stdin), "%s", stdin_data);
	if (out && out_len)
		snprintf(out, out_len, "%s", f->apply_status ? "Error: syntax" : "");
	return f->apply_status;
}

static void setup(struct apply_ctx *c, struct fake *f)
{
	memset(f, 0, sizeof(*f));
	apply_ctx_init(c, fake_exec, f);
}

/* ------------------------------------------------------- headline --- */

static void test_success_from_nft_is_not_enough(void)
{
	/* nft accepts the batch and the set is EMPTY. A caller trusting the
	 * exit code would report enforcement working. */
	struct apply_ctx c;
	struct fake f;
	setup(&c, &f);
	f.apply_status = 0;
	f.list_status = 0;
	f.list_output = "table inet fw4 {\n\tset aether_rep4 {\n\t\ttype ipv4_addr\n\t}\n}";

	char err[256];
	CHECK(apply_commands(&c, "add element inet fw4 aether_rep4 { 1.2.0.0/16 }",
	                     err, sizeof(err)) == APPLY_OK,
	      "nft says yes");

	bool ok = apply_and_verify(&c, &TGT,
	                           "add element inet fw4 aether_rep4 { 1.2.0.0/16 }",
	                           false, 1, err, sizeof(err));
	CHECK(!ok, "but verification FAILS -- the set is empty");
	CHECK(c.verify_mismatches == 1, "counted as a mismatch");
	CHECK(strstr(err, "holds 0 elements") != NULL, "error names the shortfall");
}

static void test_missing_set_is_caught(void)
{
	/* The worst case: nft applied cleanly into a set that does not exist.
	 * `list set` fails, and that must not read as "zero elements". */
	struct apply_ctx c;
	struct fake f;
	setup(&c, &f);
	f.apply_status = 0;
	f.list_status = 1; /* No such file or directory */
	f.list_output = "Error: No such file or directory";

	CHECK(apply_count_set(&c, &TGT, false) == -1,
	      "unreadable set is -1, not 0");

	char err[256];
	CHECK(!apply_and_verify(&c, &TGT, "add element ...", false, 1, err,
	                        sizeof(err)),
	      "verification fails");
	CHECK(strstr(err, "may not exist") != NULL, "error says what to look at");
	CHECK(strstr(err, "Applied is not enforced") != NULL,
	      "and says why that matters");
}

static void test_verified_success(void)
{
	struct apply_ctx c;
	struct fake f;
	setup(&c, &f);
	f.apply_status = 0;
	f.list_status = 0;
	f.list_output = "table inet fw4 {\n\tset aether_rep4 {\n"
	                "\t\telements = { 1.10.16.0/20, 2.26.75.0/24, 45.155.0.0/16 }\n"
	                "\t}\n}";

	char err[256];
	CHECK(apply_and_verify(&c, &TGT, "add element ...", false, 3, err,
	                       sizeof(err)),
	      "three elements present, three expected");
	CHECK(c.applied_batches == 1, "counted");
	CHECK(c.verify_mismatches == 0, "no mismatch");
}

static void test_auto_merge_shrinkage_is_tolerated(void)
{
	/* auto-merge legitimately collapses overlapping prefixes, so the kernel
	 * may hold fewer entries than we sent. An exact comparison would fail on
	 * correct behaviour. */
	struct apply_ctx c;
	struct fake f;
	setup(&c, &f);
	f.apply_status = 0;
	f.list_status = 0;
	f.list_output = "set aether_rep4 { elements = { 1.2.0.0/16 } }";

	char err[256];
	CHECK(apply_and_verify(&c, &TGT, "add ...", false, 1, err, sizeof(err)),
	      "a floor of 1 is met even though we sent 3 overlapping prefixes");
}

/* ---------------------------------------------------------- errors --- */

static void test_nft_rejection_is_distinct_from_absence(void)
{
	/* An operator responds differently to "nft refused our syntax" and
	 * "nft is not installed". */
	struct apply_ctx c;
	struct fake f;
	char err[256];

	setup(&c, &f);
	f.apply_status = 1;
	CHECK(apply_commands(&c, "garbage", err, sizeof(err)) == APPLY_REJECTED,
	      "non-zero status is a rejection");
	CHECK(strstr(err, "rejected") != NULL, "error says so");
	CHECK(c.failed_batches == 1, "counted");

	setup(&c, &f);
	f.apply_status = -1;
	CHECK(apply_commands(&c, "anything", err, sizeof(err)) == APPLY_UNAVAILABLE,
	      "-1 is the tool being absent");
	CHECK(strstr(err, "cannot run") != NULL, "error distinguishes it");
}

static void test_empty_batch_is_not_a_failure(void)
{
	struct apply_ctx c;
	struct fake f;
	setup(&c, &f);
	char err[256];
	CHECK(apply_commands(&c, "", err, sizeof(err)) == APPLY_OK,
	      "nothing to do is fine");
	CHECK(f.apply_calls == 0, "and nft is not invoked for it");
}

static void test_commands_reach_nft_verbatim(void)
{
	struct apply_ctx c;
	struct fake f;
	setup(&c, &f);
	f.apply_status = 0;
	char err[256];
	const char *cmd = "add element inet fw4 aether_rep4 { 1.10.16.0/20 }\n";
	apply_commands(&c, cmd, err, sizeof(err));
	CHECK(strcmp(f.last_stdin, cmd) == 0,
	      "the rendered batch is what nft receives, unmodified");
	CHECK(f.apply_calls == 1, "one invocation -- the batch is one transaction");
}

static void test_count_parsing(void)
{
	struct apply_ctx c;
	struct fake f;
	setup(&c, &f);
	f.list_status = 0;

	f.list_output = "set s { elements = { 1.2.0.0/16 } }";
	CHECK(apply_count_set(&c, &TGT, false) == 1, "one element");

	f.list_output = "set s { elements = { 1.2.0.0/16, 3.4.0.0/16 } }";
	CHECK(apply_count_set(&c, &TGT, false) == 2, "two elements");

	f.list_output = "set s { elements = { } }";
	CHECK(apply_count_set(&c, &TGT, false) == 0, "explicitly empty");

	f.list_output = "set s { type ipv4_addr }";
	CHECK(apply_count_set(&c, &TGT, false) == 0, "no elements block");

	f.list_output = "set s {\n elements = { 1.2.0.0/16,\n 3.4.0.0/16,\n"
	                " 5.6.0.0/16 }\n}";
	CHECK(apply_count_set(&c, &TGT, false) == 3, "multi-line output");
}

int main(void)
{
	test_success_from_nft_is_not_enough();
	test_missing_set_is_caught();
	test_verified_success();
	test_auto_merge_shrinkage_is_tolerated();
	test_nft_rejection_is_distinct_from_absence();
	test_empty_batch_is_not_a_failure();
	test_commands_reach_nft_verbatim();
	test_count_parsing();

	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
