/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Applying rendered nftables commands, and CONFIRMING they took effect.
 *
 * This file exists because of one sentence in ADR-017: "config committed
 * successfully" is worthless as evidence that anything is enforced. `nft -f`
 * returning 0 means nft parsed a file. It does not mean the set exists, that
 * the elements are in it, or that a packet will die.
 *
 * So applying and verifying are separate calls with separate results, and the
 * verify reads the kernel's own view back rather than believing the exit code.
 * A caller that only checks apply_commands() has not learned anything, and the
 * API is shaped to make that obvious.
 *
 * The exec seam is injectable so the command construction, the error handling
 * and the count reconciliation are all testable on the host without nft, root,
 * or a device.
 */

#ifndef AETHER_SENSORD_APPLY_H
#define AETHER_SENSORD_APPLY_H

#include "nft.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Run a command, capturing stdout into `out`.
 *
 * Returns the process exit status, or -1 if it could not be run at all. The
 * distinction matters: a non-zero status is nft rejecting our input, while -1
 * is the tool being absent, and those need different operator responses.
 */
typedef int (*apply_exec_fn)(const char *argv0, const char *const *argv,
                             const char *stdin_data, char *out, size_t out_len,
                             void *ctx);

struct apply_ctx {
	apply_exec_fn exec;
	void *user;
	const char *nft_path; /* default /usr/sbin/nft */
	/* Cumulative, for the health surface. */
	uint64_t applied_batches;
	uint64_t failed_batches;
	uint64_t verify_mismatches;
};

void apply_ctx_init(struct apply_ctx *c, apply_exec_fn exec, void *user);

enum apply_result {
	APPLY_OK = 0,
	APPLY_REJECTED,   /* nft ran and refused our input */
	APPLY_UNAVAILABLE /* nft could not be run at all */
};

const char *apply_result_str(enum apply_result r);

/*
 * Feed a rendered command buffer to `nft -f -`.
 *
 * One invocation per buffer, so nft applies it as a single transaction: either
 * every element in the batch lands or none does. Applying elements one at a
 * time would leave a partially-updated set on the first bad entry, which is
 * the state hardest to notice and hardest to recover from.
 */
enum apply_result apply_commands(struct apply_ctx *c, const char *commands,
                                 char *err, size_t err_len);

/*
 * Read back how many elements the kernel actually holds in a set.
 *
 * Returns the count, or -1 if the set could not be read -- which includes the
 * set not existing, the case that matters most. A set that was never created
 * reports 0 elements to a careless reader and -1 to this one.
 */
long apply_count_set(struct apply_ctx *c, const struct nft_target *t,
                     bool ipv6);

/*
 * Apply a batch and confirm it. Returns true only when nft accepted the input
 * AND the set afterwards holds at least `expect_min` elements.
 *
 * `expect_min` rather than an exact count because `auto-merge` legitimately
 * collapses overlapping prefixes, so the kernel may hold fewer entries than we
 * sent while covering the same addresses. An exact comparison would fail on
 * correct behaviour; a floor still catches the case that matters, which is a
 * set that did not receive the update at all.
 */
bool apply_and_verify(struct apply_ctx *c, const struct nft_target *t,
                      const char *commands, bool ipv6, long expect_min,
                      char *err, size_t err_len);

/* The real exec, used in production. Not used by tests. */
int apply_exec_posix(const char *argv0, const char *const *argv,
                     const char *stdin_data, char *out, size_t out_len,
                     void *ctx);

#endif /* AETHER_SENSORD_APPLY_H */
