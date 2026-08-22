/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 */

#include "offload.h"

#include <string.h>

const char *offload_state_str(enum offload_state s)
{
	switch (s) {
	case OFFLOAD_ABSENT:  return "absent";
	case OFFLOAD_PRESENT: return "PRESENT";
	case OFFLOAD_UNKNOWN: return "unknown";
	default:              return "?";
	}
}

enum offload_state offload_parse(const char *out)
{
	if (!out)
		return OFFLOAD_UNKNOWN;

	/*
	 * `nft list flowtables` prints "table inet fw4 {" then
	 * "flowtable ft {" for each one, and prints nothing at all when there
	 * are none. An empty result is therefore a real answer, not a failure
	 * -- but only when the command itself succeeded, which is the caller's
	 * job to establish.
	 */
	if (strstr(out, "flowtable "))
		return OFFLOAD_PRESENT;
	return OFFLOAD_ABSENT;
}

enum offload_state offload_probe(struct apply_ctx *c)
{
	char out[16 * 1024];
	const char *argv[] = { NULL, "list", "flowtables", NULL };
	int status;

	if (!c || !c->exec)
		return OFFLOAD_UNKNOWN;
	argv[0] = c->nft_path;
	out[0] = '\0';

	status = c->exec(c->nft_path, argv, NULL, out, sizeof(out), c->user);
	if (status != 0) {
		/*
		 * Could not ask. Reporting this as ABSENT would turn "I do not
		 * know whether inspection works" into "inspection works",
		 * which is the exact substitution this whole component exists
		 * to prevent.
		 */
		return OFFLOAD_UNKNOWN;
	}
	return offload_parse(out);
}
