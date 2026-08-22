/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 */

#include "apply.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define NFT_DEFAULT_PATH "/usr/sbin/nft"

const char *apply_result_str(enum apply_result r)
{
	switch (r) {
	case APPLY_OK:
		return "ok";
	case APPLY_REJECTED:
		return "rejected";
	case APPLY_UNAVAILABLE:
		return "unavailable";
	default:
		return "unknown";
	}
}

void apply_ctx_init(struct apply_ctx *c, apply_exec_fn exec, void *user)
{
	if (!c)
		return;
	memset(c, 0, sizeof(*c));
	c->exec = exec;
	c->user = user;
	c->nft_path = NFT_DEFAULT_PATH;
}

enum apply_result apply_commands(struct apply_ctx *c, const char *commands,
                                 char *err, size_t err_len)
{
	if (err && err_len)
		err[0] = '\0';
	if (!c || !c->exec || !commands)
		return APPLY_UNAVAILABLE;
	if (commands[0] == '\0')
		return APPLY_OK; /* nothing to do is not a failure */

	const char *argv[] = { c->nft_path, "-f", "-", NULL };
	char out[1024];
	out[0] = '\0';

	int status = c->exec(c->nft_path, argv, commands, out, sizeof(out), c->user);

	if (status < 0) {
		c->failed_batches++;
		if (err && err_len)
			snprintf(err, err_len, "cannot run %s", c->nft_path);
		return APPLY_UNAVAILABLE;
	}
	if (status != 0) {
		c->failed_batches++;
		if (err && err_len)
			snprintf(err, err_len, "nft rejected input (status %d): %s",
			         status, out);
		return APPLY_REJECTED;
	}

	c->applied_batches++;
	return APPLY_OK;
}

long apply_count_set(struct apply_ctx *c, const struct nft_target *t, bool ipv6)
{
	if (!c || !c->exec || !t)
		return -1;

	const char *set = ipv6 ? t->set_v6 : t->set_v4;
	const char *argv[] = { c->nft_path, "list", "set", t->family, t->table,
		               set, NULL };
	char out[64 * 1024];
	out[0] = '\0';

	int status = c->exec(c->nft_path, argv, NULL, out, sizeof(out), c->user);
	if (status != 0)
		return -1; /* includes "no such set", which is the important case */

	/*
	 * Count entries inside `elements = { ... }`. nft prints them
	 * comma-separated, one or many per line. Counting separators plus one is
	 * enough to distinguish "empty", "some" and "none" -- which is all this
	 * needs to decide, and a full parse of nft's output format would be a
	 * dependency on its formatting.
	 */
	const char *e = strstr(out, "elements = {");
	if (!e)
		return 0; /* set exists but holds nothing */

	const char *p = e + strlen("elements = {");
	const char *close = strchr(p, '}');
	if (!close)
		return 0;

	long count = 0;
	bool seen_content = false;
	for (const char *q = p; q < close; q++) {
		if (*q == ',')
			count++;
		else if (*q != ' ' && *q != '\n' && *q != '\t')
			seen_content = true;
	}
	return seen_content ? count + 1 : 0;
}

bool apply_and_verify(struct apply_ctx *c, const struct nft_target *t,
                      const char *commands, bool ipv6, long expect_min,
                      char *err, size_t err_len)
{
	enum apply_result r = apply_commands(c, commands, err, err_len);
	if (r != APPLY_OK)
		return false;

	long have = apply_count_set(c, t, ipv6);
	if (have < 0) {
		c->verify_mismatches++;
		if (err && err_len)
			snprintf(err, err_len,
			         "nft accepted the batch but the %s set cannot be read "
			         "-- it may not exist. Applied is not enforced.",
			         ipv6 ? t->set_v6 : t->set_v4);
		return false;
	}
	if (have < expect_min) {
		c->verify_mismatches++;
		if (err && err_len)
			snprintf(err, err_len,
			         "nft accepted the batch but %s holds %ld elements, "
			         "expected at least %ld",
			         ipv6 ? t->set_v6 : t->set_v4, have, expect_min);
		return false;
	}
	return true;
}

int apply_exec_posix(const char *argv0, const char *const *argv,
                     const char *stdin_data, char *out, size_t out_len,
                     void *ctx)
{
	(void)ctx;
	if (!argv0 || !argv)
		return -1;

	int in_pipe[2] = { -1, -1 };
	int out_pipe[2] = { -1, -1 };

	if (stdin_data && pipe(in_pipe) != 0)
		return -1;
	if (pipe(out_pipe) != 0) {
		if (in_pipe[0] >= 0) {
			close(in_pipe[0]);
			close(in_pipe[1]);
		}
		return -1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		if (in_pipe[0] >= 0) {
			close(in_pipe[0]);
			close(in_pipe[1]);
		}
		close(out_pipe[0]);
		close(out_pipe[1]);
		return -1;
	}

	if (pid == 0) {
		if (stdin_data) {
			dup2(in_pipe[0], STDIN_FILENO);
			close(in_pipe[1]);
			close(in_pipe[0]);
		}
		dup2(out_pipe[1], STDOUT_FILENO);
		dup2(out_pipe[1], STDERR_FILENO);
		close(out_pipe[0]);
		close(out_pipe[1]);
		execv(argv0, (char *const *)argv);
		_exit(127); /* distinguishable from any nft status */
	}

	if (stdin_data) {
		close(in_pipe[0]);
		size_t len = strlen(stdin_data);
		size_t off = 0;
		while (off < len) {
			ssize_t w = write(in_pipe[1], stdin_data + off, len - off);
			if (w <= 0)
				break;
			off += (size_t)w;
		}
		close(in_pipe[1]);
	}

	close(out_pipe[1]);
	size_t got = 0;
	if (out && out_len) {
		while (got + 1 < out_len) {
			ssize_t r = read(out_pipe[0], out + got, out_len - got - 1);
			if (r <= 0)
				break;
			got += (size_t)r;
		}
		out[got] = '\0';
	}
	close(out_pipe[0]);

	int status = 0;
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	if (WIFEXITED(status)) {
		int code = WEXITSTATUS(status);
		/* 127 is our exec failure, not an nft verdict. */
		return code == 127 ? -1 : code;
	}
	return -1;
}
