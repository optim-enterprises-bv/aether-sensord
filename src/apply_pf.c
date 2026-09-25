/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Applying reputation policy to pf, and confirming it took effect.
 * See apply_pf.h for the three ways this differs from the nftables version.
 */

#include "apply_pf.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * `strdup` is POSIX, not C11, so relying on it means the build's feature-test
 * macros decide whether this file compiles -- and glibc and FreeBSD default
 * differently. A local implementation keeps the file buildable under plain
 * -std=c11 on both, which is the portability claim being made.
 */
static char *dup_str(const char *s)
{
	size_t n = strlen(s) + 1;
	char *p = malloc(n);
	if (p)
		memcpy(p, s, n);
	return p;
}

bool pf_table_name_ok(const char *name)
{
	size_t n;

	if (!name)
		return false;
	n = strlen(name);
	if (n == 0 || n > PF_TABLE_NAME_MAX)
		return false;

	for (const char *p = name; *p; p++) {
		bool ok = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		          (*p >= '0' && *p <= '9') || *p == '_';
		if (!ok)
			return false;
	}
	/* Implied by the alphabet above (there is no '-' in it), but asserted
	 * so the property survives any future widening of the set. */
	return name[0] != '-';
}

const char *pf_apply_result_str(enum pf_apply_result r)
{
	switch (r) {
	case PF_APPLY_OK:
		return "ok";
	case PF_APPLY_REJECTED:
		return "rejected";
	case PF_APPLY_UNAVAILABLE:
		return "unavailable";
	case PF_APPLY_BAD_TABLE:
		return "bad_table_name";
	default:
		return "?";
	}
}

void pf_apply_ctx_init(struct pf_apply_ctx *c, pf_apply_exec_fn exec, void *user)
{
	if (!c)
		return;
	memset(c, 0, sizeof(*c));
	c->exec = exec;
	c->user = user;
	c->pfctl_path = PF_APPLY_DEFAULT_PATH;
}

/*
 * Distinguish "the table is not there" from other failures.
 *
 * This is the one pfctl message that needs its own handling rather than being
 * passed through as a generic rejection: it means the static alias was never
 * registered, so retrying is pointless and the operator needs a different
 * instruction. Measured on FreeBSD 16.0 with an undeclared table:
 *     pfctl: Table does not exist.
 */
static bool output_says_missing_table(const char *s)
{
	if (!s)
		return false;
	return strstr(s, "does not exist") != NULL ||
	       strstr(s, "Table does not exist") != NULL;
}

static enum pf_apply_result run_table_op(struct pf_apply_ctx *c,
                                         const char *table, const char *verb,
                                         const struct pf_elem *elems, size_t n,
                                         char *err, size_t err_len)
{
	/*
	 * argv is built on the heap: a feed batch can carry PF_BATCH_MAX
	 * elements, and a fixed stack array of pointers sized for the worst
	 * case would be 2 KB per call for no reason.
	 *
	 * Layout: pfctl -t <table> -T <verb> <elem>... NULL
	 */
	const char **argv;
	size_t argc = 0;
	size_t cap;
	char buf[8192];
	int status;
	enum pf_apply_result r;

	if (err && err_len)
		err[0] = '\0';

	if (!c || !c->exec)
		return PF_APPLY_UNAVAILABLE;
	if (!pf_table_name_ok(table))
		return PF_APPLY_BAD_TABLE;
	if (n > PF_BATCH_MAX)
		n = PF_BATCH_MAX;

	cap = 5 + n + 1;
	argv = calloc(cap, sizeof(*argv));
	if (!argv)
		return PF_APPLY_UNAVAILABLE;

	argv[argc++] = c->pfctl_path ? c->pfctl_path : PF_APPLY_DEFAULT_PATH;
	argv[argc++] = "-t";
	argv[argc++] = table;
	argv[argc++] = "-T";
	argv[argc++] = verb;

	for (size_t i = 0; i < n; i++) {
		char text[PF_ELEM_TEXT_MAX];
		if (pf_elem_render(&elems[i], text, sizeof(text)) == 0)
			continue; /* unrenderable: skip, never emit partial */

		/*
		 * Each element becomes its own argv slot. The renderer only ever
		 * emits inet_ntop output plus '/' and digits, so no element can
		 * start with '-' and be read as an option.
		 */
		{
			char *dup = dup_str(text);
			if (!dup) {
				free(argv);
				return PF_APPLY_UNAVAILABLE;
			}
			argv[argc++] = dup;
		}
	}
	argv[argc] = NULL;

	/*
	 * `flush` legitimately carries no elements, so an argv of exactly
	 * `pfctl -t <table> -T flush` is valid for it. The guard below is about
	 * elements that were OFFERED and refused, which is a different thing --
	 * testing argc alone conflated the two and made every flush fail.
	 */
	if (n > 0 && argc == 5) {
		/* Every element was unrenderable. Nothing to send, and reporting
		 * success here would be a lie. */
		for (size_t i = 5; i < argc; i++)
			free((char *)argv[i]);
		free(argv);
		return PF_APPLY_REJECTED;
	}

	status = c->exec(argv[0], argv, buf, sizeof(buf), c->user);

	if (err && err_len && status != 0)
		snprintf(err, err_len, "%s", buf);

	if (status == -1)
		r = PF_APPLY_UNAVAILABLE;
	else if (status == 0)
		r = PF_APPLY_OK;
	else if (output_says_missing_table(buf))
		r = PF_APPLY_UNAVAILABLE;
	else
		r = PF_APPLY_REJECTED;

	if (r == PF_APPLY_OK)
		c->applied_batches++;
	else if (r == PF_APPLY_UNAVAILABLE && output_says_missing_table(buf))
		c->missing_table++;

	for (size_t i = 5; i < argc; i++)
		free((char *)argv[i]);
	free(argv);

	return r;
}

enum pf_apply_result pf_apply_add(struct pf_apply_ctx *c, const char *table,
                                  const struct pf_elem *elems, size_t n,
                                  char *err, size_t err_len)
{
	if (!elems)
		return PF_APPLY_REJECTED;
	return run_table_op(c, table, "add", elems, n, err, err_len);
}

enum pf_apply_result pf_apply_del(struct pf_apply_ctx *c, const char *table,
                                  const struct pf_elem *elems, size_t n,
                                  char *err, size_t err_len)
{
	if (!elems)
		return PF_APPLY_REJECTED;
	return run_table_op(c, table, "delete", elems, n, err, err_len);
}

enum pf_apply_result pf_apply_flush(struct pf_apply_ctx *c, const char *table,
                                    char *err, size_t err_len)
{
	/* No elements: the argv is just `pfctl -t <table> -T flush`, which
	 * run_table_op builds correctly with n == 0. */
	return run_table_op(c, table, "flush", NULL, 0, err, err_len);
}

/*
 * Read the MAIN ruleset. Separate from pf_apply_show because it takes no table
 * name and has a different argv shape, but the same "absent is unreadable"
 * discipline applies: a failure to read means we cannot claim anything.
 */
long pf_apply_ruleset(struct pf_apply_ctx *c, char *out, size_t out_len)
{
	const char *argv[4];
	int status;
	size_t n;

	if (out && out_len)
		out[0] = '\0';
	if (!c || !c->exec || !out || out_len == 0)
		return -1;

	argv[0] = c->pfctl_path ? c->pfctl_path : PF_APPLY_DEFAULT_PATH;
	argv[1] = "-s";
	argv[2] = "rules";
	argv[3] = NULL;

	status = c->exec(argv[0], argv, out, out_len, c->user);
	if (status != 0)
		return -1;

	n = strlen(out);
	return (long)n;
}

long pf_apply_show(struct pf_apply_ctx *c, const char *table, char *out,
                   size_t out_len)
{
	const char *argv[6];
	int status;
	size_t n;

	if (out && out_len)
		out[0] = '\0';
	if (!c || !c->exec || !out || out_len == 0)
		return -1;
	if (!pf_table_name_ok(table))
		return -1;

	argv[0] = c->pfctl_path ? c->pfctl_path : PF_APPLY_DEFAULT_PATH;
	argv[1] = "-t";
	argv[2] = table;
	argv[3] = "-T";
	argv[4] = "show";
	argv[5] = NULL;

	status = c->exec(argv[0], argv, out, out_len, c->user);
	if (status != 0)
		return -1;

	n = strlen(out);
	return (long)n;
}

/* ------------------------------------------------------------------ */
/* Membership testing                                                  */
/* ------------------------------------------------------------------ */

/*
 * Parse "a.b.c.d/len" or "addr" (host) out of one token from pfctl output.
 * Returns true if a prefix was read.
 */
static bool token_to_prefix(const char *tok, size_t len, uint8_t *addr,
                            uint8_t *family, uint8_t *prefix)
{
	char buf[64];
	size_t n = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;

	memcpy(buf, tok, n);
	buf[n] = '\0';

	char *slash = strchr(buf, '/');
	long pfx = -1;
	if (slash) {
		*slash = '\0';
		char *endp = NULL;
		pfx = strtol(slash + 1, &endp, 10);
		if (!endp || *endp != '\0' || pfx < 0)
			return false;
	}

	if (inet_pton(AF_INET, buf, addr) == 1) {
		*family = 4;
		*prefix = (uint8_t)(slash ? pfx : 32);
		return *prefix <= 32;
	}
	if (inet_pton(AF_INET6, buf, addr) == 1) {
		*family = 6;
		*prefix = (uint8_t)(slash ? pfx : 128);
		return *prefix <= 128;
	}
	return false;
}

bool pf_table_lists_elem(const char *listing, const struct pf_elem *elem)
{
	const char *p;

	if (!listing || !elem)
		return false;
	if (elem->family != 4 && elem->family != 6)
		return false;

	/*
	 * Scan every token. pfctl prints ONE ENTRY PER LINE in plain CIDR form --
	 * measured on FreeBSD 16.0 for both interval and non-interval tables:
	 *
	 *     192.0.2.0/24
	 *     192.0.2.199
	 *
	 * An earlier version of this expected interval tables to print
	 * `start - end`, which pf does not do. That version would have failed to
	 * match every prefix, so verification would have reported a working
	 * firewall as broken -- and the temptation would have been to weaken the
	 * check rather than fix it.
	 *
	 * An element counts as present if any token parses to the SAME address
	 * and prefix. Address AND prefix must both match: /24 and /25 cover
	 * different address sets, and treating them as equal would verify a
	 * policy nobody asked for.
	 */
	for (p = listing; *p; ) {
		const char *start;
		size_t len;
		uint8_t addr[16], fam = 0, pfx = 0;

		while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
			p++;
		if (!*p)
			break;

		start = p;
		while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
			p++;
		len = (size_t)(p - start);

		if (token_to_prefix(start, len, addr, &fam, &pfx)) {
			if (fam == elem->family && pfx == elem->prefix &&
			    memcmp(addr, elem->addr, fam == 4 ? 4 : 16) == 0)
				return true;
		}
	}
	return false;
}

/* ------------------------------------------------------------------ */
/* Apply + verify                                                      */
/* ------------------------------------------------------------------ */

bool pf_apply_ruleset_references(const char *main_rules, const char *table)
{
	char needle[256];
	const char *p;
	size_t n;

	if (!main_rules || !table)
		return false;
	n = strlen(table);
	if (n == 0 || n > 240)
		return false;

	needle[0] = '<';
	memcpy(needle + 1, table, n);
	needle[n + 1] = '>';
	needle[n + 2] = '\0';

	p = strstr(main_rules, needle);
	if (!p)
		return false;

	/*
	 * Must be followed by a character that ends the token, so `<rep4>` is not
	 * satisfied by `<rep4_backup>`. pf separates a table reference from what
	 * follows with whitespace, a comma, a brace or end of line; anything else
	 * (a name character) means this is a longer table's name, and crediting
	 * its rule to ours would report enforcement belonging to another table.
	 */
	{
		char after = p[n + 2];
		if (after == '\0' || after == ' ' || after == '	' ||
		    after == '\n' || after == ',' || after == '}' ||
		    after == ')')
			return true;
	}
	return false;
}

bool pf_apply_and_verify(struct pf_apply_ctx *c, const char *table,
                         const struct pf_elem *elems, size_t n, char *err,
                         size_t err_len)
{
	char listing[16384];
	char rules[65536];
	enum pf_apply_result r;

	r = pf_apply_add(c, table, elems, n, err, err_len);
	if (r != PF_APPLY_OK) {
		c->failed_batches++;
		return false;
	}

	if (pf_apply_show(c, table, listing, sizeof(listing)) < 0) {
		/* The table was writable but not readable. Either way we cannot
		 * show the elements landed, and "the write returned 0" is
		 * explicitly not evidence. */
		c->failed_batches++;
		if (err && err_len)
			snprintf(err, err_len, "table %s unreadable after apply",
			         table);
		return false;
	}

	for (size_t i = 0; i < n; i++) {
		if (!pf_table_lists_elem(listing, &elems[i])) {
			c->verify_mismatches++;
			if (err && err_len) {
				char text[PF_ELEM_TEXT_MAX];
				if (pf_elem_render(&elems[i], text, sizeof(text)) == 0)
					snprintf(text, sizeof(text), "?");
				snprintf(err, err_len,
				         "element %s not present in table %s after "
				         "apply", text, table);
			}
			return false;
		}
	}

	/*
	 * THE CHECK THAT MATTERS. Elements being present says pf holds them; it
	 * does not say anything will be dropped, because `-T add` creates an
	 * undeclared table rather than failing. So require a rule in the main
	 * ruleset to reference it.
	 */
	if (pf_apply_ruleset(c, rules, sizeof(rules)) < 0) {
		c->failed_batches++;
		if (err && err_len)
			snprintf(err, err_len, "cannot read the pf ruleset");
		return false;
	}

	if (!pf_apply_ruleset_references(rules, table)) {
		c->unreferenced_tables++;
		if (err && err_len)
			snprintf(err, err_len,
			         "table %s holds the elements but NO RULE in the "
			         "main ruleset references it -- nothing will be "
			         "dropped. Register it as an OPNsense static alias.",
			         table);
		return false;
	}

	return true;
}

/* ------------------------------------------------------------------ */
/* Real exec                                                           */
/* ------------------------------------------------------------------ */

int pf_apply_exec_posix(const char *argv0, const char *const *argv, char *out,
                        size_t out_len, void *ctx)
{
	int pipefd[2];
	pid_t pid;
	int status;
	size_t used = 0;

	(void)ctx;
	if (!argv0 || !argv)
		return -1;

	if (out && out_len)
		out[0] = '\0';

	if (pipe(pipefd) != 0)
		return -1;

	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

	if (pid == 0) {
		/* Child. stdout to the pipe; stderr to stdout so pfctl's
		 * complaints ("Table does not exist") are captured with it --
		 * they are the diagnostic we act on. */
		close(pipefd[0]);
		if (dup2(pipefd[1], STDOUT_FILENO) < 0)
			_exit(127);
		if (dup2(pipefd[1], STDERR_FILENO) < 0)
			_exit(127);
		close(pipefd[1]);
		execv(argv0, (char *const *)argv);
		_exit(127);
	}

	close(pipefd[1]);
	if (out && out_len > 1) {
		ssize_t r;
		while (used < out_len - 1 &&
		       (r = read(pipefd[0], out + used, out_len - 1 - used)) > 0)
			used += (size_t)r;
		out[used] = '\0';
	} else {
		char sink[256];
		while (read(pipefd[0], sink, sizeof(sink)) > 0)
			; /* drain, so the child never blocks on a full pipe */
	}
	close(pipefd[0]);

	while (waitpid(pid, &status, 0) < 0)
		;
	/* 127 is our own exec failure, not a pfctl verdict. */
	if (WIFEXITED(status))
		return WEXITSTATUS(status) == 127 ? -1 : WEXITSTATUS(status);
	return -1;
}
