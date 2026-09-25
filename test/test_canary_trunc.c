/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * REGRESSION: the enforcement canary must not degrade to INCONCLUSIVE just
 * because the main ruleset is bigger than its read buffer.
 *
 * Measured on a production OPNsense firewall (26.7.2_2) whose main ruleset is
 * 13,592 bytes: the canary's listing buffer was 8,192, run_capture() read 8,191
 * and closed the pipe, pfctl -- which still had ~5 KB to write -- died of
 * SIGPIPE, pclose() returned 13 rather than 0, and pf_canary_run() set
 * probe_ran = false. The verdict became INCONCLUSIVE on EVERY run.
 *
 * Why that specific failure is the bad one: the canary is the thing that
 * distinguishes "the table exists" from "traffic is actually dropped". Failing
 * to INCONCLUSIVE destroys BOTH answers at once -- it can never report
 * `enforced`, and it can never warn `not_enforced`. An operator reading
 * "could not be checked" learns nothing, and the one state the canary exists to
 * catch (a populated table that nothing references) goes unreported on the very
 * firewalls big enough to need it.
 *
 * This drives the REAL binary against a stateful fake pfctl placed first on
 * PATH. The fake emits a ruleset deliberately larger than the old buffer, so
 * the only variable between cases is whether the table reference is present.
 *
 * FreeBSD-only: it depends on the pf-backed half of canary_pf.c, and it needs
 * the built binary. Exit 0 = pass.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Overridable so this can run against a build dir. */
#ifndef CANARY_BIN
#define CANARY_BIN "/usr/local/sbin/aether-sensord-pfcanary"
#endif
#ifndef FAKE_DIR
#define FAKE_DIR "/tmp/fakepf_regress"
#endif

static int checks;
static int failures;

static void check(int cond, const char *what)
{
	checks++;
	if (!cond) {
		failures++;
		printf("  FAIL: %s\n", what);
	} else {
		printf("  ok:   %s\n", what);
	}
}

/*
 * A stateful pfctl: -T add records, -T delete forgets, -T show lists, and
 * -s rules prints a ruleset of PAD lines (each ~82 bytes, so 200 of them clear
 * the old 8192-byte buffer by a wide margin) optionally followed by a rule
 * that references the table. $1 selects whether that final rule is present.
 */
static const char *FAKE_SRC =
"#!/bin/sh\n"
"STATE=" FAKE_DIR "/state\n"
"case \"$*\" in\n"
"  *\"-T add\"*)    for a in \"$@\"; do case \"$a\" in -*) ;; *) echo \"$a\" >> $STATE ;; esac; done; exit 0 ;;\n"
"  *\"-T delete\"*) for a in \"$@\"; do case \"$a\" in -*) ;; *) grep -v \"^$a$\" $STATE > $STATE.t 2>/dev/null; mv $STATE.t $STATE 2>/dev/null ;; esac; done; exit 0 ;;\n"
"  *\"-T show\"*)   cat $STATE 2>/dev/null; exit 0 ;;\n"
"  *\"-s rules\"*)\n"
"    i=0\n"
"    while [ $i -lt 200 ]; do\n"
"      echo \"pass in quick on igb2 inet from any to any flags S/SA keep state label \\\"pad-$i\\\"\"\n"
"      i=$((i+1))\n"
"    done\n"
"    if [ \"$REFERENCED\" = \"1\" ]; then\n"
"      echo \"block drop in log quick from <aisense_rep4> to any label \\\"realrule\\\"\"\n"
"    fi\n"
"    exit 0 ;;\n"
"esac\n"
"exit 0\n";

/* Run the canary with the fake pfctl first on PATH; return its verdict. */
static void run_canary(int referenced, char *verdict, size_t vlen)
{
	char cmd[1024];
	char line[256];
	FILE *p;

	verdict[0] = '\0';
	snprintf(cmd, sizeof(cmd),
	         "rm -f " FAKE_DIR "/state; "
	         "PATH=" FAKE_DIR ":$PATH REFERENCED=%d " CANARY_BIN " aisense_rep4 2>&1",
	         referenced);

	p = popen(cmd, "r");
	if (!p)
		return;
	while (fgets(line, sizeof(line), p)) {
		if (strncmp(line, "verdict:", 8) == 0) {
			char *v = line + 8;
			size_t n;
			while (*v == ' ' || *v == '\t')
				v++;
			n = strlen(v);
			while (n && (v[n - 1] == '\n' || v[n - 1] == '\r'))
				v[--n] = '\0';
			snprintf(verdict, vlen, "%s", v);
		}
	}
	pclose(p);
}

int main(void)
{
	char path[512], v[128];
	FILE *f;

	snprintf(path, sizeof(path), "%s", FAKE_DIR);
	if (system("mkdir -p " FAKE_DIR) != 0) {
		printf("cannot create " FAKE_DIR "\n");
		return 2;
	}
	(void)path;

	snprintf(path, sizeof(path), FAKE_DIR "/pfctl");
	f = fopen(path, "w");
	if (!f) {
		printf("cannot write %s\n", path);
		return 2;
	}
	fputs(FAKE_SRC, f);
	fclose(f);
	(void)system("chmod +x " FAKE_DIR "/pfctl");

	/*
	 * The ruleset produced by the fake is ~13.6 KB, matching the measured
	 * production size, so it clears the old 8192-byte buffer.
	 */

	printf("canary vs a ruleset larger than the old 8192-byte buffer\n");

	run_canary(1, v, sizeof(v));
	check(strcmp(v, "enforced") == 0,
	      "table referenced AFTER the 8 KB mark -> enforced");

	run_canary(0, v, sizeof(v));
	check(strcmp(v, "not_enforced") == 0,
	      "table not referenced anywhere -> not_enforced (the dangerous state)");

	printf("\n%d checks, %d failures\n", checks, failures);
	(void)system("rm -rf " FAKE_DIR);
	return failures ? 1 : 0;
}
