/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * CLI driver for the pf enforcement canary. Exists so the canary can be run by
 * hand against a live table -- which is the entire point of the mechanism: an
 * operator (or a test) must be able to ask "is this actually blocking?"
 * without reading any configuration.
 *
 * Usage: canary-pf <table> [--v6] [--spool DIR] [--serial S]
 *
 * Exit status: 0 only for ENFORCED. Every other verdict, including
 * INCONCLUSIVE, exits non-zero -- so a monitoring script that treats a non-zero
 * exit as an alarm cannot be fooled by "could not check".
 */

#include "canary_pf.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	const char *table = NULL;
	const char *spool = NULL;
	const char *serial = NULL;
	bool v6 = false;
	enum pf_canary_result r;
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--v6") == 0)
			v6 = true;
		else if (strcmp(argv[i], "--spool") == 0 && i + 1 < argc)
			spool = argv[++i];
		else if (strcmp(argv[i], "--serial") == 0 && i + 1 < argc)
			serial = argv[++i];
		else if (argv[i][0] == '-') {
			fprintf(stderr, "unknown option: %s\n", argv[i]);
			return 2;
		} else
			table = argv[i];
	}

	if (!table) {
		fprintf(stderr,
		        "usage: %s <table> [--v6] [--spool DIR] [--serial S]\n",
		        argv[0]);
		return 2;
	}

	r = pf_canary_run(table, v6);

	printf("table:   %s (%s)\n", table, v6 ? "v6" : "v4");
	printf("canary:  %s\n", pf_canary_addr(v6));
	printf("verdict: %s\n", pf_canary_token(r));
	printf("meaning: %s\n", pf_canary_str(r));

	if (spool) {
		int rc = pf_canary_report(spool, serial, r, table, v6);
		printf("spool:   %s (%s)\n", spool, rc == 0 ? "written" : "FAILED");
	}

	return pf_canary_passed(r) ? 0 : 1;
}
