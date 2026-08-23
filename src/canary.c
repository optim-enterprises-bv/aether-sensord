/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 */

#include "canary.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* TEST-NET-1 and the v6 documentation prefix. Neither can carry real traffic,
 * and obs_addr_is_private() already refuses both, so the reputation feed can
 * never legitimately contain one. */
#define CANARY_V4 "192.0.2.199"
#define CANARY_V6 "2001:db8::c0de"

const char *canary_addr(bool v6)
{
	return v6 ? CANARY_V6 : CANARY_V4;
}

const char *canary_result_str(enum canary_result r)
{
	switch (r) {
	case CANARY_ENFORCED:       return "enforced (a packet was stopped)";
	case CANARY_SET_MISSING:    return "the set does not exist";
	case CANARY_ADD_REJECTED:   return "nft refused the canary element";
	case CANARY_NOT_HELD:       return "nft accepted it but the kernel does not hold it";
	case CANARY_NOT_ENFORCED:   return "SET HOLDS IT BUT NOTHING IS BLOCKED";
	case CANARY_CLEANUP_FAILED: return "enforced, but the canary was left behind";
	case CANARY_INCONCLUSIVE:   return "could not be checked";
	default:                    return "?";
	}
}

const char *canary_result_token(enum canary_result r)
{
	/* Must stay in step with enum Verdict in aether-aegis::proof. */
	switch (r) {
	case CANARY_ENFORCED:       return "enforced";
	case CANARY_SET_MISSING:    return "set_missing";
	case CANARY_ADD_REJECTED:   return "add_rejected";
	case CANARY_NOT_HELD:       return "not_held";
	case CANARY_NOT_ENFORCED:   return "not_enforced";
	case CANARY_CLEANUP_FAILED: return "cleanup_failed";
	default:                    return "inconclusive";
	}
}

int canary_report(const char *spool_dir, const char *serial,
                  enum canary_result r, const char *target, bool v6)
{
	char path[512], tmp[540];
	FILE *f;
	time_t now;
	int err;

	if (!spool_dir)
		return -1;

	now = time(NULL);
	snprintf(path, sizeof(path), "%s/canary-%lld.ndjson", spool_dir,
	         (long long)now);
	snprintf(tmp, sizeof(tmp), "%s.partial", path);

	f = fopen(tmp, "w");
	if (!f) {
		syslog(LOG_ERR, "cannot open canary spool %s: %s", tmp,
		       strerror(errno));
		return -1;
	}

	/*
	 * The prose meaning is deliberately NOT sent. The controller has its
	 * own wording for each verdict, and shipping ours would leave two
	 * descriptions of the same state that drift apart.
	 *
	 * The serial key is OMITTED when we do not know it, rather than sent
	 * empty. This daemon has no cloud identity of its own; the uplink does,
	 * and it fills the field. An empty string would key a device row on ""
	 * and quietly collect every unidentified device's verdicts into one
	 * fictional AP.
	 */
	fputs("{\"canary\":true,", f);
	if (serial && serial[0])
		fprintf(f, "\"serial\":\"%s\",", serial);
	fprintf(f,
	        "\"result\":\"%s\",\"target\":\"%s\",\"family\":%d,"
	        "\"reported_at\":%lld}\n",
	        canary_result_token(r), target ? target : "", v6 ? 6 : 4,
	        (long long)now);

	err = ferror(f);
	if (fclose(f) != 0 || err) {
		syslog(LOG_ERR, "canary spool write failed, discarding verdict");
		unlink(tmp);
		return -1;
	}

	/* Rename only after a complete write, so the uplink never ships half a
	 * record -- a truncated verdict would be rejected by the controller and
	 * count as silence, which is an alarm. */
	if (rename(tmp, path) != 0) {
		syslog(LOG_ERR, "cannot rename %s: %s", tmp, strerror(errno));
		unlink(tmp);
		return -1;
	}
	return 0;
}

bool canary_passed(enum canary_result r)
{
	/*
	 * Only ENFORCED. INCONCLUSIVE in particular must not read as a pass:
	 * the failure this guards against is itself silent, so a guard that
	 * fails open reproduces the bug it exists to catch.
	 */
	return r == CANARY_ENFORCED;
}

int canary_probe_blocked(const char *addr, bool v6)
{
	int fd;
	ssize_t sent;
	static const uint8_t payload[4] = { 0xae, 0x11, 0xca, 0x1a };

	if (!addr)
		return -1;

	fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	if (v6) {
		struct sockaddr_in6 sa;

		memset(&sa, 0, sizeof(sa));
		sa.sin6_family = AF_INET6;
		sa.sin6_port = htons(9); /* discard */
		if (inet_pton(AF_INET6, addr, &sa.sin6_addr) != 1) {
			close(fd);
			return -1;
		}
		sent = sendto(fd, payload, sizeof(payload), MSG_DONTWAIT,
		              (struct sockaddr *)&sa, sizeof(sa));
	} else {
		struct sockaddr_in sa;

		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_port = htons(9);
		if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
			close(fd);
			return -1;
		}
		sent = sendto(fd, payload, sizeof(payload), MSG_DONTWAIT,
		              (struct sockaddr *)&sa, sizeof(sa));
	}

	if (sent < 0) {
		int e = errno;

		close(fd);
		/*
		 * EPERM is what nftables returns for a rule with `reject` or a
		 * drop the socket layer can see; EACCES appears on some paths.
		 * Anything else -- ENETUNREACH, EHOSTUNREACH -- means routing
		 * refused it, NOT the firewall, and must not be counted as
		 * enforcement.
		 */
		if (e == EPERM || e == EACCES)
			return 1;
		return 0;
	}
	close(fd);
	return 0;
}

enum canary_result canary_run(struct apply_ctx *c, const struct nft_target *t,
                              bool v6)
{
	struct nft_elem e;
	char cmd[512];
	size_t n_rendered = 0;
	enum canary_result verdict;
	long before;
	int blocked;
	const char *addr = canary_addr(v6);

	if (!c || !t)
		return CANARY_INCONCLUSIVE;

	/* Does the set even exist? apply_count_set returns -1 for "no such
	 * set", which is exactly the state that went unnoticed for a whole
	 * session. */
	before = apply_count_set(c, t, v6);
	if (before < 0)
		return CANARY_SET_MISSING;

	memset(&e, 0, sizeof(e));
	if (nft_elem_parse(addr, &e) != NFT_OK)
		return CANARY_INCONCLUSIVE;
	/* Short-lived: if we die mid-test the kernel cleans up after us. */
	e.timeout_sec = 60;

	if (nft_render_add(t, &e, 1, cmd, sizeof(cmd), &n_rendered) == 0 ||
	    n_rendered != 1)
		return CANARY_INCONCLUSIVE;
	if (apply_commands(c, cmd, NULL, 0) != APPLY_OK)
		return CANARY_ADD_REJECTED;

	/* nft accepting a command is not the kernel holding the element. */
	if (apply_count_set(c, t, v6) <= before) {
		verdict = CANARY_NOT_HELD;
		goto cleanup;
	}

	blocked = canary_probe_blocked(addr, v6);
	if (blocked < 0)
		verdict = CANARY_INCONCLUSIVE;
	else if (blocked == 1)
		verdict = CANARY_ENFORCED;
	else
		/*
		 * The set holds the address and the packet still left. The set
		 * exists but no rule references it -- enforcement is decorative.
		 */
		verdict = CANARY_NOT_ENFORCED;

cleanup:
	/* Always try to remove it, on every path. */
	n_rendered = 0;
	if (nft_render_del(t, &e, 1, cmd, sizeof(cmd), &n_rendered) != 0 &&
	    n_rendered == 1) {
		if (apply_commands(c, cmd, NULL, 0) != APPLY_OK &&
		    verdict == CANARY_ENFORCED)
			verdict = CANARY_CLEANUP_FAILED;
	} else if (verdict == CANARY_ENFORCED) {
		verdict = CANARY_CLEANUP_FAILED;
	}
	return verdict;
}
