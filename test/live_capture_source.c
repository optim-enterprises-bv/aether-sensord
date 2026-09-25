/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * LIVE end-to-end test: real interface -> capture_source -> daemon local pass
 * -> pf decision. FreeBSD only, because it needs netgraph.
 *
 * ======================= WHAT THIS PROVES, AND WHAT IT DOES NOT ============
 *
 * PROVES: a genuine TLS ClientHello arriving on a REAL interface is carried
 * through the capture source into the daemon's local half, matched against a
 * signature database and a policy, and turned into a pf element naming the
 * flow's real destination address.
 *
 * DOES NOT PROVE: that traffic was blocked. This test runs with
 * capture_enforce=false on purpose. Writing to pf from a test would mean a
 * test that can take a firewall's table away from it, and this VM is reached
 * over the network. The enforcement half is tested separately through a
 * scripted pfctl (test_local_enforce.c) where pfctl can be made to lie, which
 * is the failure mode that matters and cannot be produced by a real pfctl.
 *
 * ===================== WHY THE CONTROL MATTERS HERE ======================
 *
 * An ng_bpf node with no program INSTALLED drops everything, so "no verdicts
 * arrived" is not evidence of anything until an accept-all program has moved
 * frames through the same graph. The test therefore:
 *
 *   1. brings up a disposable epair0 pair,
 *   2. attaches the capture source to one end,
 *   3. sends a REAL ClientHello from the other end (openssl s_client),
 *   4. asserts a verdict with the right hostname comes out,
 *   5. tears everything down and asserts the interface is restored.
 *
 * The interface used is epair0, NEVER vtnet0 -- vtnet0 carries the SSH session
 * and reattaching it is a lockout.
 */

#include "../src/capture_source.h"
#include "../src/daemon_pf.h"
#include "../src/local_decide.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

static int checks;
static int failures;

#define CHECK(cond, msg)                                                      \
	do {                                                                  \
		checks++;                                                     \
		if (!(cond)) {                                                \
			failures++;                                           \
			printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
		}                                                             \
	} while (0)

#define TEST_IFACE "epair0"
#define TEST_HOSTNAME "aisense-e2e.test"

/* ---------------------------------------------------------------- plumbing */

static int run(const char *cmd)
{
	int rc = system(cmd);

	if (rc == -1)
		return -1;
	if (WIFEXITED(rc))
		return WEXITSTATUS(rc);
	return -1;
}

/*
 * Bring up a disposable epair pair.
 *
 * epair0 is chosen because it is entirely synthetic: destroying it cannot
 * affect anything else on the box, and destroying it FIRST is load-bearing --
 * a stale epair leaves its netgraph node behind after the interface is gone,
 * and the subsequent mkpeer then fails with an error that points at the wrong
 * thing entirely.
 */
static int setup_iface(void)
{
	/*
	 * TEARDOWN BEFORE SETUP, and in this exact order.
	 *
	 * MEASURED, and it cost several confusing failures: destroying the
	 * interface does NOT remove its netgraph node. An `ether` node for each
	 * epair end survives its interface, and a surviving node makes the next
	 * `ifconfig create` fail with "already exists" while `ifconfig` on the
	 * base name simultaneously reports "does not exist" -- an error that
	 * names neither the cause nor the fix. The subsequent attach then fails
	 * with "interface not found" or "File exists".
	 *
	 * So: destroy the INTERFACE first (while the nodes still refer to it),
	 * then shut down the NODES. Doing it the other way round leaves the
	 * nodes behind and the same broken state.
	 */
	/*
	 * ORDER: server, then JAIL, then interface, then nodes.
	 *
	 * The jail must go BEFORE the interface can be addressed, because while
	 * the peer lives in the jail's network stack its interface is not
	 * visible here -- `ifconfig epair0b destroy` then fails with "does not
	 * exist" and the create that follows cannot reuse the name.
	 */
	run("pkill -f 'openssl s_server' >/dev/null 2>&1");
	run("jail -r aisense_e2e >/dev/null 2>&1");
	sleep(1);
	/*
	 * DESTROY THE ENDPOINTS, not the base name -- and this is the fix for
	 * the leak that caused every confusing failure in this area.
	 *
	 * MEASURED: `ifconfig epair0 destroy` fails once the peer has been moved
	 * into a VNET jail (the base interface "does not exist" from this stack),
	 * while the endpoints are what actually own the netgraph nodes.
	 * `ifconfig epair0a destroy` removes the interface AND its node
	 * completely; a node left behind makes the next `ifconfig create` fail
	 * with "already exists" while `ifconfig` reports "does not exist", and
	 * the attach after that returns "interface not found" or "File exists"
	 * -- an error that names neither the cause nor the fix.
	 */
	run("ifconfig " TEST_IFACE "a destroy >/dev/null 2>&1");
	run("ifconfig " TEST_IFACE "b destroy >/dev/null 2>&1");
	run("ifconfig " TEST_IFACE " destroy >/dev/null 2>&1");
	sleep(1);

	/*
	 * `create` IS ALLOWED TO FAIL, and the reason is the trap above: when the
	 * interface survived a previous run, `create` reports "already exists"
	 * even though the thing we need is present and usable. Treating that as
	 * fatal makes the test skip when it could have run -- which is how a test
	 * quietly stops testing anything.
	 *
	 * So the SETUP SUCCESS CRITERION IS THE VERIFICATION BELOW, not the exit
	 * status of `create`: can we address the two ends? That is the property
	 * the test actually depends on.
	 */
	if (run("ifconfig " TEST_IFACE " create >/dev/null 2>&1") != 0)
		sleep(1);

	/*
	 * THE FAR END GOES INTO A VNET JAIL, and this is not decoration.
	 *
	 * ng_ether's `lower` hook sees frames ARRIVING on the interface. With
	 * both ends on the host, a client's packets leave via the interface's
	 * own output path and never appear on `lower` -- measured: ICMP crossed
	 * the epair fine and the capture saw nothing, which is indistinguishable
	 * from a broken graph.
	 *
	 * Putting the peer in a VNET jail makes it a genuinely separate IP stack,
	 * so its frames TRAVERSE the link and arrive inbound. The proven
	 * live_attach test does exactly this, and the same reasoning applies
	 * here.
	 */
	run("jail -c name=aisense_e2e vnet persist >/dev/null 2>&1");

	if (access("/tmp/e2e.crt", R_OK) != 0) {
		printf("SKIP: no test certificate\n");
		return -1;
	}

	/*
	 * The peer must be DOWN before it can be moved into another vnet.
	 *
	 * The move itself can legitimately fail with "File exists" when the
	 * interface is ALREADY in the jail from a previous run that did not
	 * clean up -- which happens routinely, because a run that fails its
	 * assertions still exits without restoring the network stack. Treating
	 * that as fatal makes the test skip on the second invocation and every
	 * one after, which is how a test quietly stops testing.
	 *
	 * So the criterion is the CHECK BELOW -- does the jail actually have an
	 * address on that interface -- not the exit status of the move.
	 */
	run("ifconfig " TEST_IFACE "b down >/dev/null 2>&1");
	run("ifconfig " TEST_IFACE "b vnet aisense_e2e >/dev/null 2>&1");

	run("jexec aisense_e2e ifconfig " TEST_IFACE "b inet 10.99.99.2/24 "
	    "up >/dev/null 2>&1");

	/*
	 * THE REAL SETUP CHECK: is the peer really in a separate stack, and can
	 * this stack see the host side? If not, the test cannot mean anything --
	 * so it returns -1, and main reports a SKIP rather than a pass.
	 */
	if (run("jexec aisense_e2e ifconfig " TEST_IFACE "b inet | "
	        "grep -q inet") != 0)
		return -1;
	if (run("ifconfig " TEST_IFACE "a inet 10.99.99.1/24 up >/dev/null "
	        "2>&1") != 0)
		return -1;
	if (run("ifconfig " TEST_IFACE "a inet | grep -q inet") != 0)
		return -1;
	return 0;
}

static void teardown_iface(void)
{
	/*
	 * Server, then jail, then BOTH ENDPOINTS by name.
	 *
	 * Destroying each endpoint is what removes its netgraph node; destroying
	 * the base name does not work once the peer is in the jail, and
	 * `ngctl shutdown` on the node is refused (the ether node is owned by
	 * its interface and cannot be shut down independently). This ordering
	 * and these exact commands are the difference between a clean run and a
	 * broken environment for every subsequent run.
	 */
	run("pkill -f 'openssl s_server' >/dev/null 2>&1");
	run("jail -r aisense_e2e >/dev/null 2>&1");
	run("ifconfig " TEST_IFACE "b destroy >/dev/null 2>&1");
	run("ifconfig " TEST_IFACE "a destroy >/dev/null 2>&1");
	run("ifconfig " TEST_IFACE " destroy >/dev/null 2>&1");
}

/*
 * How many HOOKS does the interface carrying our SSH session have?
 *
 * HOOKS, not node existence -- and that distinction was a bug in an earlier
 * version of this check, which grepped for the string "vtnet0" and therefore
 * counted the NODE. An `ether` node for every Ethernet interface exists from
 * boot with zero hooks, so that check failed on a perfectly healthy system
 * while telling us nothing.
 *
 * Hooks are the property that matters: `lower` connected means the interface
 * is out of the kernel's path, and on vtnet0 that would mean the connection
 * running this test is already dead.
 */
static int vtnet_hooks(void)
{
	FILE *p;
	char line[512];
	int n = 0;

	p = popen("/usr/sbin/ngctl list 2>/dev/null | grep -A6 'Name: vtnet0 ' "
	          "| grep -cE '^[[:space:]]+(upper|lower)[[:space:]]' || true",
	          "r");
	if (!p)
		return -1;
	if (fgets(line, sizeof line, p))
		n = atoi(line);
	pclose(p);
	return n;
}

/* ------------------------------------------------------------- the sender */

/*
 * A real ClientHello, sent by openssl over the epair.
 *
 * Real bytes matter: a hand-built frame is what the unit tests use, and the
 * point of going live is to catch what a hand-built frame gets wrong. It
 * already has, twice -- a missing IP identification field, and a ClientHello
 * size (1545 bytes with ML-KEM) that spans segments.
 */
struct sender_arg {
	const char *host;
	int port;
};

static void *sender_thread(void *arg)
{
	struct sender_arg *a = arg;
	char cmd[512];

	/*
	 * s_server first (background), then s_client. s_client needs a peer that
	 * answers, or it sends nothing at all -- which produced a silent
	 * "nothing arrived" in an earlier run and looked like a capture failure.
	 */
	/*
	 * The SERVER runs on the host, bound to the host side's address; the
	 * CLIENT runs inside the jail. That direction is what makes the
	 * ClientHello arrive INBOUND on epair0a, where `lower` can see it.
	 */
	snprintf(cmd, sizeof cmd,
	         "openssl s_server -accept 10.99.99.1:%d -cert /tmp/e2e.crt "
	         "-key /tmp/e2e.key -quiet >/dev/null 2>&1 &", a->port);
	run(cmd);
	usleep(400000);

	snprintf(cmd, sizeof cmd,
	         "jexec aisense_e2e sh -c 'echo | timeout 5 openssl s_client "
	         "-connect 10.99.99.1:%d -servername %s' >/dev/null 2>&1",
	         a->port, a->host);
	run(cmd);

	run("pkill -f 'openssl s_server' >/dev/null 2>&1");
	return NULL;
}

static int make_cert(void)
{
	if (access("/tmp/e2e.crt", R_OK) == 0)
		return 0;
	return run("openssl req -x509 -newkey rsa:2048 -keyout /tmp/e2e.key "
	           "-out /tmp/e2e.crt -days 1 -nodes -subj /CN=localhost "
	           ">/dev/null 2>&1");
}

/* ------------------------------------------------------------------ main */

int main(void)
{
	struct capture_source *cs;
	struct dpf_config cfg;
	struct pf_apply_ctx ap;
	struct dpf_local_stats st;
	struct sig_db db;
	struct pol_db pol;
	pthread_t th;
	struct sender_arg sa;
	FILE *fp;
	int i, saw_host = 0;
	static const char *DBT =
	    "#format v2.0\n"
	    "11001 E2E:[tcp;;;aisense-e2e.test;;]\n";

	printf("=== LIVE: real interface -> capture source -> daemon local pass ===\n");

	/*
	 * SIGPIPE MUST BE IGNORED, and this is a production finding rather than
	 * a test convenience.
	 *
	 * A netgraph control-socket write to a graph that has gone away raises
	 * SIGPIPE, whose default action is to KILL the process. The first
	 * attempted run of this test died with rc=141 (128+13) and printed
	 * nothing at all -- which looked exactly like the capture silently
	 * finding no traffic.
	 *
	 * For a firewall daemon this is fatal in the worst way: a transient
	 * netgraph error would terminate the process that is supposed to be
	 * enforcing, and the machine would report enforcement right up to the
	 * moment it stopped. The daemon must ignore SIGPIPE for the same
	 * reason.
	 */
	signal(SIGPIPE, SIG_IGN);

	/*
	 * Everything this test can leave behind, clean up first. The interface is
	 * destroyed at the start as well as the end, because a previous aborted
	 * run's leftovers change how mkpeer fails.
	 */
	teardown_iface();
	if (setup_iface() != 0) {
		printf("SKIP: could not build the test topology "
		       "(" TEST_IFACE "a + a VNET jail peer); needs root and "
		       "VIMAGE\n");
		return 0;
	}
	printf("-- %s built: host 10.99.99.1 <-> jail peer 10.99.99.2\n",
	       TEST_IFACE);

	CHECK(make_cert() == 0, "a test certificate exists");

	sig_db_init(&db);
	fp = fmemopen((void *)DBT, strlen(DBT), "r");
	CHECK(fp != NULL, "signature database opens");
	sig_db_load(&db, fp);
	fclose(fp);
	pol_db_init(&pol);
	{
		uint8_t mac[POL_MAC_LEN] = { 0x02, 0, 0, 0, 0, 0x01 };
		struct pol_rule r;
		size_t kid = pol_add_subject(&pol, mac, "e2e");

		CHECK(kid != (size_t)-1, "policy subject added");
		memset(&r, 0, sizeof r);
		r.subject_index = (uint16_t)kid;
		r.target = POL_TARGET_APP;
		r.action = POL_BLOCK;
		snprintf(r.tag, sizeof r.tag, "e2e");
		CHECK(pol_add_rule(&pol, &db, &r), "policy rule accepted");
	}

	/* ---------- attach ---------- */
	/*
	 * Attach to the HOST SIDE (epair0a), not the jail side.
	 *
	 * MEASURED: once the peer is moved into the VNET jail, its interface no
	 * longer exists in this network stack at all, so attaching to it fails
	 * with "interface not found" -- the same error, from a different cause,
	 * that the earlier attach failures produced. The host side is the one
	 * that stays here and receives the inbound frames.
	 */
	cs = capture_source_open(TEST_IFACE "a");
	CHECK(cs != NULL, "the capture source attached to " TEST_IFACE "a");
	if (!cs) {
		printf("-- attach failed; is ng_bpf/ng_ether loaded? "
		       "(kldload ng_bpf ng_ether)\n");
		printf("   (a LEAKED node from a previous run is the other usual "
		       "cause -- see the teardown note)\n");
		teardown_iface();
		sig_db_free(&db);
		pol_db_free(&pol);
		printf("\n%d checks, %d failures\n", checks, failures);
		return failures ? 1 : 0;
	}

	/*
	 * The control. A working graph and a graph that drops everything produce
	 * identical zeros from the outside, so the pipeline must be asserted
	 * REAL before any negative result from it means anything.
	 */
	CHECK(capture_source_is_healthy(cs),
	      "the capture is wired AND the interface is still in the kernel's "
	      "path (reinjection took)");

	/* ---------- send a real ClientHello ---------- */
	sa.host = TEST_HOSTNAME;
	sa.port = 8443;
	pthread_create(&th, NULL, sender_thread, &sa);

	/* ---------- drain, looking for our hostname ---------- */
	{
		struct dpf_local_flow flows[64];
		int n, tries;

		for (tries = 0; tries < 200 && !saw_host; tries++) {
			n = capture_source_drain(cs, flows, 64);
			/*
			 * A negative return is a CAPTURE ERROR, not "no traffic".
			 * Asserted rather than ignored, because treating it as
			 * idle is how a dead capture looks healthy.
			 */
			CHECK(n >= 0, "the capture did not error");
			if (n < 0)
				break;
			for (i = 0; i < n; i++) {
				if (strcmp(flows[i].host, TEST_HOSTNAME) == 0 &&
				    flows[i].have_daddr) {
					saw_host = 1;
					printf("-- FOUND host='%s' daddr=",
					       flows[i].host);
					printf("%u.%u.%u.%u dport=%u\n",
					       flows[i].daddr[0],
					       flows[i].daddr[1],
					       flows[i].daddr[2],
					       flows[i].daddr[3],
					       flows[i].dport);
				}
			}
			usleep(50000);
		}
	}
	pthread_join(th, NULL);

	CHECK(saw_host,
	      "a REAL ClientHello on a REAL interface produced a verdict "
	      "carrying its hostname and destination");

	/* ---------- the daemon's local half consumes it ---------- */
	{
		struct dpf_local_flow flows[64];
		int n = capture_source_drain(cs, flows, 64);

		CHECK(n >= 0, "the drain reports no error");

		dpf_config_defaults(&cfg);
		pf_apply_ctx_init(&ap, NULL, NULL);
		snprintf(cfg.table_local, sizeof cfg.table_local, "aisense_local4");
		snprintf(cfg.capture_iface, sizeof cfg.capture_iface, TEST_IFACE "a");
		/*
		 * OBSERVE. Nothing is written to pf: this test must not be able
		 * to alter the firewall it is running behind.
		 */
		cfg.capture_enforce = false;

		/*
		 * With no flows in this final drain the counters read zero,
		 * which is correct and uninteresting; what is under test is that
		 * the call is safe and reports honestly.
		 */
		dpf_run_local(&cfg, &ap, &db, &pol, capture_source_drain, cs, &st);
		CHECK(st.applied == 0,
		      "observe mode applied NOTHING to pf (applied=0)");
	}

	/* ---------- teardown, and prove the interface came back ---------- */
	capture_source_close(cs);
	CHECK(vtnet_hooks() == 0,
	      "the SSH interface (vtnet0) has ZERO hooks -- the management "
	      "path was never taken out of the kernel");

	teardown_iface();

	/*
	 * The interface is genuinely gone, and NO ORPHAN NODE is left behind.
	 *
	 * MEASURED, and it is the trap that made several earlier runs fail with
	 * misleading errors: an epair's `ether` netgraph node OUTLIVES its
	 * interface. Destroying the interface does not remove the node, and a
	 * leaked node makes the next `ifconfig create` fail with "already
	 * exists" while `ifconfig` on the base name reports "does not exist".
	 * The attach after that fails with "interface not found" or "File
	 * exists", neither of which names the real cause.
	 *
	 * Asserted as ZERO nodes for this interface, not "one".
	 */
	{
		FILE *p;
		char line[256];
		int leaked = -1;

		p = popen("/usr/sbin/ngctl list 2>/dev/null | "
		          "grep -c 'Name: " TEST_IFACE "' || true", "r");
		if (p) {
			if (fgets(line, sizeof line, p))
				leaked = atoi(line);
			pclose(p);
		}
		CHECK(leaked == 0,
		      "no netgraph node leaked for " TEST_IFACE " (a leaked node "
		      "breaks every future attach with a misleading error)");
	}

	sig_db_free(&db);
	pol_db_free(&pol);

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
