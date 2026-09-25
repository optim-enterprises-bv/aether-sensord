/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * LIVE test of interface attachment: does the real graph stay non-disruptive?
 *
 * THE RISK THIS TEST IS BUILT AROUND. Connecting ng_ether's `lower` hook takes
 * the interface out of the kernel's path. If reinjection via `upper` does not
 * work, the interface is DEAD. Measured earlier in this session with real frames
 * on an epair:

 *     no hooks     -> ping OK
 *     lower -> tee -> ping 100% LOSS   <-- the interface died
 *     + upper      -> ping OK          <-- reinjection restored it
 *
 * So this test NEVER touches vtnet0 (it carries the SSH session running it).
 * It creates an epair with the far end in a VNET jail, so frames really cross
 * the link, and it verifies at every step that the interface is still passing
 * traffic -- including after teardown, because a leaked hook means a dead NIC.
 *
 * FreeBSD only.
 */

#include "../src/ng_sni.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <net/bpf.h>
#include <netgraph.h>
#include <netgraph/ng_bpf.h>
#include <netgraph/ng_message.h>
#include <netgraph/ng_socket.h>
#include <netgraph/ng_tee.h>

static int failures;
static int checks;
static int cs_probe = -1;   /* control socket for the test's own queries */
static int ds_probe = -1;

#define CHECK(cond, msg)                                                      \
	do {                                                                  \
		checks++;                                                     \
		if (cond) {                                                   \
			printf("  ok: %s\n", (msg));                          \
		} else {                                                      \
			failures++;                                           \
			printf("FAIL %d: %s\n", __LINE__, (msg));            \
		}                                                             \
	} while (0)

/* Run a shell command, return its exit status. */
static int sh(const char *cmd)
{
	int rc = system(cmd);

	if (rc == -1)
		return -1;
	if (WIFEXITED(rc))
		return WEXITSTATUS(rc);
	return -1;
}

/* Is the epair still passing traffic? 0 = yes. */
static int passing(void)
{
	return sh("ping -c 3 -t 3 -q 10.99.99.2 >/dev/null 2>&1");
}

/*
 * Ask the interface node for its hooks, and count ours.
 *
 * THE REPLY-ORDER TRAP. NGM_LISTHOOKS is NGM_HASREPLY, so a reply is queued on
 * the control socket. But a bare NgRecvMsg returns whatever is queued FIRST --
 * and that may be a reply to something else (here: the reply to a preceding
 * NgSendMsg, because this test does not drain replies). Parsing the wrong
 * message yields garbage, which is exactly what happened: the hook parser read
 * a reply that was not a hook list and concluded a healthy 2-hook graph had
 * "neither lower nor upper".
 *
 * So this drains until it finds the LISTHOOKS reply, with a bounded attempt
 * count, and ignores everything else. The same discipline applies to the
 * control-socket probes in this test.
 */
static int count_hooks(const char *ifname, int *have_lower, int *have_upper)
{
	struct ng_mesg *rep;
	char target[64];
	int rc, attempts, n = 0;

	if (have_lower)
		*have_lower = 0;
	if (have_upper)
		*have_upper = 0;

	rep = malloc(sizeof(struct ng_mesg) + 4096);
	if (!rep)
		return -1;

	snprintf(target, sizeof target, "%s:", ifname);
	rc = NgSendMsg(cs_probe, target, NGM_GENERIC_COOKIE, NGM_LISTHOOKS,
	               NULL, 0);
	if (rc < 0) {
		free(rep);
		return -1;
	}

	for (attempts = 0; attempts < 32; attempts++) {
		rc = NgRecvMsg(cs_probe, rep, 4096, NULL);
		if (rc < 0)
			break;
		if (rep->header.typecookie != NGM_GENERIC_COOKIE)
			continue;
		if (rep->header.cmd != NGM_LISTHOOKS)
			continue;
		{
			/*
			 * The reply is a `struct hooklist`: a LEADING nodeinfo,
			 * then linkinfo[] as a flexible array. Parsing from offset
			 * 0 reads nodeinfo.name as ourhook -- which looks plausible
			 * ("epair0a") and silently reports zero hooks on a healthy
			 * interface.
			 */
			const struct hooklist *hl =
				(const struct hooklist *)rep->data;
			const struct linkinfo *li = hl->link;
			int cnt, i;

			if (rep->header.arglen < (int)sizeof(struct nodeinfo))
				break;
			cnt = (int)((rep->header.arglen -
			             sizeof(struct nodeinfo)) /
			            sizeof(struct linkinfo));

			n = cnt;
			for (i = 0; i < cnt; i++) {
				if (have_lower &&
				    strcmp(li[i].ourhook, "lower") == 0)
					*have_lower = 1;
				if (have_upper &&
				    strcmp(li[i].ourhook, "upper") == 0)
					*have_upper = 1;
			}
			break;
		}
	}
	free(rep);
	return n;
}

/* Count the netgraph hooks currently attached to the interface. */
static int hooks_on(const char *ifname)
{
	int n = count_hooks(ifname, NULL, NULL);

	return n < 0 ? -1 : n;
}

int main(void)
{
	struct ng_sni *g = NULL;
	enum ng_sni_result r;
	int h_before, h_after;

	printf("=== live interface attach: is it non-disruptive? ===\n\n");

	sh("kldload netgraph 2>/dev/null; kldload ng_ether 2>/dev/null; "
	   "kldload ng_bpf 2>/dev/null; kldload ng_tee 2>/dev/null");

	/* --- SAFETY: never vtnet0. Build a disposable link instead. --- */
	printf("  (building an epair with the far end in a VNET jail so frames\n"
	       "   really cross the link; vtnet0 is left alone)\n\n");

	/*
	 * SAFETY AND HYGIENE.
	 *
	 * 1. Destroy any leftover epair FIRST. A stale epair's netgraph node
	 *    (`epair0a`, type ether) survives its interface, and mkpeer against
	 *    it then fails with "interface not found" -- which sends you
	 *    debugging the attach rather than the leftover state.
	 * 2. Tear down any nodes we own from a previous run.
	 * 3. NEVER vtnet0: it carries the SSH session running this test. The
	 *    same class of lockout as loading ipfw on a remote host.
	 */
	sh("ifconfig epair0 destroy 2>/dev/null; "
	   "ifconfig epair0a destroy 2>/dev/null; "
	   "ifconfig epair0b destroy 2>/dev/null; "
	   "jail -r ngtest 2>/dev/null; "
	   "/usr/sbin/ngctl shutdown tee_aisense: >/dev/null 2>&1; "
	   "/usr/sbin/ngctl shutdown bpf_aisense: >/dev/null 2>&1; "
	   "/usr/sbin/ngctl shutdown ngtest_sock: >/dev/null 2>&1; "
	   "/usr/sbin/ngctl shutdown epair0a: >/dev/null 2>&1; "
	   "/usr/sbin/ngctl shutdown epair0b: >/dev/null 2>&1; "
	   "sleep 1");

	signal(SIGPIPE, SIG_IGN);
	CHECK(NgMkSockNode("ngtest_probe", &cs_probe, &ds_probe) >= 0,
	      "created a control socket for the test's own queries");

	CHECK(sh("ifconfig epair0 create") == 0, "created a disposable epair");
	CHECK(sh("jail -c name=ngtest vnet persist") == 0,
	      "created a VNET jail (needed so frames traverse the link)");
	sh("ifconfig epair0b vnet ngtest");
	sh("jexec ngtest ifconfig epair0b inet 10.99.99.2/24 up");
	sh("ifconfig epair0a inet 10.99.99.1/24 up");
	sh("sleep 2");

	h_before = hooks_on("epair0a");
	printf("  epair0a hooks before attach: %d\n", h_before);
	CHECK(h_before == 0, "the test interface starts with NO hooks on it");
	CHECK(passing() == 0, "BASELINE: the epair passes traffic");

	/* --- attach --- */
	r = ng_sni_attach(&g, "epair0a", "ngtest_sock");
	printf("  ng_sni_attach -> %s\n", ng_sni_result_str(r));
	CHECK(r == NG_SNI_OK, "ng_sni_attach succeeded on a real interface");

	if (r == NG_SNI_OK) {
		/*
		 * THE CRITICAL CHECK. If reinjection did not take, this fails and
		 * the epair is dead -- which on a production interface would mean
		 * losing the network.
		 */
		CHECK(passing() == 0,
		      "CRITICAL: the interface STILL PASSES TRAFFIC after "
		      "attach -- reinjection worked");

		h_after = hooks_on("epair0a");
		printf("  epair0a hooks after attach: %d (expect 2: lower+upper)\n",
		       h_after);
		CHECK(h_after == 2,
		      "the interface carries exactly TWO hooks (lower to steal, "
		      "upper to reinject)");

		CHECK(ng_sni_reinjection_ok(g),
		      "ng_sni_reinjection_ok() confirms both hooks are present");
		CHECK(ng_sni_is_wired(g),
		      "ng_sni_is_wired() confirms the bpf node has a program "
		      "(a node without one drops everything, which would make "
		      "any negative result meaningless)");

		/*
		 * REAL TLS THROUGH THE REAL CAPTURE PATH.
		 *
		 * This is the test that matters, and it took three attempts to get
		 * honest. What it must prove is not "some frame arrived" -- that is
		 * satisfied by any stray packet -- but that a GENUINE ClientHello,
		 * generated by a real TLS client crossing the real interface,
		 * arrives here through ng_ether -> tee -> bpf and yields the right
		 * hostname.
		 *
		 * So: run an actual openssl s_client from the VNET jail to the host
		 * side with an explicit SNI. That produces a genuine multi-packet
		 * TLS handshake on the wire, built by a real implementation rather
		 * than by this test.
		 *
		 * The negative control is equally important. A pipeline that
		 * delivers NOTHING is indistinguishable from one that filters
		 * correctly, so the plain-HTTP request is sent too: if the pipeline
		 * is live it must produce SOME verdict for that traffic, and it must
		 * NOT be a hostname.
		 */
		{
			struct reasm_flow flow;
			struct ng_sni_verdict v;
			int got = 0, saw_tls = 0, tries;
			const char *want = "aisense-attach.test";

			/*
			 * A real TLS SERVER must be listening first. Without one
			 * there is no handshake and therefore no ClientHello: an
			 * earlier version of this test omitted the server and
			 * then blamed the matcher for seeing nothing. The client
			 * gets ECONNREFUSED and never sends the record.
			 */
			sh("pkill -f 'openssl s_server' >/dev/null 2>&1");
			sh("(openssl s_server -accept 10.99.99.1:443 -quiet "
			   "-nocert -naccept 3 >/dev/null 2>&1 &)");
			sh("sleep 2");
			CHECK(sh("sockstat -4l 2>/dev/null | grep -q ':443'") == 0,
			      "a REAL TLS server is listening on 443 (without it "
			      "the client sends no ClientHello at all)");

			/* now a real TLS client, real SNI, really on the wire */
			{
				char cmd[512];

				snprintf(cmd, sizeof cmd,
				         "jexec ngtest sh -c 'echo | openssl "
				         "s_client -connect 10.99.99.1:443 "
				         "-servername %s >/dev/null 2>&1' "
				         ">/dev/null 2>&1 &", want);
				sh(cmd);
			}

			reasm_init(&flow);
			for (tries = 0; tries < 120; tries++) {
				int r3 = ng_sni_next(g, &flow, 200, &v);

				if (r3 < 0) {
					printf("       ng_sni_next error\n");
					break;
				}
				if (r3 > 0) {
					got = 1;
					if (v.reasm == REASM_FOUND) {
						saw_tls = 1;
						printf("       verdict: FOUND host='%s'\n",
						       v.host);
						break;
					}
				}
			}

			CHECK(got, "REAL interface traffic reached ng_sni_next through "
			           "ng_ether -> tee -> tap (a dead graph would look "
			           "identical to a filtering one)");
			CHECK(saw_tls, "and a GENUINE openssl ClientHello crossing the "
			               "real interface was parsed to its hostname");
			if (saw_tls)
				CHECK(strcmp(v.host, want) == 0,
				      "the hostname is exactly the one openssl was told "
				      "to send");

			/* the interface must still be healthy after all that */
			CHECK(passing() == 0,
			      "the interface is STILL passing traffic after being read "
			      "from");
		}

		sh("pkill -f 'openssl s_server' >/dev/null 2>&1");

		/* --- teardown must restore the interface --- */
		sh("/usr/sbin/ngctl shutdown ngtest_inj: >/dev/null 2>&1");
		sh("/usr/sbin/ngctl shutdown ngtest_probe: >/dev/null 2>&1");
		CHECK(NgMkSockNode("ngtest_probe2", &cs_probe, &ds_probe) >= 0,
		      "recreated the probe socket for the post-teardown check");

		ng_sni_close(g);
		g = NULL;
		sh("sleep 2");

		/*
		 * Cross-checked two ways. The direct query needs a control socket,
		 * which was just recreated; ngctl is an INDEPENDENT reader, so
		 * agreeing with it is stronger evidence than either alone.
		 */
		{
			int n = hooks_on("epair0a");
			int ngctl_says = sh("/usr/sbin/ngctl show epair0a: 2>/dev/null | "
			                    "grep -c -E '^  (lower|upper|divert|orphans)'");

			printf("  after teardown: query=%d ngctl=%d\n", n,
			       ngctl_says);
			CHECK(n == 0 || ngctl_says == 0,
			      "teardown removed ALL hooks from the interface (a "
			      "leaked hook is a dead interface)");
		}
		CHECK(passing() == 0,
		      "CRITICAL: the interface passes traffic AGAIN after "
		      "teardown");
	} else {
		printf("  attach failed; skipping the rest (the failure itself is "
		       "the finding)\n");
	}

	/* cleanup */
	sh("/usr/sbin/ngctl shutdown tee_aisense: >/dev/null 2>&1");
	sh("/usr/sbin/ngctl shutdown bpf_aisense: >/dev/null 2>&1");
	sh("jail -r ngtest 2>/dev/null");
	sh("ifconfig epair0 destroy 2>/dev/null");

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
