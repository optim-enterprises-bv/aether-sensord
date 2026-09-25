/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * The netgraph-backed flow source: turns the capture layer into a
 * dpf_flow_source_fn so the daemon's local half runs on real traffic.
 *
 * ==================== WHY THIS IS A SEPARATE, FREEBSD-ONLY FILE ============
 *
 * ng_sni.c needs <netgraph.h>, <net/bpf.h> and friends, which exist on FreeBSD
 * and not on Linux. The daemon's local half must build on BOTH, because its
 * arithmetic is the part that can be wrong in a way that matters -- so the
 * boundary is drawn here: daemon_pf.c knows only a function pointer, and this
 * file is the only thing that knows about netgraph.
 *
 * A Linux build simply does not compile this file, and a daemon configured with
 * a capture_iface on Linux gets a source that returns an error rather than
 * silently reporting no traffic. That distinction is the whole reason
 * dpf_flow_source_fn returns -1 for an error and 0 for "nothing to say".
 *
 * ======================= THE DRAIN SEMANTICS ==============================
 *
 * One call drains up to `cap` flows, each producing at most one verdict, and
 * returns when the capture has nothing more IMMEDIATELY available (a short
 * timeout). It never blocks for long: the daemon's loop also services the
 * reputation feed, and a capture that could block indefinitely on a quiet
 * interface would stall the feed indefinitely with it.
 *
 * Flows that cannot be parsed to a hostname are still returned, with an empty
 * host. That is deliberate: they are counted by the decision layer as no_host,
 * which is how an operator finds out their coverage is thin. Dropping them here
 * would make the same flows invisible instead.
 */

#include "capture_source.h"

#include "daemon_pf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __FreeBSD__

#include "ng_sni.h"
#include "sni.h"

/*
 * The capture handle and its bounded per-call budget.
 *
 * CAPTURE_DRAIN_CAP is deliberately smaller than DPF_LOCAL_MAX_FLOWS: the
 * daemon's buffer is the upper bound on one pass, and a source that always
 * filled it would leave no room to notice that more was waiting.
 */
#define CAPTURE_DRAIN_CAP 64
#define CAPTURE_POLL_MS 20

struct capture_source {
	struct ng_sni *g;
	/*
	 * The reassembly table lives with the source, NOT in the daemon. A flow
	 * spanning segments is a property of the capture, and resetting it every
	 * pass would make every multi-segment ClientHello unparseable -- which
	 * is precisely the bug that was already fixed once in the transport
	 * layer. Keeping it here means the state outlives a pass.
	 */
	struct reasm_flow *flows;
	size_t n_flows;
};

struct capture_source *capture_source_open(const char *ifname)
{
	struct capture_source *cs;
	enum ng_sni_result r;
	char node_name[64];

	if (!ifname || ifname[0] == '\0')
		return NULL;

	cs = calloc(1, sizeof *cs);
	if (!cs)
		return NULL;

	/*
	 * THE NODE NAME MUST BE SUPPLIED, and this was a real bug: ng_sni_attach
	 * rejects a NULL nodename outright (it validates it up front), so this
	 * call returned NG_SNI_ERR_GRAPH -- "could not build the graph" -- for a
	 * reason that had nothing to do with the graph. The error names the
	 * wrong thing, which is exactly why it took a manual mkpeer, a drain
	 * probe and a named-vs-unnamed comparison to find.
	 *
	 * The name is derived from the INTERFACE rather than fixed, because
	 * NgMkSockNode fails if a node of that name already exists and a fixed
	 * name therefore makes a reattach impossible: the daemon's first
	 * restart after a crash would fail to capture, permanently, until
	 * someone removed the stale node by hand. Deriving it from the
	 * interface means one capture per interface, which is the real
	 * constraint anyway.
	 */
	snprintf(node_name, sizeof node_name, "aisense_cap_%s",
	         ifname);
	{
		/*
		 * The name length is bounded by ng_sni_attach itself
		 * (NG_SNI_NODENAME_MAX); if the interface name is long enough to
		 * overrun it, that is a configuration error and the attach will
		 * refuse -- better than silently truncating two different
		 * interfaces onto one node name.
		 */
		size_t i;
		for (i = 0; node_name[i]; i++) {
			/* netgraph names are safer without punctuation that a
			 * caller might mistake for hook syntax */
			if (node_name[i] == ':' || node_name[i] == ' ')
				node_name[i] = '_';
		}
	}

	r = ng_sni_attach(&cs->g, ifname, node_name);
	if (r != NG_SNI_OK) {
		free(cs);
		return NULL;
	}

	/*
	 * One reassembly context per capture. The daemon reads hostnames out of
	 * the verdicts ng_sni_next produces; the transport owns the table.
	 */
	cs->flows = calloc(CAPTURE_DRAIN_CAP, sizeof *cs->flows);
	if (!cs->flows) {
		ng_sni_close(cs->g);
		free(cs);
		return NULL;
	}
	cs->n_flows = CAPTURE_DRAIN_CAP;
	return cs;
}

void capture_source_close(struct capture_source *cs)
{
	if (!cs)
		return;
	/*
	 * Close BEFORE freeing the table: ng_sni_close detaches the graph, and
	 * the reassembly contexts it may still hold pointers into are freed
	 * after, not before.
	 */
	if (cs->g)
		ng_sni_close(cs->g);
	free(cs->flows);
	free(cs);
}

/*
 * Is the interface still passing traffic?
 *
 * Exposed separately because the daemon's canary needs to distinguish "the
 * capture is up and finding nothing" from "the capture has silently stopped".
 * ng_sni_healthcheck answers the second question; a source that only ever
 * returned flows could not.
 */
bool capture_source_is_healthy(const struct capture_source *cs)
{
	/*
	 * Both checks, because they fail differently and only one of them is
	 * recoverable remotely.
	 *
	 * ng_sni_reinjection_ok: is the interface still in the kernel's path?
	 * False here means the network is DOWN on that interface -- the failure
	 * that cannot be fixed over SSH, because the SSH session used it.
	 * ng_sni_is_wired: is the graph real rather than a no-op that looks
	 * identical from the outside? A broken graph and a working graph that
	 * drops everything produce the same zero verdicts.
	 */
	return cs && cs->g && ng_sni_reinjection_ok(cs->g) &&
	       ng_sni_is_wired(cs->g);
}

/*
 * The dpf_flow_source_fn.
 *
 * Returns flows written, or -1 when the capture is unusable -- which the caller
 * counts as a fault, not as an idle interface.
 */
int capture_source_drain(void *user, struct dpf_local_flow *out, size_t cap)
{
	struct capture_source *cs = user;
	size_t n = 0;

	if (!cs || !cs->g || !out)
		return -1;

	while (n < cap && n < cs->n_flows) {
		struct ng_sni_verdict v;
		int r;

		r = ng_sni_next(cs->g, &cs->flows[n], CAPTURE_POLL_MS, &v);
		if (r < 0)
			return -1; /* capture error, distinct from idle */

		/*
		 * Nothing conclusive: the flow is still being assembled, or the
		 * traffic is not something this layer can name. Stop draining
		 * rather than spinning -- the next pass will try again, and the
		 * interface has nothing more to give right now.
		 */
		if (!v.conclusive)
			break;

		memset(&out[n], 0, sizeof out[n]);
		snprintf(out[n].host, sizeof out[n].host, "%s", v.host);
		out[n].proto = v.proto;
		out[n].dport = v.dport;

		/*
		 * The tuple is carried out ONLY when the transport says it parsed
		 * one. `have_tuple` exists because a zero tuple and a real tuple
		 * that happens to be zero are otherwise identical, and a
		 * destination of 0.0.0.0 would be rendered into a pf table as a
		 * match-anything entry -- the widest possible block, produced
		 * from a frame we failed to parse.
		 */
		if (v.have_tuple) {
			memcpy(out[n].daddr, v.daddr, sizeof out[n].daddr);
			out[n].daddr_family = 4;
			out[n].have_daddr = true;
		} else {
			out[n].have_daddr = false;
		}

		/*
		 * The source MAC is in the frame but NOT in the verdict: ng_sni
		 * copies the tuple out, and the MAC is not part of a 5-tuple. On
		 * a routed firewall this is the router's address anyway (see
		 * local_decide.c), so it is left unset here rather than
		 * invented. A caller that needs per-client identity on a routed
		 * path needs a different identity source, not a guessed MAC.
		 */
		out[n].have_smac = false;
		n++;
	}

	return (int)n;
}

#else /* !__FreeBSD__ */

/*
 * On Linux the capture has no implementation. It reports an ERROR rather than
 * returning zero flow.

 * Returning zero would make "this platform cannot capture" look exactly like
 * "this platform captured and found nothing" -- and the daemon would then run
 * with local capture configured, report healthy counters, and enforce nothing.
 * A build that cannot do the work must say so.
 */
struct capture_source;

struct capture_source *capture_source_open(const char *ifname)
{
	(void)ifname;
	return NULL;
}

void capture_source_close(struct capture_source *cs)
{
	(void)cs;
}

bool capture_source_is_healthy(const struct capture_source *cs)
{
	(void)cs;
	return false;
}

int capture_source_drain(void *user, struct dpf_local_flow *out, size_t cap)
{
	(void)user;
	(void)out;
	(void)cap;
	return -1;
}

#endif /* __FreeBSD__ */
