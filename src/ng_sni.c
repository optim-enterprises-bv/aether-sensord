/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * FreeBSD netgraph transport: the frame source for the payload filter.
 *
 * WHY NETGRAPH AND NOT A KERNEL MODULE. On Linux, aether-af is a kernel module
 * in the netfilter FORWARD hook. That mechanism does not exist on FreeBSD and
 * cannot be built for OPNsense: /usr/src/sys is absent on the appliance, so
 * bsd.kmod.mk cannot produce a module at all. Netgraph is the measured
 * replacement -- OPNsense already ships ng_bpf.ko, ng_ether.ko, ng_socket.ko,
 * ng_tee.ko and ng_tag.ko, so nothing new has to be built or loaded beyond what
 * is already on the box.
 *
 * HOW IT WORKS, as measured end to end (see the freebsd-payload-filtering
 * skill for the exact probe and its traps):
 *
 *   1. NgMkSockNode creates a userspace socket node -- the point at which
 *      packets become reachable from this process.
 *   2. mkpeer hangs an ng_bpf node off one of our hooks. That node carries a
 *      BPF program, so the KERNEL does the per-packet byte matching.
 *   3. We connect its match output back to our own data hook, and read frames
 *      with NgRecvData. A frame reaching us IS the kernel's decision.
 *
 * THE TRAPS THIS FILE ENCODES, each of which cost a failed run:
 *
 *   a. mkpeer creates the bpf node UNNAMED, so "bpf:" does not resolve.
 *      The far end of a hook is addressable as "<mynode>:<myhook>", and
 *      NgNameNode renames it so later messages have a stable target.
 *      NGM_NAME does NOT exist -- it is NgNameNode.
 *
 *   b. An empty ifNotMatch means unmatched frames have NO destination and are
 *      dropped. A test that observes "nothing arrived" therefore passes
 *      VACUOUSLY if the graph is broken, because a broken graph also delivers
 *      nothing. Every check here is paired with a control: install an
 *      accept-all program and prove frames arrive BEFORE trusting silence.
 *
 *   c. A stale node with the same name from a previous run makes NgMkSockNode
 *      fail with an error that does not mention the collision.
 */

#include "bpf_tls.h"
#include "ng_sni.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <net/bpf.h>
#include <netgraph.h>
#include <netgraph/ng_bpf.h>
#include <netgraph/ng_message.h>
#include <netgraph/ng_socket.h>
#include <netgraph/ng_tee.h>

/* Hook names on our socket node. Ours to choose; no header defines them. */
#define OUR_HOOK_IN   "in"     /* matched data comes back to us */

#define BPF_NODE_NAME NG_BPF_NODE_TYPE "_aisense"
#define TEE_NODE_NAME "tee_aisense"

/*
 * netgraph node addresses are "name:" -- WITH the trailing colon.
 *
 * Dropping it fails with ENOENT, which reads like "no such node" rather than
 * "malformed address", so it is easy to chase the wrong thing. Adding it back
 * at every call site got missed repeatedly, so every send goes through this.
 */
static const char *ngaddr(const char *name)
{
	static char buf[NG_SNI_NODENAME_MAX + 2];

	snprintf(buf, sizeof buf, "%s:", name);
	return buf;
}

struct ng_sni {
	int cs;                  /* control socket */
	int ds;                  /* data socket */
	char node[NG_SNI_NODENAME_MAX];
	char iface[NG_SNI_NODENAME_MAX];
	char tee_node[NG_SNI_NODENAME_MAX];
	char bpf_node[NG_SNI_NODENAME_MAX];
	int iface_hooked;        /* 1 once iface:lower is connected (interface
	                          * is DOWN until reinjected) */
	int reinjected;          /* 1 once tee:left -> iface:upper succeeded */
	int hooked;
};

const char *ng_sni_result_str(enum ng_sni_result r)
{
	switch (r) {
	case NG_SNI_OK:
		return "ok";
	case NG_SNI_ERR_NO_DEV:
		return "interface not found";
	case NG_SNI_ERR_NO_NETGRAPH:
		return "netgraph unavailable (kldload netgraph?)";
	case NG_SNI_ERR_GRAPH:
		return "could not build the graph";
	case NG_SNI_ERR_PROGRAM:
		return "the BPF program was rejected";
	case NG_SNI_ERR_NAME:
		return "a netgraph node with that name already exists";
	case NG_SNI_ERR_NOT_PASSING:
		return "the interface was hooked but could NOT be reinjected -- "
		       "it is not passing traffic";
	default:
		return "?";
	}
}

/*
 * Install a program on the bpf node.
 *
 * `insns`/`n` is the program; ifNotMatch is left EMPTY on purpose, which is
 * what makes a non-matching frame go nowhere. The length must come from the
 * library's own macro: computing it by hand returns EINVAL, which reads exactly
 * like "your program is invalid" and sends you debugging the wrong thing.
 */
static int set_program(int cs, const char *node,
                       const struct bpf_insn *insns, int n)
{
	struct ng_bpf_hookprog *p;
	int sz, rc;

	sz = (int)NG_BPF_HOOKPROG_SIZE(n);
	p = calloc(1, (size_t)sz);
	if (!p)
		return -1;

	strncpy(p->thisHook, "in", NG_HOOKSIZ - 1);
	strncpy(p->ifMatch, "match", NG_HOOKSIZ - 1);
	p->ifNotMatch[0] = '\0';   /* no destination: unmatched is dropped */
	p->bpf_prog_len = n;
	memcpy(p->bpf_prog, insns, (size_t)n * sizeof *insns);

	rc = NgSendMsg(cs, node, NGM_BPF_COOKIE, NGM_BPF_SET_PROGRAM, p,
	               (size_t)sz);
	free(p);
	return rc;
}

/*
 * Install the DELIVERY program: IPv4 + TCP + not a fragment + non-empty
 * payload.
 *
 * This is deliberately NOT the ClientHello pattern. Measured: OpenSSL 3.5 sends
 * a 1545-byte ClientHello, the first segment carries 1448 bytes, and the rest
 * arrives in a SECOND segment that does not begin with 0x16. Filtering delivery
 * on the pattern dropped that segment, so the reassembler waited for bytes that
 * could never arrive and no hostname was ever produced -- while the counters
 * reported a healthy matcher.
 *
 * Delivering TCP payload in general is also strictly more truthful: "we could
 * not read a hostname" then means the reassembler saw the bytes and could not
 * parse a ClientHello, rather than that the kernel never let us look. The two
 * are very different answers to an operator.
 */
static int install_delivery(int cs, const char *node)
{
	return set_program(cs, node, bpf_tcp_payload, BPF_TCP_PAYLOAD_LEN);
}

/*
 * The capture topology. Built in this order because the interface is
 * OUT OF SERVICE from the moment `lower` is connected until `upper` is
 * connected -- so the reinjection is not an optimisation, it is the step that
 * puts the network back. See the long note in ng_sni.h for the measurement.
 *
 *     1. NgMkSockNode                 our socket node
 *     2. mkpeer  iface:lower -> tee   steal incoming (interface now down)
 *     3. connect tee:left -> iface:upper   REINJECT (interface back up)
 *     4. mkpeer  tee:right2left -> bpf     the tap (a copy, cannot drop)
 *     5. connect bpf:match -> our hook     only interesting frames reach us
 *
 * The order of 2 and 3 is what makes a failure at 3 recoverable: if 3 cannot be
 * made, the graph must be torn down completely, because leaving the interface
 * with `lower` connected and nothing on `upper` is a dead interface.
 */
enum ng_sni_result ng_sni_attach(struct ng_sni **out, const char *ifname,
                                 const char *nodename)
{
	struct ng_sni *g;
	struct ngm_mkpeer mp;
	struct ngm_connect cn;
	char path[NG_SNI_NODENAME_MAX + NG_HOOKSIZ + 2];
	int rc;

	if (!out || !ifname || !nodename)
		return NG_SNI_ERR_GRAPH;
	if (strlen(nodename) >= NG_SNI_NODENAME_MAX ||
	    strlen(ifname) >= NG_SNI_NODENAME_MAX)
		return NG_SNI_ERR_NAME;

	g = calloc(1, sizeof *g);
	if (!g)
		return NG_SNI_ERR_GRAPH;
	strlcpy(g->node, nodename, sizeof g->node);
	strlcpy(g->iface, ifname, sizeof g->iface);
	strlcpy(g->tee_node, TEE_NODE_NAME, sizeof g->tee_node);
	strlcpy(g->bpf_node, BPF_NODE_NAME, sizeof g->bpf_node);
	g->cs = g->ds = -1;

	rc = NgMkSockNode(g->node, &g->cs, &g->ds);
	if (rc < 0) {
		/* A stale node with this name is the usual cause, and the error
		 * does not say so. */
		free(g);
		return NG_SNI_ERR_NAME;
	}

	/*
	 * A TIMEOUT ON THE CONTROL SOCKET, and it is not optional.
	 *
	 * Every message sent here can have a reply queued (NGM_HASREPLY), and
	 * every reply we do not read stays queued. Querying the graph later --
	 * as ng_sni_reinjection_ok() does -- therefore has to DRAIN past other
	 * replies to find its own, and a bare NgRecvMsg with nothing left to
	 * read BLOCKS FOREVER. A firewall daemon hanging on a control socket is
	 * a worse failure than a wrong answer.
	 *
	 * With a timeout the drain degrades to "I could not confirm", which the
	 * caller can handle.
	 */
	{
		struct timeval tv;

		tv.tv_sec = 2;
		tv.tv_usec = 0;
		(void)setsockopt(g->cs, SOL_SOCKET, SO_RCVTIMEO, &tv,
		                 sizeof tv);
	}

	/* -- 2. steal incoming: iface:lower -> tee:right -------------------- */
	memset(&mp, 0, sizeof mp);
	strlcpy(mp.type, NG_TEE_NODE_TYPE, sizeof mp.type);
	strlcpy(mp.ourhook, "lower", sizeof mp.ourhook);
	strlcpy(mp.peerhook, NG_TEE_HOOK_RIGHT, sizeof mp.peerhook);
	{
		char target[NG_SNI_NODENAME_MAX + 2];

		snprintf(target, sizeof target, "%s:", ifname);
		rc = NgSendMsg(g->cs, target, NGM_GENERIC_COOKIE, NGM_MKPEER,
		               &mp, sizeof mp);
	}
	if (rc < 0) {
		ng_sni_close(g);
		return NG_SNI_ERR_NO_DEV;
	}
	g->iface_hooked = 1;

	/* Name the tee so the next steps have a target. mkpeer left it unnamed. */
	snprintf(path, sizeof path, "%s:lower", ifname);
	rc = NgNameNode(g->cs, path, "%s", g->tee_node);
	if (rc < 0) {
		ng_sni_close(g);
		return NG_SNI_ERR_NAME;
	}

	/*
	 * -- 3. REINJECT: iface:upper -> tee:left --------------------------
	 * THE INTERFACE IS DOWN UNTIL THIS SUCCEEDS. If it fails, the graph must
	 * be torn down completely -- a partially-built graph leaves `lower`
	 * connected with nothing forwarding back, which is a dead interface.
	 * ng_sni_close handles that, and the caller gets a hard error rather
	 * than a silent outage.
	 *
	 * THE MESSAGE GOES TO THE ETHER NODE, NOT THE TEE. Measured: sending
	 * this to the tee returns ENOENT, while sending it to the interface
	 * succeeds. Both are "our hook" from the other end's point of view, so
	 * this is not obvious from the struct -- the working ngctl form is
	 * `connect epair0a: t: upper left`, i.e. the target node is the one
	 * whose `ourhook` is named.
	 *
	 * AND THE NODE ADDRESS NEEDS ITS TRAILING COLON. "x_tee" fails with
	 * ENOENT; "x_tee:" resolves. netgraph node paths are "name:", and
	 * dropping the colon produces an error that reads like a missing node
	 * rather than a malformed address.
	 */
	memset(&cn, 0, sizeof cn);
	{
		char target[NG_SNI_NODENAME_MAX + 2];

		snprintf(target, sizeof target, "%s:", ifname);
		strlcpy(cn.ourhook, "upper", sizeof cn.ourhook);
		strlcpy(cn.peerhook, NG_TEE_HOOK_LEFT, sizeof cn.peerhook);
		snprintf(cn.path, sizeof cn.path, "%s:", g->tee_node);
		rc = NgSendMsg(g->cs, target, NGM_GENERIC_COOKIE, NGM_CONNECT,
		               &cn, sizeof cn);
	}
	if (rc < 0) {
		ng_sni_close(g);
		return NG_SNI_ERR_NOT_PASSING;
	}
	g->reinjected = 1;

	/* -- 4. the TAP: tee:right2left -> bpf:in -------------------------- */
	memset(&mp, 0, sizeof mp);
	strlcpy(mp.type, NG_BPF_NODE_TYPE, sizeof mp.type);
	strlcpy(mp.ourhook, NG_TEE_HOOK_RIGHT2LEFT, sizeof mp.ourhook);
	strlcpy(mp.peerhook, "in", sizeof mp.peerhook);
	rc = NgSendMsg(g->cs, ngaddr(g->tee_node), NGM_GENERIC_COOKIE,
	               NGM_MKPEER, &mp, sizeof mp);
	if (rc < 0) {
		ng_sni_close(g);
		return NG_SNI_ERR_GRAPH;
	}

	/* TRAP: mkpeer leaves the bpf node unnamed, so "bpf:" does not resolve.
	 * The far end of the tee's tap hook is addressable as a hook path. */
	snprintf(path, sizeof path, "%s:" NG_TEE_HOOK_RIGHT2LEFT, g->tee_node);
	rc = NgNameNode(g->cs, path, "%s", g->bpf_node);
	if (rc < 0) {
		ng_sni_close(g);
		return NG_SNI_ERR_NAME;
	}

	/* -- 5. bpf:match -> our socket node ------------------------------- */
	memset(&cn, 0, sizeof cn);
	{
		char target[NG_SNI_NODENAME_MAX + 2];

		snprintf(target, sizeof target, "%s:", g->node);
		strlcpy(cn.path, target, sizeof cn.path);
	}
	strlcpy(cn.ourhook, "match", sizeof cn.ourhook);
	strlcpy(cn.peerhook, OUR_HOOK_IN, sizeof cn.peerhook);
	rc = NgSendMsg(g->cs, ngaddr(g->bpf_node), NGM_GENERIC_COOKIE,
	               NGM_CONNECT, &cn, sizeof cn);
	if (rc < 0) {
		ng_sni_close(g);
		return NG_SNI_ERR_GRAPH;
	}

	if (install_delivery(g->cs, ngaddr(g->bpf_node)) < 0) {
		ng_sni_close(g);
		return NG_SNI_ERR_PROGRAM;
	}

	g->hooked = 1;
	*out = g;
	return NG_SNI_OK;
}

bool ng_sni_is_wired(const struct ng_sni *g)
{
	/*
	 * A bpf node with NO program drops everything, so "no traffic arrived" is
	 * not evidence of filtering -- a working graph that matches nothing and a
	 * broken graph look identical from here. Asking the node for its stats
	 * distinguishes them.
	 *
	 * This checks the CAPTURE path. It deliberately does NOT check that the
	 * interface is still passing traffic: that requires watching counters
	 * over time, and a caller that cares (because it just attached to a live
	 * interface) should use ng_sni_reinjection_ok().
	 */
	if (!g || !g->hooked || g->cs < 0 || g->bpf_node[0] == '\0')
		return false;
	if (!g->reinjected)
		return false;
	return NgSendMsg(g->cs, ngaddr(g->bpf_node), NGM_BPF_COOKIE,
	                 NGM_BPF_GET_STATS, "match", 6) >= 0;
}

int ng_sni_next(struct ng_sni *g, struct reasm_flow *flow, int timeout_ms,
                struct ng_sni_verdict *verdict)
{
	struct timeval tv;
	unsigned char frame[REASM_CAP + 64];
	const uint8_t *payload = NULL;
	size_t payload_len = 0, need = 0;
	uint32_t seq = 0;
	char host[SNI_MAX_NAME];
	enum sni_result sr;
	ssize_t n;

	if (!g || g->ds < 0 || !flow || !verdict)
		return -1;

	memset(verdict, 0, sizeof *verdict);

	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;
	if (setsockopt(g->ds, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0)
		return -1;

	/*
	 * A short read is normal: netgraph delivers packet by packet, and a
	 * frame larger than our buffer arrives truncated. The parser then
	 * reports INCOMPLETE, which is the honest answer.
	 */
	/*
	 * THE OUTPUT-ARGUMENT TRAP, and it is a CRASH, not a wrong value.
	 *
	 * NgRecvData's 4th parameter is an OUTPUT buffer: it RECEIVES the name of
	 * the hook the data arrived on. Passing OUR_HOOK_IN ("in") there is
	 * writing into a string literal -- read-only memory -- so this
	 * segfaults.
	 *
	 * What makes it vicious: it only fires when a frame ACTUALLY ARRIVES.
	 * While the matcher was dropping everything the call returned EAGAIN
	 * first and the process survived, so the bug was invisible in exactly the
	 * configuration where the rest of the pipeline was being tested. The
	 * first real matching ClientHello would have killed the daemon.
	 */
	{
		char arrived_on[NG_HOOKSIZ];

		n = NgRecvData(g->ds, frame, sizeof frame, arrived_on);
	}
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0; /* nothing to do */
		return -1;        /* graph broken */
	}
	if (n == 0)
		return 0;

	sr = sni_extract_frame(frame, (size_t)n, host, sizeof host, &need,
	                       &payload, &payload_len, &seq);

	/*
	 * DO NOT GATE ON "IS THIS TLS". Feed every TCP payload in the flow to the
	 * reassembler and let IT decide; that is the entire reason it exists.
	 *
	 * An earlier version returned early when sni_extract_frame() said
	 * SNI_NOT_TLS, which looked reasonable and was fatal: a ClientHello that
	 * spans segments has a FIRST segment starting with 0x16 and a
	 * CONTINUATION segment starting with arbitrary ciphertext-ish bytes. The
	 * gate discarded exactly the continuations, so the reassembler waited for
	 * bytes that had already been thrown away and never returned a hostname.
	 *
	 * MEASURED, and this is the common case rather than an edge case: OpenSSL
	 * 3.5's 1545-byte ClientHello (ML-KEM hybrid key shares) arrives as 1448
	 * bytes + 95 bytes, and the 95-byte segment is the continuation.
	 *
	 * `payload == NULL` still means there is no TCP payload at all (a pure
	 * ACK, a non-TCP frame, a fragment) and there is nothing to reassemble.
	 */
	if (payload == NULL || payload_len == 0) {
		verdict->reasm = REASM_NOT_TLS;
		verdict->conclusive = sni_result_is_conclusive(sr);
		return 1;
	}

	/*
	 * Hand the TLS bytes to the reassembler rather than deciding from one
	 * frame. This is the whole reason the reassembler exists: a ClientHello
	 * routinely spans segments, and a per-frame decision would miss exactly
	 * those flows -- the ones a user is most likely to be using, since
	 * modern browsers send large ClientHellos.
	 *
	 * The sequence number comes from the frame, so segments are placed at
	 * their real offsets and out-of-order delivery is handled correctly. A
	 * caller still owns the per-flow reassembly state: two flows interleaved
	 * through this function would corrupt each other, so `flow` must be
	 * keyed by the 5-tuple (see ng_sni_verdict, which carries it).
	 */
	verdict->reasm = reasm_feed(flow, seq, payload, payload_len, host,
	                            sizeof host);
	verdict->truncated = reasm_was_truncated(flow);
	if (verdict->reasm == REASM_FOUND)
		strlcpy(verdict->host, host, sizeof verdict->host);
	verdict->conclusive = !reasm_wants_more(flow, verdict->reasm);
	return 1;
}

/*
 * Fetch the interface's hook list, draining replies until the right one arrives.
 *
 * THE REPLY-ORDER TRAP. NGM_LISTHOOKS is NGM_HASREPLY, so a reply is queued --
 * but a bare NgRecvMsg returns whatever is queued FIRST, which may be a reply to
 * something else entirely. Parsing the wrong message yields garbage, and the
 * garbage looks like a plausible answer: this exact bug made a healthy
 * two-hook graph read as "neither lower nor upper", i.e. a false alarm on a
 * working interface. Only the reply whose typecookie AND cmd match is used.
 *
 * Returns the number of hooks, or -1. `have_lower`/`have_upper` (optional) are
 * set when our own hooks are present.
 */
static int fetch_hooks(int cs, const char *ifname, int *have_lower,
                       int *have_upper)
{
	struct ng_mesg *rep;
	char target[NG_SNI_NODENAME_MAX + 2];
	int rc, attempts, n = -1;

	if (have_lower)
		*have_lower = 0;
	if (have_upper)
		*have_upper = 0;

	rep = malloc(sizeof(struct ng_mesg) + 4096);
	if (!rep)
		return -1;

	snprintf(target, sizeof target, "%s:", ifname);
	rc = NgSendMsg(cs, target, NGM_GENERIC_COOKIE, NGM_LISTHOOKS, NULL, 0);
	if (rc < 0) {
		free(rep);
		return -1;
	}

	/*
	 * The drain budget must exceed the number of replies the ATTACH sequence
	 * queued, or the LISTHOOKS reply is never reached and the function
	 * returns a false negative. Measured: attach sends ~7 NGM_HASREPLY
	 * messages (2 mkpeer, 2 connect, 2 name, 1 set_program), so 8 attempts
	 * sat right on the boundary and intermittently failed. 32 gives room.
	 */
	for (attempts = 0; attempts < 32; attempts++) {
		rc = NgRecvMsg(cs, rep, 4096, NULL);
		if (rc < 0)
			break;
		if (rep->header.typecookie != NGM_GENERIC_COOKIE ||
		    rep->header.cmd != NGM_LISTHOOKS)
			continue;
		{
			/*
			 * THE LAYOUT TRAP. The NGM_LISTHOOKS reply is a `struct
			 * hooklist`, which is a `struct nodeinfo` FOLLOWED BY a
			 * flexible array of `struct linkinfo`:
			 *
			 *     struct hooklist {
			 *         struct nodeinfo nodeinfo;
			 *         struct linkinfo link[];
			 *     };
			 *
			 * Reading `rep->data` as linkinfo[] from offset 0 is wrong
			 * in a way that looks almost right: nodeinfo also begins
			 * with a 32-byte name field, so `ourhook` silently reads as
			 * the NODE's name ("epair0a") instead of a hook name, and
			 * every hook lookup fails on a healthy interface. Measured
			 * exactly that -- a false alarm on a graph where ngctl
			 * showed both hooks present.
			 *
			 * The links therefore start AFTER the leading nodeinfo, and
			 * the count comes from the remaining bytes.
			 */
			const struct hooklist *hl =
				(const struct hooklist *)rep->data;
			const struct linkinfo *li = hl->link;
			int cnt, i;

			if (rep->header.arglen < (int)sizeof(struct nodeinfo)) {
				free(rep);
				return -1;
			}
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

/*
 * Tear down, and PUT THE INTERFACE BACK.
 *
 * Order matters more than anywhere else in this file. `lower` is connected and
 * the kernel path runs through our tee; the interface only returns to normal
 * when BOTH of the tee's hooks are gone. So:
 *
 *   1. shut the bpf node    -- nothing more is needed from the tap
 *   2. shut the TEE         -- removes BOTH hooks from the interface, which is
 *                              what restores its normal path
 *   3. ASK the interface    -- confirm no hooks remain, and say so loudly if
 *                              any do
 *
 * Step 3 is not paranoia. A teardown that reports success while the NIC is
 * silent is the worst available outcome, because the operator stops looking.
 * ng_ether(4): "When no hooks are connected, upper and lower are in effect
 * connected together, so that packets flow normally upwards and downwards."
 */
void ng_sni_close(struct ng_sni *g)
{
	if (!g)
		return;

	if (g->cs >= 0) {
		if (g->bpf_node[0])
			(void)NgSendMsg(g->cs, ngaddr(g->bpf_node),
			                NGM_GENERIC_COOKIE, NGM_SHUTDOWN, NULL, 0);
		if (g->tee_node[0])
			(void)NgSendMsg(g->cs, ngaddr(g->tee_node),
			                NGM_GENERIC_COOKIE, NGM_SHUTDOWN, NULL, 0);
		(void)NgSendMsg(g->cs, ngaddr(g->node),
		                NGM_GENERIC_COOKIE, NGM_SHUTDOWN, NULL, 0);

		/*
		 * Ask the interface whether it still has hooks. If it does, it is
		 * not passing traffic and the caller must know -- rather than
		 * being told "stopped cleanly" over a dead NIC.
		 */
		if (g->iface_hooked && g->iface[0]) {
			char target[NG_SNI_NODENAME_MAX + 2];
			struct ng_mesg *rep = NULL;

			snprintf(target, sizeof target, "%s:", g->iface);
			if (NgSendMsg(g->cs, target, NGM_GENERIC_COOKIE,
			              NGM_LISTHOOKS, NULL, 0) >= 0 &&
			    (rep = malloc(sizeof(struct ng_mesg) + 1024)) != NULL &&
			    NgRecvMsg(g->cs, rep, 1024, NULL) >= 0 &&
			    rep->header.arglen >= sizeof(struct linkinfo)) {
				fprintf(stderr,
				        "ng_sni: WARNING: %s still has netgraph "
				        "hooks connected and is NOT passing "
				        "traffic. Restore it with: ngctl shutdown "
				        "%s:\n",
				        g->iface, g->tee_node);
			}
			free(rep);
		}
	}

	if (g->ds >= 0)
		close(g->ds);
	if (g->cs >= 0)
		close(g->cs);
	free(g);
}

/*
 * Is the interface still carrying traffic?
 *
 * A caller that attached to a LIVE interface needs to know this, because the
 * failure it guards against is the one that cannot be recovered remotely: if
 * reinjection did not take, the interface is dead and the operator has lost the
 * network. Returns true when no hooks remain on the interface (its normal
 * state), false when something is still attached.
 */
bool ng_sni_reinjection_ok(const struct ng_sni *g)
{
	int have_lower = 0, have_upper = 0;
	int cs_probe = -1, ds_probe = -1;
	int rc;

	if (!g || !g->iface[0])
		return false;

	/*
	 * A FRESH SOCKET, NOT g->cs. The attach sequence left ~7 unread replies
	 * queued on g->cs, and a query sent on that socket has to drain past all
	 * of them before it sees its own -- which a bounded drain can miss,
	 * producing a FALSE NEGATIVE on a perfectly healthy interface. Measured:
	 * exactly that, reported as "neither lower nor upper" while ngctl showed
	 * both hooks present.
	 *
	 * A new socket's queue holds only this query's reply, so one read is
	 * enough and the result is deterministic.
	 *
	 * The interface is deliberately queried by NAME rather than through our
	 * tee node: asking the interface is what proves the kernel's own node
	 * still has both hooks.
	 */
	rc = NgMkSockNode("aisense_check", &cs_probe, &ds_probe);
	if (rc < 0)
		return false;
	(void)ds_probe;
	{
		struct timeval tv;

		tv.tv_sec = 2;
		tv.tv_usec = 0;
		(void)setsockopt(cs_probe, SOL_SOCKET, SO_RCVTIMEO, &tv,
		                 sizeof tv);
	}

	/*
	 * Our tee deliberately has TWO hooks on the interface (lower and upper),
	 * so a healthy attached graph reports hooks. What matters is that BOTH
	 * of ours are present: with only `lower` the interface is DEAD, because
	 * nothing forwards the packets back to the kernel.
	 */
	rc = fetch_hooks(cs_probe, g->iface, &have_lower, &have_upper);
	(void)NgSendMsg(cs_probe, "aisense_check:", NGM_GENERIC_COOKIE,
	                NGM_SHUTDOWN, NULL, 0);
	close(ds_probe);
	close(cs_probe);
	if (rc < 0)
		return false;

	if (have_lower && !have_upper) {
		/* Print rather than only returning false: the caller may be a
		 * daemon whose return value nobody reads, and this is the state
		 * that means the operator has lost the network. */
		fprintf(stderr,
		        "ng_sni: %s has `lower` hooked but NOT `upper` -- it is "
		        "NOT passing traffic. Restore it with: ngctl shutdown "
		        "%s:\n",
		        g->iface, g->tee_node);
	}
	return have_lower && have_upper;
}
