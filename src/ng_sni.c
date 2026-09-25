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

/* Hook names on our socket node. Ours to choose; no header defines them. */
#define OUR_HOOK_OUT  "out"    /* data goes out to the matcher   */
#define OUR_HOOK_IN   "in"     /* matched data comes back to us  */

#define BPF_NODE_NAME "aisense_bpf"

struct ng_sni {
	int cs;                  /* control socket */
	int ds;                  /* data socket */
	char node[NG_SNI_NODENAME_MAX];
	char bpf_node[NG_SNI_NODENAME_MAX];
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
 * The coarse per-packet filter, run in kernel.
 *
 * OFFSETS, computed rather than guessed -- getting these wrong is invisible
 * because the program still installs and simply never matches, which looks
 * exactly like the matcher working correctly:
 *
 *   Ethernet 14 + IPv4 20 + TCP 20 = 54 -> the TLS record header
 *   byte 54 = content type 0x16, 55 = version major 0x03
 *   so the halfword at 54 is 0x1603
 *   +5 for the record header -> 59 = the handshake message type
 *
 * That is all a per-packet program can honestly do: it cannot see a name that
 * spans segments, which is exactly why the reassembler exists one layer up.
 *
 * KNOWN LIMITATION, stated rather than implied: fixed offsets mean a
 * VLAN-TAGGED frame shifts everything by 4 and will not match, so on a trunk
 * port this program silently matches nothing. A caller must not read "no
 * matches on the trunk" as "no TLS".
 */
static int install_match(int cs, const char *node)
{
	static struct bpf_insn prog[] = {
		/* A = the TLS content-type/version halfword at offset 54 */
		{ BPF_LD | BPF_H | BPF_ABS, 0, 0, 54 },
		/* if A == 0x1603 (handshake, TLS 1.x) continue, else drop */
		{ BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 0x1603 },
		{ BPF_RET | BPF_K, 0, 0, 0 },
		/* A = the handshake message type at offset 59 */
		{ BPF_LD | BPF_B | BPF_ABS, 0, 0, 59 },
		/* if A == 0x01 (ClientHello) accept, else drop */
		{ BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 0x01 },
		{ BPF_RET | BPF_K, 0, 0, 0 },
		{ BPF_RET | BPF_K, 0, 0, 0xffffffff }, /* accept the whole frame */
	};

	return set_program(cs, node, prog, (int)(sizeof prog / sizeof prog[0]));
}

enum ng_sni_result ng_sni_attach(struct ng_sni **out, const char *ifname,
                                 const char *nodename)
{
	struct ng_sni *g;
	struct ngm_mkpeer mp;
	struct ngm_connect cn;
	char path[NG_SNI_NODENAME_MAX + NG_HOOKSIZ + 2];
	int rc;

	(void)ifname; /* interface attachment is ng_ether, a later step */

	if (!out || !nodename)
		return NG_SNI_ERR_GRAPH;
	if (strlen(nodename) >= NG_SNI_NODENAME_MAX)
		return NG_SNI_ERR_NAME;

	g = calloc(1, sizeof *g);
	if (!g)
		return NG_SNI_ERR_GRAPH;
	strlcpy(g->node, nodename, sizeof g->node);
	g->cs = g->ds = -1;

	rc = NgMkSockNode(g->node, &g->cs, &g->ds);
	if (rc < 0) {
		/* A stale node with this name is the usual cause, and the error
		 * does not say so -- hence the distinct result value. */
		free(g);
		return NG_SNI_ERR_NAME;
	}

	/* Hang a bpf node off our OUT hook. mkpeer leaves it unnamed. */
	memset(&mp, 0, sizeof mp);
	strlcpy(mp.type, NG_BPF_NODE_TYPE, sizeof mp.type);
	strlcpy(mp.ourhook, OUR_HOOK_OUT, sizeof mp.ourhook);
	strlcpy(mp.peerhook, "in", sizeof mp.peerhook);
	rc = NgSendMsg(g->cs, g->node, NGM_GENERIC_COOKIE, NGM_MKPEER, &mp,
	               sizeof mp);
	if (rc < 0) {
		ng_sni_close(g);
		return NG_SNI_ERR_GRAPH;
	}

	/*
	 * TRAP (a): address the auto-created node through the HOOK PATH, then
	 * give it a name. "bpf:" alone does not resolve -- the node has no name
	 * until NgNameNode is called.
	 */
	snprintf(path, sizeof path, "%s:%s", g->node, OUR_HOOK_OUT);
	strlcpy(g->bpf_node, BPF_NODE_NAME, sizeof g->bpf_node);
	/*
	 * NgNameNode is printf-style (__printflike(3,4)), so the name goes
	 * through a format string rather than being passed directly. Passing it
	 * directly works only while the name contains no '%' -- which is why the
	 * probe appeared fine and the strict build flagged it.
	 */
	rc = NgNameNode(g->cs, path, "%s", g->bpf_node);
	if (rc < 0) {
		ng_sni_close(g);
		return NG_SNI_ERR_NAME;
	}

	/* Connect the matcher's match output back to us. */
	memset(&cn, 0, sizeof cn);
	strlcpy(cn.path, g->bpf_node, sizeof cn.path);
	strlcpy(cn.ourhook, "match", sizeof cn.ourhook);
	strlcpy(cn.peerhook, OUR_HOOK_IN, sizeof cn.peerhook);
	rc = NgSendMsg(g->cs, g->node, NGM_GENERIC_COOKIE, NGM_CONNECT, &cn,
	               sizeof cn);
	if (rc < 0) {
		ng_sni_close(g);
		return NG_SNI_ERR_GRAPH;
	}

	if (install_match(g->cs, g->bpf_node) < 0) {
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
	 * A bpf node with NO program drops everything, so "no traffic arrived"
	 * is not evidence of filtering -- a working graph that matches nothing
	 * and a broken graph look identical from here. Asking the node for its
	 * program is what distinguishes them, and it is why this function
	 * exists rather than a caller inferring health from silence.
	 */
	if (!g || !g->hooked || g->cs < 0 || g->bpf_node[0] == '\0')
		return false;
	return NgSendMsg(g->cs, g->bpf_node, NGM_BPF_COOKIE,
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
	n = NgRecvData(g->ds, frame, sizeof frame, OUR_HOOK_IN);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0; /* nothing to do */
		return -1;        /* graph broken */
	}
	if (n == 0)
		return 0;

	sr = sni_extract_frame(frame, (size_t)n, host, sizeof host, &need,
	                       &payload, &payload_len, &seq);

	if (sr == SNI_NOT_TLS || payload == NULL) {
		verdict->reasm = REASM_NOT_TLS;
		verdict->conclusive = sni_result_is_conclusive(sr);
		return 1;
	}

	if (payload_len == 0) {
		verdict->reasm = REASM_NOT_TLS;
		verdict->conclusive = true;
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

void ng_sni_close(struct ng_sni *g)
{
	if (!g)
		return;

	/*
	 * Shutdown in REVERSE order of creation. Netgraph reference-counts
	 * hooks, so tearing down out of order leaves the peer attached -- which
	 * is how an interface ends up carrying a node nobody can account for.
	 */
	if (g->cs >= 0) {
		if (g->bpf_node[0])
			(void)NgSendMsg(g->cs, g->bpf_node,
			                NGM_GENERIC_COOKIE, NGM_SHUTDOWN, NULL, 0);
		(void)NgSendMsg(g->cs, g->node, NGM_GENERIC_COOKIE,
		                NGM_SHUTDOWN, NULL, 0);
	}
	if (g->ds >= 0)
		close(g->ds);
	if (g->cs >= 0)
		close(g->cs);
	free(g);
}
