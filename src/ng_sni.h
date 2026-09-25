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
 *   1. ng_ether attaches to the NIC WITHOUT taking it from the kernel. This is
 *      the property that matters: netmap would steal the interface and take the
 *      network down, which is unacceptable on a production firewall. ng_ether
 *      is passive.
 *   2. ng_bpf is connected downstream and carries a BPF program that matches
 *      the bytes we care about, IN KERNEL, per packet.
 *   3. Matching packets are delivered to a userspace socket. The kernel has
 *      already done the filtering; userspace does the parsing and decides.
 *
 * THE TRAP THIS FILE ENCODES, because it cost the most to find: mkpeer creates
 * the bpf node UNNAMED, so "bpf:" does not resolve and the obvious
 * NgSendMsg("bpf:", ...) fails. The far end of a hook is addressable as
 * "<mynode>:<myhook>" -- and it is then nameable with NgNameNode.
 *
 * The second trap: an ng_bpf node with NO program installed does not pass
 * traffic, it DROPS everything. A test that observes "nothing arrives" after
 * installing a matching program therefore passes vacuously if the graph was
 * broken. Every check in this file is paired with a control.
 */

#ifndef AETHER_SENSORD_NG_SNI_H
#define AETHER_SENSORD_NG_SNI_H

#include "reassembly.h"
#include "sni.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NG_SNI_NODENAME_MAX 32

/*
 * A live capture graph: ng_ether lower/upper -> ng_tee -> ng_bpf -> this process.
 *
 * Opaque on purpose. Callers must not poke at the node names or the socket
 * descriptors: netgraph graphs are reference-counted and a caller that shuts one
 * node down out of order leaves the rest attached, which is how an interface
 * ends up with a zombie node on it.
 */
struct ng_sni;

enum ng_sni_result {
	NG_SNI_OK = 0,
	NG_SNI_ERR_NO_DEV,     /* the interface does not exist */
	NG_SNI_ERR_NO_NETGRAPH, /* netgraph is not available in this kernel */
	NG_SNI_ERR_GRAPH,      /* building the graph failed */
	NG_SNI_ERR_PROGRAM,    /* the BPF program was rejected */
	NG_SNI_ERR_NAME,       /* a node with that name already exists */
	/* The interface is up but frames are not coming back to the kernel.
	 * Treated as FATAL: see the note on reinjection below. */
	NG_SNI_ERR_NOT_PASSING
};

const char *ng_sni_result_str(enum ng_sni_result r);

/*
 * Attach a capture graph to `ifname`.
 *
 * `nodename` is the name this process's socket node takes; it must be unique,
 * because netgraph names are global and a stale node from a previous run will
 * cause the attach to fail with an error that looks unrelated.
 *
 * ============================ IT IS NOT PASSIVE ============================
 *
 * An earlier version of this file claimed the attachment was "PASSIVE: frames
 * are COPIED to us; they are not removed from the kernel's path". THAT WAS
 * WRONG, and wrong in the dangerous direction -- it would justify attaching to
 * a production firewall interface.
 *
 * MEASURED on FreeBSD 16.0 with real frames on an epair (two ends in separate
 * VNET jails, so traffic genuinely traversed the link):
 *
 *     no hooks                  -> ping OK
 *     epair0a:lower -> tee      -> ping 100% LOSS   (kernel path stolen)
 *     + tee:left -> epair0a:upper -> ping OK        (reinjection restores it)
 *
 * ng_ether(4) says it plainly: "When connected, all incoming packets are
 * forwarded to this hook, instead of being passed to the kernel." Connecting
 * `lower` alone takes the interface OUT OF SERVICE. Any attachment that only
 * steals is an outage, not monitoring.
 *
 * So this function builds the topology that REINJECTS:
 *
 *     iface:lower --> tee:right        (steal incoming)
 *     tee:left    --> iface:upper      (reinject: kernel path restored)
 *     tee:right2left --> bpf:in        (the TAP: a copy, cannot drop)
 *     bpf:match   --> our socket       (only interesting frames reach us)
 *
 * The tee is what makes it safe. Per ng_tee(4), every frame is forwarded to
 * BOTH the pass-through hook and the tap, unconditionally -- so the tap cannot
 * break the path, and this process dying cannot down the interface. That
 * property is the whole reason for the tee rather than wiring bpf inline:
 * a userspace reader must never be in the pass-through path.
 *
 * Attaching to an interface carrying your own management session is a lockout.
 * There is no check for that here -- the caller must know which interface it is
 * on. (The same class of mistake as loading ipfw on a remote host.)
 *
 * Note what this does NOT do: it does not DROP anything. ng_bpf here only
 * decides what this process is interested in; the tee has already forwarded the
 * frame. Blocking is a separate topology with its own failure mode, and this
 * function refuses to make it silently.
 */
enum ng_sni_result ng_sni_attach(struct ng_sni **out, const char *ifname,
                                 const char *nodename);

/*
 * Read one frame and decide.
 *
 * Blocks until a frame arrives or `timeout_ms` elapses. Returns:
 *   1  a frame was processed; `*verdict` is set
 *   0  timeout, nothing to do
 *  -1  the graph is broken and the caller should tear down and re-attach
 *
 * `flow` must be the reassembly state for this flow; callers key it by the
 * 5-tuple. The 5-tuple is copied out into `key`, so a caller can maintain its
 * own table without re-parsing the frame.
 */
struct ng_sni_verdict {
	enum reasm_result reasm;
	bool conclusive;      /* may the caller act on this, or wait? */
	char host[SNI_MAX_NAME];
	uint8_t proto;
	uint8_t saddr[16];
	uint8_t daddr[16];
	uint16_t sport;
	uint16_t dport;
	/*
	 * Whether the tuple above is valid, and why this flag has to exist:
	 *
	 * these fields are zero-initialised by the caller, and a zero tuple is
	 * indistinguishable from a real one whose addresses happen to be zero.
	 * Without this flag a caller keying a flow table would silently group
	 * every unparseable frame under one all-zero key -- which is the bug
	 * that made these fields dead code in the first place, just in a new
	 * costume.
	 */
	bool have_tuple;
	bool truncated;       /* our window was too small for this traffic */
};

int ng_sni_next(struct ng_sni *g, struct reasm_flow *flow, int timeout_ms,
                struct ng_sni_verdict *verdict);

/* Detach everything and free. Safe to call with a partially-built graph. */
void ng_sni_close(struct ng_sni *g);

/*
 * Is the interface still passing traffic?
 *
 * A caller that attached to a LIVE interface must check this, because the
 * failure it guards against is the one that cannot be recovered remotely: if
 * reinjection did not take, the interface is out of the kernel's path and the
 * operator has lost the network.
 *
 * True when BOTH of our hooks are present on the interface (`lower` to steal,
 * `upper` to reinject). `lower` without `upper` means DEAD, and this prints to
 * stderr in that case rather than just returning false -- the caller may be a
 * daemon whose return value nobody reads.
 */
bool ng_sni_reinjection_ok(const struct ng_sni *g);

/*
 * Is the graph live and correctly wired?
 *
 * This exists because of the vacuous-pass trap: a broken graph and a working
 * graph that drops everything look identical from the outside. It checks the
 * nodes are present and the bpf node carries a program, so a caller can assert
 * the pipeline is real before trusting any negative result from it.
 */
bool ng_sni_is_wired(const struct ng_sni *g);

#endif /* AETHER_SENSORD_NG_SNI_H */
