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
 * A live capture graph: ng_ether -> ng_bpf -> this process.
 *
 * Opaque on purpose. Callers must not poke at the node names or the socket
 * descriptors: netgraph graphs are reference-counted and a caller that shuts one
 * node down out of order leaves the rest attached, which is how an interface
 * ends up with a zombie tee on it.
 */
struct ng_sni;

enum ng_sni_result {
	NG_SNI_OK = 0,
	NG_SNI_ERR_NO_DEV,     /* the interface does not exist */
	NG_SNI_ERR_NO_NETGRAPH, /* netgraph is not available in this kernel */
	NG_SNI_ERR_GRAPH,      /* building the graph failed */
	NG_SNI_ERR_PROGRAM,    /* the BPF program was rejected */
	NG_SNI_ERR_NAME        /* the node could not be named */
};

const char *ng_sni_result_str(enum ng_sni_result r);

/*
 * Attach a capture graph to `ifname`.
 *
 * `nodename` is the name this process's socket node takes; it must be unique,
 * because netgraph names are global and a stale node from a previous run will
 * cause the attach to fail with an error that looks unrelated. Cleanup on
 * failure is complete: nothing is left attached to the interface.
 *
 * PASSIVE: the interface keeps working normally. Frames are COPIED to us for
 * matching; they are not removed from the kernel's path. That is deliberate --
 * a firewall that stops forwarding because a userspace process died is worse
 * than one that stops filtering.
 *
 * Note what this does NOT do: it does not yet drop anything. Dropping requires
 * a second hook (ng_tee feeding a divert or an ipfw one_pass rule), which is a
 * separate decision with a separate failure mode, and this function refuses to
 * silently make it.
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
	bool truncated;       /* our window was too small for this traffic */
};

int ng_sni_next(struct ng_sni *g, struct reasm_flow *flow, int timeout_ms,
                struct ng_sni_verdict *verdict);

/* Detach everything and free. Safe to call with a partially-built graph. */
void ng_sni_close(struct ng_sni *g);

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
