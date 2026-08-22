/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 */

#include "dpi.h"

#include <stdlib.h>
#include <string.h>

#include <ndpi/ndpi_api.h>
#include <ndpi/ndpi_typedefs.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

struct dpi_flow {
	bool used;
	/* Key. Stored normalised (low endpoint first) so both directions of a
	 * conversation land on the same entry -- nDPI needs to see both to
	 * dissect a handshake. */
	struct obs_addr a, b;
	uint16_t pa, pb;
	uint8_t l4proto;

	struct ndpi_flow_struct *nf;
	uint32_t pkts;
	uint64_t last_ms;
	bool done;      /* verdict reached (or given up on): stop dissecting */
	bool reported;  /* result already handed to the caller once */
};

struct dpi_ctx {
	struct ndpi_detection_module_struct *ndpi;
	struct dpi_flow *flows;
	size_t cap;
	size_t used;
	struct dpi_stats st;
};

/* ---- key handling ------------------------------------------------------- */

static int addr_cmp(const struct obs_addr *x, const struct obs_addr *y)
{
	if (x->len != y->len)
		return x->len < y->len ? -1 : 1;
	return memcmp(x->bytes, y->bytes, x->len);
}

/*
 * Order the two endpoints so a flow keys identically in both directions.
 *
 * Without this, a TLS ClientHello and its ServerHello land in different table
 * entries, nDPI sees half a handshake in each, and dissection quietly never
 * completes -- which looks exactly like "this traffic is unclassifiable".
 */
static void key_normalise(struct obs_addr *a, uint16_t *pa, struct obs_addr *b,
                          uint16_t *pb)
{
	int c = addr_cmp(a, b);

	if (c > 0 || (c == 0 && *pa > *pb)) {
		struct obs_addr ta = *a;
		uint16_t tp = *pa;

		*a = *b;
		*pa = *pb;
		*b = ta;
		*pb = tp;
	}
}

static size_t key_hash(const struct obs_addr *a, uint16_t pa,
                       const struct obs_addr *b, uint16_t pb, uint8_t proto)
{
	/* FNV-1a, same constants as everywhere else in this package. */
	uint64_t h = 1469598103934665603ULL;
	size_t i;

#define MIX(byte)                                                              \
	do {                                                                   \
		h ^= (uint8_t)(byte);                                          \
		h *= 1099511628211ULL;                                         \
	} while (0)

	for (i = 0; i < a->len; i++)
		MIX(a->bytes[i]);
	for (i = 0; i < b->len; i++)
		MIX(b->bytes[i]);
	MIX(pa & 0xff);
	MIX(pa >> 8);
	MIX(pb & 0xff);
	MIX(pb >> 8);
	MIX(proto);
#undef MIX
	return (size_t)h;
}

/* ---- packet decode ------------------------------------------------------ */

/*
 * Pull the 5-tuple out of an L3 packet.
 *
 * Deliberately strict and deliberately separate from obs_decode(): that one
 * only needs a source address and a destination port for attacker reporting,
 * while this needs both endpoints and both ports, and must refuse anything it
 * cannot fully parse rather than dissecting against a half-read header.
 */
static bool decode5(const uint8_t *p, uint32_t len, struct obs_addr *src,
                    struct obs_addr *dst, uint16_t *sport, uint16_t *dport,
                    uint8_t *l4)
{
	uint32_t hl;

	if (!p || len < 20)
		return false;

	if ((p[0] >> 4) == 4) {
		hl = (uint32_t)(p[0] & 0x0f) * 4;
		if (hl < 20 || len < hl)
			return false;
		if (!obs_addr_from_v4(src, p + 12) || !obs_addr_from_v4(dst, p + 16))
			return false;
		*l4 = p[9];
		/* Fragments past the first carry no L4 header. */
		if ((((uint32_t)p[6] << 8 | p[7]) & 0x1fff) != 0)
			return false;
	} else if ((p[0] >> 4) == 6) {
		if (len < 40)
			return false;
		hl = 40;
		if (!obs_addr_from_v6(src, p + 8) || !obs_addr_from_v6(dst, p + 24))
			return false;
		*l4 = p[6];
		/* Extension headers are not walked. Refusing is correct: a
		 * guessed offset would feed nDPI garbage and produce a
		 * confident wrong classification. */
	} else {
		return false;
	}

	if (*l4 != IPPROTO_TCP && *l4 != IPPROTO_UDP) {
		*sport = *dport = 0;
		return true; /* still a flow, just portless */
	}
	if (len < hl + 4)
		return false;
	*sport = (uint16_t)((p[hl] << 8) | p[hl + 1]);
	*dport = (uint16_t)((p[hl + 2] << 8) | p[hl + 3]);
	return true;
}

/* ---- scope decision ----------------------------------------------------- */

bool dpi_kernel_can_match(uint8_t l4proto, uint16_t master_proto,
                          uint16_t app_proto)
{
	/*
	 * af_module.c refuses anything that is not IPPROTO_TCP, and af_match.c
	 * reads only a TLS ClientHello or an HTTP request line. Everything else
	 * -- all of QUIC, DNS, and the other 470-odd protocols nDPI knows --
	 * has to be enforced by address, because the kernel has no way to
	 * recover the name from the wire.
	 */
	if (l4proto != IPPROTO_TCP)
		return false;

	switch (master_proto) {
	case NDPI_PROTOCOL_TLS:
	case NDPI_PROTOCOL_HTTP:
		return true;
	default:
		break;
	}
	switch (app_proto) {
	case NDPI_PROTOCOL_TLS:
	case NDPI_PROTOCOL_HTTP:
		return true;
	default:
		return false;
	}
}

/* ---- lifecycle ---------------------------------------------------------- */

struct dpi_ctx *dpi_new(size_t max_flows)
{
	struct dpi_ctx *c;

	if (max_flows == 0 || max_flows > (1u << 20))
		return NULL;

	c = calloc(1, sizeof(*c));
	if (!c)
		return NULL;

	c->flows = calloc(max_flows, sizeof(*c->flows));
	if (!c->flows) {
		free(c);
		return NULL;
	}
	c->cap = max_flows;

	c->ndpi = ndpi_init_detection_module(NULL);
	if (!c->ndpi) {
		free(c->flows);
		free(c);
		return NULL;
	}

	/* nDPI 5.0 enables every protocol by default and dropped the
	 * NDPI_PROTOCOL_BITMASK API that 4.x needed here. init + finalize is
	 * the whole sequence; adding a bitmask call would not compile. */
	if (ndpi_finalize_initialization(c->ndpi) != 0) {
		ndpi_exit_detection_module(c->ndpi);
		free(c->flows);
		free(c);
		return NULL;
	}
	return c;
}

static void flow_release(struct dpi_flow *f)
{
	if (f->nf) {
		ndpi_flow_free(f->nf);
		f->nf = NULL;
	}
	f->used = false;
}

void dpi_free(struct dpi_ctx *c)
{
	size_t i;

	if (!c)
		return;
	for (i = 0; i < c->cap; i++)
		if (c->flows[i].used)
			flow_release(&c->flows[i]);
	free(c->flows);
	if (c->ndpi)
		ndpi_exit_detection_module(c->ndpi);
	free(c);
}

const char *dpi_proto_name(struct dpi_ctx *c, uint16_t proto_id)
{
	const char *n;

	if (!c || !c->ndpi)
		return "";
	n = ndpi_get_proto_name(c->ndpi, proto_id);
	return n ? n : "";
}

void dpi_get_stats(const struct dpi_ctx *c, struct dpi_stats *out)
{
	if (!c || !out)
		return;
	*out = c->st;
}

/* ---- table -------------------------------------------------------------- */

static struct dpi_flow *flow_lookup(struct dpi_ctx *c, const struct obs_addr *a,
                                    uint16_t pa, const struct obs_addr *b,
                                    uint16_t pb, uint8_t proto, bool *created,
                                    uint64_t now_ms)
{
	size_t start = key_hash(a, pa, b, pb, proto) % c->cap;
	size_t i, oldest = c->cap;
	uint64_t oldest_ms = UINT64_MAX;

	*created = false;

	/* Open addressing, linear probe, whole table. Bounded by cap. */
	for (i = 0; i < c->cap; i++) {
		struct dpi_flow *f = &c->flows[(start + i) % c->cap];

		if (!f->used) {
			memset(f, 0, sizeof(*f));
			f->used = true;
			f->a = *a;
			f->b = *b;
			f->pa = pa;
			f->pb = pb;
			f->l4proto = proto;
			f->last_ms = now_ms;
			c->used++;
			c->st.flows_new++;
			*created = true;
			return f;
		}
		if (f->l4proto == proto && f->pa == pa && f->pb == pb &&
		    addr_cmp(&f->a, a) == 0 && addr_cmp(&f->b, b) == 0) {
			f->last_ms = now_ms;
			return f;
		}
		if (f->last_ms < oldest_ms) {
			oldest_ms = f->last_ms;
			oldest = (start + i) % c->cap;
		}
	}

	/*
	 * Full. Evict the least recently seen rather than refusing: a table of
	 * stale flows that blocks all new dissection is a worse outcome than
	 * losing the oldest conversation. Counted either way.
	 */
	if (oldest < c->cap) {
		struct dpi_flow *f = &c->flows[oldest];

		flow_release(f);
		memset(f, 0, sizeof(*f));
		f->used = true;
		f->a = *a;
		f->b = *b;
		f->pa = pa;
		f->pb = pb;
		f->l4proto = proto;
		f->last_ms = now_ms;
		c->st.flows_evicted++;
		c->st.flows_new++;
		*created = true;
		return f;
	}

	c->st.flows_refused++;
	return NULL;
}

size_t dpi_expire(struct dpi_ctx *c, uint64_t now_ms, uint64_t idle_ms)
{
	size_t i, freed = 0;

	if (!c)
		return 0;
	for (i = 0; i < c->cap; i++) {
		struct dpi_flow *f = &c->flows[i];

		if (!f->used)
			continue;
		if (now_ms < f->last_ms || now_ms - f->last_ms < idle_ms)
			continue;
		flow_release(f);
		memset(f, 0, sizeof(*f));
		c->used--;
		freed++;
	}
	return freed;
}

/* ---- the hot path ------------------------------------------------------- */

static void take_host(struct dpi_ctx *c, struct dpi_flow *f,
                      struct dpi_result *out)
{
	const char *h = NULL;
	size_t n;

	(void)c;
	if (f->nf && f->nf->host_server_name[0])
		h = (const char *)f->nf->host_server_name;
	if (!h || !*h)
		return;

	n = strnlen(h, sizeof(f->nf->host_server_name));
	if (n >= DPI_HOST_MAX) {
		n = DPI_HOST_MAX - 1;
		out->host_truncated = true;
	}
	memcpy(out->host, h, n);
	out->host[n] = '\0';
	out->have_host = true;
}

bool dpi_process(struct dpi_ctx *c, const uint8_t *pkt, uint32_t len,
                 uint64_t now_ms, struct dpi_result *out)
{
	struct obs_addr src, dst, ka, kb;
	uint16_t sport = 0, dport = 0, kpa, kpb;
	uint8_t l4 = 0;
	struct dpi_flow *f;
	bool created;
	ndpi_protocol pr;

	if (!c || !pkt || !out)
		return false;
	memset(out, 0, sizeof(*out));
	c->st.packets_in++;

	if (!decode5(pkt, len, &src, &dst, &sport, &dport, &l4)) {
		c->st.undecodable++;
		return false;
	}

	ka = src;
	kb = dst;
	kpa = sport;
	kpb = dport;
	key_normalise(&ka, &kpa, &kb, &kpb);

	f = flow_lookup(c, &ka, kpa, &kb, kpb, l4, &created, now_ms);
	if (!f)
		return false;

	/* Already decided. Do not re-dissect and do not report twice. */
	if (f->done)
		return false;

	if (f->pkts >= DPI_MAX_PKTS_PER_FLOW) {
		/* Stop DISSECTING only. No verdict changes here -- see the
		 * note in dpi.h about why this is not OAF's by_pass_accl. */
		f->done = true;
		c->st.gave_up++;
		return false;
	}

	if (!f->nf) {
		f->nf = ndpi_flow_malloc(sizeof(struct ndpi_flow_struct));
		if (!f->nf)
			return false;
		memset(f->nf, 0, sizeof(struct ndpi_flow_struct));
	}

	f->pkts++;
	pr = ndpi_detection_process_packet(c->ndpi, f->nf, pkt,
	                                   (unsigned short)len, now_ms, NULL);

	if (pr.proto.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
	    pr.proto.master_protocol == NDPI_PROTOCOL_UNKNOWN)
		return false; /* undecided; keep feeding it */

	/*
	 * A protocol verdict is NOT the end of dissection.
	 *
	 * nDPI recognises TLS from the first handshake byte, well before it has
	 * parsed the SNI out of the ClientHello. Stopping here -- which this
	 * did -- yields proto=TLS with no hostname, and a protocol is not an
	 * application, so nothing can ever be enforced. Observed on the BPI-R4:
	 * every live flow classified, every one with host=-.
	 *
	 * extra_packets_func is nDPI's signal that it wants more packets for
	 * exactly this reason. Keep feeding it until it stops asking, we have a
	 * name, or the per-flow budget runs out.
	 */
	if (!f->nf->host_server_name[0] && f->nf->extra_packets_func &&
	    f->pkts < DPI_MAX_PKTS_PER_FLOW)
		return false; /* undecided on the NAME; keep dissecting */

	f->done = true;
	if (f->reported)
		return false;
	f->reported = true;

	out->classified = true;
	out->master_proto = pr.proto.master_protocol;
	out->app_proto = pr.proto.app_protocol;
	snprintf(out->proto_name, sizeof(out->proto_name), "%s",
	         dpi_proto_name(c, pr.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN
	                                   ? pr.proto.app_protocol
	                                   : pr.proto.master_protocol));
	out->src = src;
	out->dst = dst;
	out->sport = sport;
	out->dport = dport;
	out->l4proto = l4;

	take_host(c, f, out);

	out->scope = dpi_kernel_can_match(l4, out->master_proto, out->app_proto)
	                     ? DPI_SCOPE_NAME_HASH
	                     : DPI_SCOPE_ADDRESS;

	c->st.classified++;
	if (out->have_host)
		c->st.with_host++;
	if (out->host_truncated)
		c->st.host_truncated++;
	return true;
}
