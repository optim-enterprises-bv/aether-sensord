/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 */

#include "observe.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

const char *obs_kind_str(enum obs_kind k)
{
	switch (k) {
	case OBS_PORT_SCAN:
		return "port_scan";
	case OBS_BLOCKED_CONNECT:
	default:
		return "blocked_connect";
	}
}

bool obs_addr_from_v4(struct obs_addr *a, const uint8_t ip[4])
{
	if (!a || !ip)
		return false;
	memset(a, 0, sizeof(*a));
	memcpy(a->bytes, ip, 4);
	a->len = 4;
	return true;
}

bool obs_addr_from_v6(struct obs_addr *a, const uint8_t ip[16])
{
	if (!a || !ip)
		return false;
	memset(a, 0, sizeof(*a));
	memcpy(a->bytes, ip, 16);
	a->len = 16;
	return true;
}

bool obs_addr_parse(struct obs_addr *a, const char *text)
{
	if (!a || !text)
		return false;
	uint8_t buf[16];
	if (inet_pton(AF_INET, text, buf) == 1)
		return obs_addr_from_v4(a, buf);
	if (inet_pton(AF_INET6, text, buf) == 1)
		return obs_addr_from_v6(a, buf);
	return false;
}

bool obs_addr_str(const struct obs_addr *a, char *out, size_t out_len)
{
	if (!a || !out)
		return false;
	int af = (a->len == 4) ? AF_INET : AF_INET6;
	return inet_ntop(af, a->bytes, out, (socklen_t)out_len) != NULL;
}

bool obs_addr_eq(const struct obs_addr *a, const struct obs_addr *b)
{
	if (!a || !b || a->len != b->len)
		return false;
	return memcmp(a->bytes, b->bytes, a->len) == 0;
}

bool obs_addr_is_private(const struct obs_addr *a)
{
	if (!a)
		return true; /* refuse what we cannot classify */

	if (a->len == 4) {
		const uint8_t *b = a->bytes;
		if (b[0] == 0)                                  return true; /* 0.0.0.0/8 */
		if (b[0] == 10)                                 return true; /* RFC 1918 */
		if (b[0] == 127)                                return true; /* loopback */
		if (b[0] == 169 && b[1] == 254)                 return true; /* link-local */
		if (b[0] == 172 && (b[1] & 0xf0) == 16)         return true; /* RFC 1918 */
		if (b[0] == 192 && b[1] == 168)                 return true; /* RFC 1918 */
		if (b[0] == 100 && (b[1] & 0xc0) == 64)         return true; /* CGNAT */
		if (b[0] == 192 && b[1] == 0 && b[2] == 0)      return true; /* IETF */
		if (b[0] == 192 && b[1] == 0 && b[2] == 2)      return true; /* TEST-NET-1 */
		if (b[0] == 198 && (b[1] & 0xfe) == 18)         return true; /* benchmarking */
		if (b[0] == 198 && b[1] == 51 && b[2] == 100)   return true; /* TEST-NET-2 */
		if (b[0] == 203 && b[1] == 0 && b[2] == 113)    return true; /* TEST-NET-3 */
		if ((b[0] & 0xf0) == 224)                       return true; /* multicast */
		if ((b[0] & 0xf0) == 240)                       return true; /* reserved */
		return false;
	}

	if (a->len == 16) {
		const uint8_t *b = a->bytes;
		static const uint8_t loopback[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
		static const uint8_t unspecified[16] = { 0 };

		/* :: -- the v6 counterpart of the 0.0.0.0/8 guard above. Without
		 * this, all-zeros fails the loopback memcmp on the last byte and
		 * falls through as PUBLIC. The two branches of this function must
		 * refuse the same classes of address or the asymmetry reads as
		 * deliberate later. */
		if (memcmp(b, unspecified, 16) == 0)
			return true;
		if (memcmp(b, loopback, 16) == 0)           return true; /* ::1 */
		if ((b[0] & 0xfe) == 0xfc)                  return true; /* fc00::/7 */
		if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)  return true; /* fe80::/10 */
		if (b[0] == 0xff)                           return true; /* multicast */

		/* 2001:db8::/32 documentation, for symmetry with the v4 TEST-NETs. */
		if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8)
			return true;

		/* ::ffff:0:0/96 IPv4-mapped. Believed unreachable from a wire
		 * header -- mapped addresses are a sockets-API construct and
		 * obs_decode builds from RFC byte offsets -- but an RFC1918
		 * address wearing a v6 coat must not read as public if it ever
		 * does arrive. Defensive, not a known live path. */
		static const uint8_t v4mapped[12] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff };
		if (memcmp(b, v4mapped, 12) == 0) {
			struct obs_addr inner;
			if (obs_addr_from_v4(&inner, b + 12))
				return obs_addr_is_private(&inner);
			return true;
		}
		return false;
	}

	return true;
}

bool obs_table_init(struct obs_table *t, size_t capacity, uint32_t scan_port_threshold)
{
	if (!t || capacity == 0)
		return false;
	/* An unreachable threshold would disable scan detection while looking
	 * configured. Refuse it here so the coupling between this bound and the
	 * UCI value is enforced rather than assumed. */
	if (scan_port_threshold > OBS_MAX_PORTS)
		return false;
	memset(t, 0, sizeof(*t));
	t->entries = calloc(capacity, sizeof(struct obs_entry));
	if (!t->entries)
		return false;
	t->capacity = capacity;
	t->scan_port_threshold = scan_port_threshold ? scan_port_threshold : 8;
	return true;
}

void obs_table_free(struct obs_table *t)
{
	if (!t)
		return;
	free(t->entries);
	t->entries = NULL;
	t->capacity = 0;
	t->used = 0;
}

void obs_table_reset(struct obs_table *t)
{
	if (!t || !t->entries)
		return;
	memset(t->entries, 0, t->capacity * sizeof(struct obs_entry));
	t->used = 0;
	t->dropped_full = 0;
	t->dropped_private = 0;
}

/* Linear probe over a simple FNV-1a hash of the address bytes. The table is
 * small (thousands) and the load factor is bounded by `used < capacity`, so a
 * chained structure would cost allocations for no measurable gain. */
static size_t hash_addr(const struct obs_addr *a, size_t capacity)
{
	uint64_t h = 1469598103934665603ULL;
	for (uint8_t i = 0; i < a->len; i++) {
		h ^= a->bytes[i];
		h *= 1099511628211ULL;
	}
	h ^= a->len;
	h *= 1099511628211ULL;
	return (size_t)(h % capacity);
}

static struct obs_entry *find_or_insert(struct obs_table *t, const struct obs_addr *src)
{
	size_t idx = hash_addr(src, t->capacity);
	for (size_t probe = 0; probe < t->capacity; probe++) {
		struct obs_entry *e = &t->entries[(idx + probe) % t->capacity];
		if (!e->used) {
			if (t->used >= t->capacity)
				return NULL;
			e->used = true;
			e->src = *src;
			t->used++;
			return e;
		}
		if (obs_addr_eq(&e->src, src))
			return e;
	}
	return NULL;
}

static void note_port(struct obs_entry *e, uint16_t port)
{
	for (uint8_t i = 0; i < e->n_ports; i++) {
		if (e->ports[i] == port)
			return; /* already recorded */
	}
	if (e->n_ports < OBS_MAX_PORTS) {
		e->ports[e->n_ports++] = port;
		e->ports_seen++;
		return;
	}
	/* Store is full. We can no longer distinguish a new port from a repeat
	 * of one we could not keep, so stop counting and say so. Reporting a
	 * number we cannot stand behind is worse than reporting a floor. */
	e->ports_truncated = true;
}

bool obs_record(struct obs_table *t, const struct obs_addr *src, uint16_t dst_port,
                int64_t now)
{
	if (!t || !t->entries || !src)
		return false;

	if (obs_addr_is_private(src)) {
		t->dropped_private++;
		return false;
	}

	struct obs_entry *e = find_or_insert(t, src);
	if (!e) {
		t->dropped_full++;
		return false;
	}

	if (e->hits == 0)
		e->first_seen = now;
	e->last_seen = now;
	if (e->hits < UINT32_MAX)
		e->hits++;
	note_port(e, dst_port);
	return true;
}

enum obs_kind obs_classify(const struct obs_table *t, const struct obs_entry *e)
{
	if (!t || !e)
		return OBS_BLOCKED_CONNECT;
	if (e->ports_seen >= t->scan_port_threshold)
		return OBS_PORT_SCAN;
	return OBS_BLOCKED_CONNECT;
}

long obs_write_ndjson(const struct obs_table *t, FILE *out)
{
	if (!t || !t->entries || !out)
		return -1;

	long written = 0;
	char addr[46];

	for (size_t i = 0; i < t->capacity; i++) {
		const struct obs_entry *e = &t->entries[i];
		if (!e->used || e->hits == 0)
			continue;
		if (!obs_addr_str(&e->src, addr, sizeof(addr)))
			continue;

		int rc = fprintf(out,
		                 "{\"src\":\"%s\",\"kind\":\"%s\",\"hits\":%u,"
		                 "\"ports_seen\":%u,\"ports_truncated\":%s,"
		                 "\"first_seen\":%lld,\"last_seen\":%lld}\n",
		                 addr, obs_kind_str(obs_classify(t, e)), e->hits,
		                 e->ports_seen, e->ports_truncated ? "true" : "false",
		                 (long long)e->first_seen,
		                 (long long)e->last_seen);
		if (rc < 0)
			return -1;
		written++;
	}
	return written;
}

/* Fixed header sizes, by RFC rather than by sizeof(). */
#define IPV4_MIN_HDR 20
#define IPV6_HDR 40
#define L4_PORTS_MIN 4

/*
 * Decode enough of the packet to get (source address, destination port).
 *
 * NFLOG hands us the raw L3 payload. Anything we cannot parse is skipped
 * rather than guessed at -- a wrong source address would be attributed to an
 * innocent party by the backend.
 *
 * Header fields are read at their RFC byte offsets rather than through
 * `struct iphdr` / `struct tcphdr`. Those structs and their member names
 * (`th_dport` vs `dest`, `iphdr` vs `ip`) differ between glibc and musl and
 * are gated on _GNU_SOURCE / __FAVOR_BSD, so using them builds cleanly on the
 * host and then fails or, worse, silently reads the wrong offset when
 * cross-compiled for a musl target. Byte offsets are the same everywhere.
 */
int obs_decode(const unsigned char *pkt, int len, struct obs_addr *src,
                  uint16_t *dst_port)
{
	if (len < 1)
		return -1;

	unsigned version = pkt[0] >> 4;
	const unsigned char *l4 = NULL;
	uint8_t proto = 0;

	if (version == 4) {
		if (len < IPV4_MIN_HDR)
			return -1;
		/* IHL is the low nibble of byte 0, in 32-bit words. */
		unsigned ihl = (pkt[0] & 0x0f) * 4u;
		if (ihl < IPV4_MIN_HDR || (int)ihl > len)
			return -1;
		/* Source address: bytes 12..15. */
		if (!obs_addr_from_v4(src, pkt + 12))
			return -1;
		/* Protocol: byte 9. */
		proto = pkt[9];
		/* Fragments after the first carry no L4 header. Fragment offset
		 * is the low 13 bits of bytes 6..7. */
		unsigned frag_off = ((unsigned)(pkt[6] & 0x1f) << 8) | pkt[7];
		if (frag_off != 0)
			proto = 0;
		l4 = pkt + ihl;
		len -= (int)ihl;
	} else if (version == 6) {
		if (len < IPV6_HDR)
			return -1;
		/* Source address: bytes 8..23. */
		if (!obs_addr_from_v6(src, pkt + 8))
			return -1;
		/* Next header: byte 6. Extension headers are not walked, so an
		 * extension-laden packet yields no port -- that downgrades the
		 * record rather than corrupting it. */
		proto = pkt[6];
		l4 = pkt + IPV6_HDR;
		len -= IPV6_HDR;
	} else {
		return -1;
	}

	/* Destination port is bytes 2..3 of the L4 header for both TCP and
	 * UDP. Zero means "unknown", which the backend treats as diagnostic
	 * only -- it never affects scoring. */
	*dst_port = 0;
	if ((proto == IPPROTO_TCP || proto == IPPROTO_UDP) && len >= L4_PORTS_MIN)
		*dst_port = (uint16_t)((l4[2] << 8) | l4[3]);

	return 0;
}
