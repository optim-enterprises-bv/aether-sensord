/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Replay a pcap through dpi.c and print what was classified.
 *
 * Deliberately does NOT link libpcap: this reads the classic pcap container
 * itself, in about eighty lines, because adding a GPL-adjacent dependency to
 * prove a point about dissection would be a poor trade. pcapng is not handled
 * and is reported as such rather than silently producing nothing.
 *
 *   dpi_replay <file.pcap> [--quiet]
 *
 * Exit codes: 0 classified at least one flow, 1 nothing classified,
 * 2 the file could not be read as a classic pcap.
 */

#include "../src/dpi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct pcap_hdr {
	uint32_t magic, ver, tz, sigfigs, snaplen, link;
};

struct rec_hdr {
	uint32_t ts_sec, ts_usec, incl, orig;
};

static uint32_t swap32(uint32_t v)
{
	return ((v & 0xffu) << 24) | ((v & 0xff00u) << 8) |
	       ((v >> 8) & 0xff00u) | ((v >> 24) & 0xffu);
}

int main(int argc, char **argv)
{
	FILE *f;
	struct pcap_hdr ph;
	int swap = 0, quiet = 0, nano = 0;
	size_t pkts = 0, classified = 0, with_host = 0, addr_scope = 0;
	struct dpi_ctx *c;
	uint8_t buf[65536];

	if (argc < 2) {
		fprintf(stderr, "usage: %s <file.pcap> [--quiet]\n", argv[0]);
		return 2;
	}
	if (argc > 2 && strcmp(argv[2], "--quiet") == 0)
		quiet = 1;

	f = fopen(argv[1], "rb");
	if (!f) {
		fprintf(stderr, "cannot open %s\n", argv[1]);
		return 2;
	}
	if (fread(&ph, sizeof(ph), 1, f) != 1) {
		fclose(f);
		return 2;
	}
	if (ph.magic == 0x0a0d0d0a) {
		fprintf(stderr, "%s is pcapng, not classic pcap -- skipping\n",
		        argv[1]);
		fclose(f);
		return 2;
	}
	if (ph.magic == 0xa1b2c3d4) {
		swap = 0;
	} else if (ph.magic == 0xd4c3b2a1) {
		swap = 1;
	} else if (ph.magic == 0xa1b23c4d) {
		nano = 1;
	} else if (ph.magic == 0x4d3cb2a1) {
		swap = 1;
		nano = 1;
	} else {
		fprintf(stderr, "%s: not a pcap (magic %08x)\n", argv[1], ph.magic);
		fclose(f);
		return 2;
	}
	(void)nano;

	uint32_t link = swap ? swap32(ph.link) : ph.link;

	c = dpi_new(4096);
	if (!c) {
		fclose(f);
		return 2;
	}

	for (;;) {
		struct rec_hdr rh;
		uint32_t incl, ts;
		size_t off = 0;
		struct dpi_result r;

		if (fread(&rh, sizeof(rh), 1, f) != 1)
			break;
		incl = swap ? swap32(rh.incl) : rh.incl;
		ts = swap ? swap32(rh.ts_sec) : rh.ts_sec;
		if (incl == 0 || incl > sizeof(buf))
			break;
		if (fread(buf, 1, incl, f) != incl)
			break;
		pkts++;

		/* Strip the link layer to reach the IP header. */
		switch (link) {
		case 1: /* Ethernet */
			if (incl < 14)
				continue;
			if (buf[12] == 0x81 && buf[13] == 0x00) {
				if (incl < 18)
					continue;
				off = 18; /* 802.1Q */
			} else {
				off = 14;
			}
			break;
		case 101: /* raw IP */
			off = 0;
			break;
		case 113: /* Linux cooked */
			if (incl < 16)
				continue;
			off = 16;
			break;
		case 276: /* Linux cooked v2 */
			if (incl < 20)
				continue;
			off = 20;
			break;
		default:
			continue;
		}
		if (off >= incl)
			continue;

		if (dpi_process(c, buf + off, incl - (uint32_t)off,
		                (uint64_t)ts * 1000, &r)) {
			classified++;
			if (r.have_host)
				with_host++;
			if (r.scope == DPI_SCOPE_ADDRESS)
				addr_scope++;
			if (!quiet) {
				char sb[64] = "?", db[64] = "?";

				obs_addr_str(&r.src, sb, sizeof(sb));
				obs_addr_str(&r.dst, db, sizeof(db));
				/* Bracket IPv6 so the address does not run into
				 * the port and read as a ninth group. */
				char sf[80], df[80];

				snprintf(sf, sizeof(sf),
				         r.src.len == 16 ? "[%s]:%u" : "%s:%u",
				         sb, r.sport);
				snprintf(df, sizeof(df),
				         r.dst.len == 16 ? "[%s]:%u" : "%s:%u",
				         db, r.dport);
				printf("  %-16s %s -> %s  proto=%s  host=%s  scope=%s\n",
				       r.proto_name, sf, df,
				       r.l4proto == 6 ? "tcp" : (r.l4proto == 17 ? "udp" : "other"),
				       r.have_host ? r.host : "-",
				       r.scope == DPI_SCOPE_ADDRESS ? "ADDRESS" : "name-hash");
			}
		}
	}
	fclose(f);

	struct dpi_stats st;
	dpi_get_stats(c, &st);
	printf("%s: %zu packets, %zu flows classified, %zu with a hostname, "
	       "%zu address-scope (undecodable %llu, evicted %llu)\n",
	       argv[1], pkts, classified, with_host, addr_scope,
	       (unsigned long long)st.undecodable,
	       (unsigned long long)st.flows_evicted);
	dpi_free(c);
	return classified > 0 ? 0 : 1;
}
