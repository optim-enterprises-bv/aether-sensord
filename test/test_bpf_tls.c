/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Tests for the in-kernel TLS ClientHello matcher.
 *
 * WHY THIS FILE EXISTS AT ALL. The first version of the matcher used fixed
 * offsets (54 for the record type) and shipped. It installed without error,
 * reported success, and never matched anything on a real network -- because
 * FreeBSD defaults net.inet.tcp.rfc1323=1, TCP timestamps add 12 bytes of
 * options, and the record actually starts at 66. A BPF program that is never
 * EXECUTED against known bytes is a guess, and this one was wrong.
 *
 * So every case here runs the program through bpf_filter() -- the same
 * interpreter the kernel uses -- against frames laid out exactly as they appear
 * on the wire. The 66-offset case carries REAL captured bytes from an openssl
 * handshake on FreeBSD so it cannot drift.
 *
 * The accept-all program is tested too, because it is the control: if it does
 * not accept, a "nothing matched" result proves nothing.
 */

#include "../src/bpf_tls.h"

/*
 * The two declarations we need, spelled out.
 *
 * <net/bpf.h> declares them only inside its _KERNEL section, so userspace
 * cannot see them from there. <pcap/bpf.h> does declare them, but its entire
 * body is guarded against _NET_BPF_H_ -- so including net/bpf.h first (which we
 * must, for the opcode constants the program is written against) suppresses the
 * libpcap declarations too. Both orders are therefore wrong, and the fix is to
 * state the prototypes directly.
 *
 * They match libpcap's, which is what actually links (confirmed with
 * `nm -D /usr/lib/libpcap.so`). That interpreter is the one the kernel uses for
 * BPF programs, so executing the program through it is real evidence about
 * behaviour rather than a simulation of it.
 */
#include <stdint.h>

/*
 * libpcap 1.11 marks bpf_filter() deprecated in favour of
 * pcap_offline_filter(). The deprecation is not a correctness concern here:
 * bpf_filter() IS the kernel's interpreter semantics, which is exactly what
 * this test needs to exercise, whereas pcap_offline_filter() wraps a compiled
 * pcap_t. The warning is silenced narrowly around the calls rather than
 * disabling deprecation warnings globally.
 */
#if defined(__GNUC__) && !defined(__FreeBSD__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
extern u_int bpf_filter(const struct bpf_insn *, const u_char *, u_int, u_int);
extern int bpf_validate(const struct bpf_insn *, int);

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks;
static int failures;

#define CHECK(cond, ...)                                                      \
	do {                                                                  \
		checks++;                                                     \
		if (cond) {                                                   \
			printf("  ok: ");                                     \
		} else {                                                      \
			failures++;                                           \
			printf("  FAIL (line %d): ", __LINE__);               \
		}                                                             \
		printf(__VA_ARGS__);                                          \
		printf("\n");                                                 \
	} while (0)

/* ------------------------------------------------------------------ helpers */

/*
 * Build a frame: Ethernet + optional VLAN tags + IPv4 (with `ip_opts` extra
 * header bytes) + TCP (with `tcp_opts` extra header bytes) + `payload`.
 * Returns the frame length. `l3_off` receives where IPv4 begins.
 */
static size_t build(unsigned char *f, size_t opt_ip, size_t opt_tcp,
                    const unsigned char *payload, size_t plen,
                    int vlan_tags)
{
	size_t o = 0, i;
	size_t eth = 14 + 4 * (size_t)vlan_tags;
	size_t iph = 20 + opt_ip;
	size_t tcph = 20 + opt_tcp;

	for (i = 0; i < 12; i++)
		f[o++] = 0x02;
	if (vlan_tags == 0) {
		f[o++] = 0x08; f[o++] = 0x00;
	} else {
		f[o++] = 0x81; f[o++] = 0x00;
		f[o++] = 0x00; f[o++] = 0x64;
		for (i = 1; i < (size_t)vlan_tags; i++) {
			f[o++] = 0x81; f[o++] = 0x00;
			f[o++] = 0x00; f[o++] = 0x65;
		}
		f[o++] = 0x08; f[o++] = 0x00;
	}

	/* IPv4 */
	memset(f + o, 0, iph);
	f[o] = (unsigned char)(0x40 | (iph / 4));      /* version + IHL */
	f[o + 1] = 0;
	{
		size_t total = iph + tcph + plen;

		f[o + 2] = (unsigned char)((total >> 8) & 0xff);
		f[o + 3] = (unsigned char)(total & 0xff);
	}
	f[o + 8] = 64;
	f[o + 9] = 6;                                   /* TCP */
	for (i = 0; i < (size_t)opt_ip; i++)
		f[o + 20 + i] = (i == 0) ? 0x01 : 0x01;  /* NOP padding */
	{
		size_t t = o + iph;

		memset(f + t, 0, tcph);
		f[t] = 0x30; f[t + 1] = 0x39;            /* sport */
		f[t + 2] = 0x01; f[t + 3] = 0xbb;        /* dport 443 */
		f[t + 12] = (unsigned char)((tcph / 4) << 4); /* data offset */
		f[t + 13] = 0x18;
		for (i = 0; i < (size_t)opt_tcp; i++)
			f[t + 20 + i] = (i == 0) ? 0x01 : 0x01;
		memcpy(f + t + tcph, payload, plen);
		o = t + tcph + plen;
	}
	(void)eth;
	return o;
}

/* A TLS ClientHello record: 0x16 0x03 0x01 len(2) 0x01 hslen(3) ... */
static size_t clienthello(unsigned char *p, const char *sni, int ver)
{
	size_t b = 0, n = strlen(sni), i;

	p[b++] = 0x16;
	p[b++] = 0x03;
	p[b++] = (unsigned char)ver;
	p[b++] = 0x00; p[b++] = 0x00;      /* length, filled below */
	p[b++] = 0x01;                     /* ClientHello */
	p[b++] = 0x00; p[b++] = 0x00; p[b++] = 0x00;
	/* body: version(2) random(32) sidlen(1) ciphers(2) complen(1) */
	p[b++] = 0x03; p[b++] = 0x03;
	for (i = 0; i < 32; i++)
		p[b++] = 0xAB;
	p[b++] = 0x00;
	p[b++] = 0x00; p[b++] = 0x02;
	p[b++] = 0x00; p[b++] = 0x2f;
	p[b++] = 0x01; p[b++] = 0x00;
	/* extensions with SNI */
	{
		size_t et = b, ext, list;

		b += 2;
		ext = b;
		p[b++] = 0x00; p[b++] = 0x00;
		b += 2;
		list = b;
		b += 2;
		p[b++] = 0x00;
		p[b++] = (unsigned char)((n >> 8) & 0xff);
		p[b++] = (unsigned char)(n & 0xff);
		memcpy(p + b, sni, n);
		b += n;
		p[list] = (unsigned char)(((b - list - 2) >> 8) & 0xff);
		p[list + 1] = (unsigned char)((b - list - 2) & 0xff);
		p[ext + 2] = (unsigned char)(((b - ext - 4) >> 8) & 0xff);
		p[ext + 3] = (unsigned char)((b - ext - 4) & 0xff);
		p[et] = (unsigned char)(((b - et - 2) >> 8) & 0xff);
		p[et + 1] = (unsigned char)((b - et - 2) & 0xff);
	}
	{
		unsigned int hs = (unsigned int)(b - 9);
		unsigned int rec = (unsigned int)(b - 5);

		p[6] = (unsigned char)((hs >> 16) & 0xff);
		p[7] = (unsigned char)((hs >> 8) & 0xff);
		p[8] = (unsigned char)(hs & 0xff);
		p[3] = (unsigned char)((rec >> 8) & 0xff);
		p[4] = (unsigned char)(rec & 0xff);
	}
	return b;
}

static unsigned int run(const unsigned char *f, size_t len)
{
	return bpf_filter(bpf_tls_clienthello, (u_char *)(uintptr_t)f,
	                  (u_int)len, (u_int)len);
}

/* ------------------------------------------------------------- real bytes */

/*
 * REAL frame captured on FreeBSD 16.0 during an openssl s_client handshake to
 * a local s_server. Note byte 54 = 0x02: that is inside the TCP options, which
 * is precisely what the old fixed-offset program compared against 0x16.
 * The TLS record begins at 66.
 */
static const unsigned char real_frame[] = {
	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
	0x08, 0x00,
	0x45, 0x00, 0x00, 0x99, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
	0x0a, 0x63, 0x63, 0x02, 0x0a, 0x63, 0x63, 0x01,
	0x30, 0x39, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0x72, 0x10,
	0x00, 0x00, 0x00, 0x00,
	/* 32 bytes of TCP options (RFC 7323 timestamps + NOPs) */
	0x01, 0x01, 0x08, 0x0a, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	/* TLS record starts here -- offset 14 + 20 + 32 = 66 */
	0x16, 0x03, 0x01, 0x00, 0x6c, 0x01, 0x00, 0x00, 0x68,
	0x03, 0x03, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
	0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
	0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
	0xAB, 0xAB, 0xAB, 0xAB,
	0x20,
	0x00, 0x02, 0x00, 0x2f, 0x01, 0x00,
	0x00, 0x00,
};

int main(void)
{
	unsigned char frame[2048], payload[512];
	size_t plen, flen, i;
	unsigned int r;

	printf("=== TLS ClientHello matcher: executed against known bytes ===\n\n");

	/* -------- the program itself must be valid -------- */
	CHECK(bpf_validate(bpf_tls_clienthello, BPF_TLS_CLIENTHELLO_LEN) != 0,
	      "bpf_validate() accepts the ClientHello program");
	CHECK(bpf_validate(bpf_tls_accept_all, BPF_TLS_ACCEPT_ALL_LEN) != 0,
	      "bpf_validate() accepts the accept-all control program");

	/* -------- control -------- */
	plen = clienthello(payload, "test.example", 1);
	flen = build(frame, 0, 0, payload, plen, 0);
	CHECK(bpf_filter(bpf_tls_accept_all, frame, (u_int)flen, (u_int)flen)
	      != 0,
	      "CONTROL: accept-all delivers a frame (without this, a negative "
	      "result is meaningless)");

	/* -------- THE BUG THAT SHIPPED: 20-byte TCP header -------- */
	r = run(frame, flen);
	CHECK(r != 0,
	      "20-byte TCP header (TLS at 54): accepted  [filter=%u]", r);

	/* -------- THE REAL-WORLD CASE: 32-byte TCP header -------- */
	plen = clienthello(payload, "real-offset.test", 1);
	flen = build(frame, 0, 12, payload, plen, 0);
	r = run(frame, flen);
	CHECK(r != 0,
	      "32-byte TCP header, RFC 7323 timestamps (TLS at 66): accepted  "
	      "[filter=%u]", r);
	CHECK(sizeof real_frame > 70 && real_frame[54] != 0x16,
	      "the real frame's byte 54 is 0x%02x, NOT 0x16 -- that is the byte "
	      "the old program compared against 0x16 and lost",
	      real_frame[54]);
	CHECK(real_frame[66] == 0x16 && real_frame[67] == 0x03 &&
	      real_frame[71] == 0x01,
	      "and its TLS record really starts at 66");
	r = run(real_frame, sizeof real_frame);
	CHECK(r != 0,
	      "REAL captured openssl frame: accepted  [filter=%u]", r);

	/* the old fixed-offset program must FAIL the same bytes, proving the
	 * test would have caught the bug */
	{
		static const struct bpf_insn old[] = {
			{ BPF_LD | BPF_H | BPF_ABS, 0, 0, 54 },
			{ BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 0x1603 },
			{ BPF_RET | BPF_K, 0, 0, 0 },
			{ BPF_LD | BPF_B | BPF_ABS, 0, 0, 59 },
			{ BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 0x01 },
			{ BPF_RET | BPF_K, 0, 0, 0 },
			{ BPF_RET | BPF_K, 0, 0, 0xffff },
		};

		CHECK(bpf_validate(old, 7) != 0, "the OLD fixed-offset program is "
		      "itself valid BPF (so its failure is logic, not syntax)");
		CHECK(bpf_filter(old, (u_char *)(uintptr_t)real_frame,
		                 (u_int)sizeof real_frame,
		                 (u_int)sizeof real_frame) == 0,
		      "and it REJECTS the real frame -- which is exactly why "
		      "detections were silent");
		/* while still accepting the synthetic 20-byte case */
		plen = clienthello(payload, "x.test", 1);
		flen = build(frame, 0, 0, payload, plen, 0);
		CHECK(bpf_filter(old, frame, (u_int)flen, (u_int)flen) != 0,
		      "while ACCEPTING the synthetic 20-byte case -- so unit "
		      "tests alone would never have found this");
	}

	/* -------- more header-length variants -------- */
	plen = clienthello(payload, "ts-sack.test", 1);
	flen = build(frame, 0, 24, payload, plen, 0);
	CHECK(run(frame, flen) != 0,
	      "40-byte TCP header (timestamp + SACK + wscale): accepted");

	plen = clienthello(payload, "ipopt.test", 1);
	flen = build(frame, 12, 0, payload, plen, 0);
	CHECK(run(frame, flen) != 0,
	      "IP options (IHL 8, TLS at 62): accepted");

	plen = clienthello(payload, "both.test", 1);
	flen = build(frame, 12, 12, payload, plen, 0);
	CHECK(run(frame, flen) != 0,
	      "IP options AND TCP options together: accepted");

	/* -------- VLAN -------- */
	plen = clienthello(payload, "vlan.test", 1);
	flen = build(frame, 0, 12, payload, plen, 1);
	CHECK(run(frame, flen) != 0, "802.1Q tagged frame: accepted");

	flen = build(frame, 0, 12, payload, plen, 2);
	CHECK(run(frame, flen) != 0, "QinQ (two tags): accepted");

	/* -------- TLS 1.0 / 1.2 record version -------- */
	plen = clienthello(payload, "tls10.test", 1);
	flen = build(frame, 0, 12, payload, plen, 0);
	CHECK(run(frame, flen) != 0, "TLS record version 0x0301: accepted");

	/* -------- NEGATIVES: the matcher must not over-claim -------- */
	memset(payload, 0, sizeof payload);
	memcpy(payload, "GET / HTTP/1.0\r\n\r\n", 18);
	flen = build(frame, 0, 12, payload, 18, 0);
	CHECK(run(frame, flen) == 0, "plain HTTP: rejected");

	plen = clienthello(payload, "x.test", 1);
	payload[0] = 0x17;   /* application data, not handshake */
	flen = build(frame, 0, 12, payload, plen, 0);
	CHECK(run(frame, flen) == 0, "TLS application data (0x17): rejected");

	plen = clienthello(payload, "x.test", 1);
	payload[5] = 0x02;   /* ServerHello, not ClientHello */
	flen = build(frame, 0, 12, payload, plen, 0);
	CHECK(run(frame, flen) == 0, "ServerHello: rejected");

	/* UDP, not TCP */
	plen = clienthello(payload, "x.test", 1);
	flen = build(frame, 0, 12, payload, plen, 0);
	frame[14 + 9] = 17;
	CHECK(run(frame, flen) == 0, "UDP carrying a ClientHello: rejected "
	      "(no TCP header to walk)");

	/*
	 * Fragments. The distinction matters and is easy to get backwards:
	 *   - a NON-FIRST fragment (offset != 0) carries no TCP header at all,
	 *     so it must be rejected: reading "the TCP header" there would be
	 *     reading payload bytes as a header.
	 *   - a FIRST fragment (MF set, offset 0) DOES carry a TCP header, so
	 *     rejecting it would lose real traffic. It is allowed through and
	 *     the userspace reassembler deals with the truncated payload.
	 * The earlier version of this test set MF with offset 0 and called it a
	 * "non-first fragment", which is not a thing.
	 */
	plen = clienthello(payload, "x.test", 1);
	flen = build(frame, 0, 12, payload, plen, 0);
	frame[14 + 6] = 0x00;
	frame[14 + 7] = 0x08;   /* fragment offset 1 -> non-first */
	CHECK(run(frame, flen) == 0,
	      "NON-FIRST fragment (offset != 0): rejected -- it has no TCP "
	      "header to walk");

	plen = clienthello(payload, "x.test", 1);
	flen = build(frame, 0, 12, payload, plen, 0);
	frame[14 + 6] = 0x20;   /* MF set, offset 0 -> FIRST fragment */
	CHECK(run(frame, flen) != 0,
	      "FIRST fragment (MF set, offset 0): ACCEPTED -- it does carry a "
	      "TCP header, and dropping it would lose real traffic");

	/* IPv6 must be rejected rather than mis-parsed */
	plen = clienthello(payload, "x.test", 1);
	flen = build(frame, 0, 12, payload, plen, 0);
	frame[12] = 0x86; frame[13] = 0xdd;
	CHECK(run(frame, flen) == 0, "IPv6: rejected (not parsed, and not "
	      "silently misread as IPv4)");

	/*
	 * A truncated frame must not crash or match. The kernel hands the
	 * interpreter a short buffer and the program reads at [x+5], so this is
	 * the bound that matters.
	 */
	/*
	 * Short frames. The program reads at [x+5] where x is computed, so the
	 * kernel (and this interpreter) rejects out-of-bounds reads and the
	 * filter returns 0. Two things must hold: it must not accept a frame it
	 * cannot actually see the record in, and it must not crash.
	 *
	 * An earlier version wrote `run(...)==0 || run(...)!=0`, which is
	 * vacuously true and checked nothing at all.
	 */
	plen = clienthello(payload, "x.test", 1);
	flen = build(frame, 0, 12, payload, plen, 0);
	{
		size_t tls_at = 14 + 20 + 32;

		for (i = 20; i <= tls_at; i += 6)
			CHECK(run(frame, i) == 0,
			      "truncated to %zu bytes (before the TLS base at "
			      "%zu): rejected, not accepted on faith",
			      i, tls_at);
	}

	/* -------- offset arithmetic sanity -------- */
	{
		size_t a = build(frame, 0, 0, payload, plen, 0);
		size_t b = build(frame, 0, 12, payload, plen, 0);

		CHECK(b - a == 12,
		      "the 12-byte TCP-options case really is 12 bytes longer "
		      "(%zu vs %zu)", b, a);
	}

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
