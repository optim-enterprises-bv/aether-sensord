/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * LIVE integration test: the netgraph transport, against the real kernel.
 *
 * WHAT THIS PROVES THAT A UNIT TEST CANNOT. sni.c and reassembly.c are pure and
 * tested on the host, but they are fed by a real netgraph graph whose failure
 * modes are entirely in the wiring: an unnamed node, a missing connect, an
 * uninstalled program. None of that is reachable with fixtures.
 *
 * THE CONTROL COMES FIRST, and that ordering is the point. An ng_bpf node with
 * no program drops everything, so "no frame arrived" is indistinguishable from
 * "the frame was filtered" unless frames are first shown to arrive at all. An
 * earlier version of this test passed CASE 2 vacuously for exactly that reason.
 *
 * FreeBSD only.
 */

#include "../src/reassembly.h"
#include "../src/sni.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * INCLUDE ORDER IS LOAD-BEARING. netgraph/ng_socket.h uses sa_family_t, which
 * only sys/socket.h defines -- and it is not included transitively on FreeBSD.
 * sys/socket.h first (for sa_family_t, SOL_SOCKET, setsockopt), then net/bpf.h
 * and netgraph.h before the node-specific headers, because NG_HOOKSIZ comes
 * from netgraph.h. Measured: getting this wrong produces "unknown type name
 * 'sa_family_t'" and "use of undeclared identifier 'SOL_SOCKET'", neither of
 * which points at include order.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/bpf.h>
#include <netgraph.h>
#include <netgraph/ng_bpf.h>
#include <netgraph/ng_message.h>
#include <netgraph/ng_socket.h>

static int failures;
static int checks;

#define CHECK(cond, msg)                                                      \
	do {                                                                  \
		checks++;                                                     \
		if (!(cond)) {                                                \
			failures++;                                           \
			printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
		}                                                             \
	} while (0)

/* Build a whole Ethernet frame carrying a TLS ClientHello with `sni`. */
static size_t build_frame(unsigned char *out, size_t cap, const char *sni,
                          size_t *sni_off)
{
	unsigned char ch[1024];
	size_t b = 0, nlen = strlen(sni), f = 0, i;

	/* ClientHello body */
	ch[b++] = 0x03; ch[b++] = 0x03;
	memset(ch + b, 0xAB, 32); b += 32;
	ch[b++] = 0x00;                       /* session id */
	ch[b++] = 0x00; ch[b++] = 0x02;       /* cipher suites */
	ch[b++] = 0x00; ch[b++] = 0x2f;
	ch[b++] = 0x01; ch[b++] = 0x00;       /* compression */
	{
	/*
	 * The extensions block is PREFIXED with its total length, and an
	 * earlier version of this builder omitted it. The parser then
	 * read the extension TYPE as that length, found zero, walked no
	 * extensions, and correctly reported "no server_name" -- the
	 * frame was the thing that was wrong.
	 */
	size_t ext_total_at = b;
	size_t ext;
	size_t list;

	b += 2;                           /* extensions total, filled below */
	ext = b;
	ch[b++] = 0x00; ch[b++] = 0x00;   /* server_name */
	b += 2;                           /* ext length, filled below */
	list = b;
	b += 2;                           /* list length, filled below */
	ch[b++] = 0x00;                   /* host_name */
	ch[b++] = (unsigned char)((nlen >> 8) & 0xff);
	ch[b++] = (unsigned char)(nlen & 0xff);
	memcpy(ch + b, sni, nlen);
	b += nlen;
	{
		size_t ll = b - list - 2;
		unsigned int ev = (unsigned int)(b - ext - 4);

		ch[list] = (unsigned char)((ll >> 8) & 0xff);
		ch[list + 1] = (unsigned char)(ll & 0xff);
		ch[ext + 2] = (unsigned char)((ev >> 8) & 0xff);
		ch[ext + 3] = (unsigned char)(ev & 0xff);
		{
			size_t et = b - ext_total_at - 2;

			ch[ext_total_at] =
				(unsigned char)((et >> 8) & 0xff);
			ch[ext_total_at + 1] =
				(unsigned char)(et & 0xff);
		}
	}
	}
	{
		size_t hs, rec;
		unsigned char hs_buf[1200 + 9];
		size_t hb = 0;

		hs_buf[hb++] = 0x01;
		hs_buf[hb++] = 0;
		hs_buf[hb++] = 0;
		hs_buf[hb++] = 0;
		memcpy(hs_buf + hb, ch, b);
		hb += b;
		hs = b;
		hs_buf[1] = (unsigned char)((hs >> 16) & 0xff);
		hs_buf[2] = (unsigned char)((hs >> 8) & 0xff);
		hs_buf[3] = (unsigned char)(hs & 0xff);

		rec = hs + 4;
		out[f++] = 0x16; out[f++] = 0x03; out[f++] = 0x01;
		out[f++] = (unsigned char)((rec >> 8) & 0xff);
		out[f++] = (unsigned char)(rec & 0xff);
		memcpy(out + f, hs_buf, hb);
		f += hb;
	}

	/* now wrap: Ethernet + IPv4 + TCP */
	{
		size_t tls_len = f;
		unsigned char pkt[2048];
		size_t p = 0;
		size_t total = 20 + 20 + tls_len;

		memcpy(pkt, out, tls_len);

		/* move the TLS bytes to the end of the packet */
		{
			size_t off = 14 + 20 + 20;

			memset(out, 0x02, 12);
			out[12] = 0x08; out[13] = 0x00;
			out[14] = 0x45; out[15] = 0x00;
			out[16] = (unsigned char)((total >> 8) & 0xff);
			out[17] = (unsigned char)(total & 0xff);
			out[18] = 0; out[19] = 0;
			out[20] = 0; out[21] = 0;
			out[22] = 64; out[23] = 6;
			out[24] = 0; out[25] = 0;
			out[26] = 10; out[27] = 0; out[28] = 0; out[29] = 1;
			out[30] = 10; out[31] = 0; out[32] = 0; out[33] = 2;
			out[34] = 0x30; out[35] = 0x39;
			out[36] = 0x01; out[37] = 0xbb;
			for (i = 0; i < 8; i++) out[38 + i] = 0;
			out[46] = 0x50; out[47] = 0x18;
			out[48] = 0x72; out[49] = 0x10;
			out[50] = 0; out[51] = 0;
			out[52] = 0; out[53] = 0;
			memmove(out + off, pkt, tls_len);
			f = off + tls_len;
			(void)p;
		}
		/* where does the name start inside the frame? */
		{
			size_t k;

			*sni_off = 0;
			for (k = 0; k + nlen <= f; k++) {
				if (memcmp(out + k, sni, nlen) == 0) {
					*sni_off = k;
					break;
				}
			}
		}
	}
	(void)cap;
	return f;
}

static ssize_t try_recv(int ds, unsigned char *buf, size_t cap, int ms)
{
	struct timeval tv;
	/*
	 * THE 4TH ARGUMENT IS AN OUTPUT, NOT A SELECTOR. NgRecvData writes the
	 * hook name the data arrived on into it (strlcpy). Passing a string
	 * literal here segfaults inside libnetgraph, in strlcpy, with a stack
	 * that points at NgRecvData rather than at the mistake -- which is how
	 * this cost a core dump rather than a compile error. It must be a
	 * writable buffer.
	 */
	char hook[NG_HOOKSIZ];

	tv.tv_sec = ms / 1000;
	tv.tv_usec = (ms % 1000) * 1000;
	setsockopt(ds, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	return NgRecvData(ds, buf, cap, hook);
}

int main(void)
{
	unsigned char frame[2048], rbuf[2048];
	size_t flen, sni_off = 0;
	const char *sni = "live-ng-sni.example";
	int cs_src = -1, ds_src = -1, cs_sink = -1, ds_sink = -1;
	struct ngm_mkpeer mp;
	struct ngm_connect cn;
	int rc, control_ok;

	printf("=== live netgraph transport ===\n\n");

	system("/usr/sbin/ngctl shutdown src:  >/dev/null 2>&1");
	system("/usr/sbin/ngctl shutdown sink: >/dev/null 2>&1");
	system("/usr/sbin/ngctl shutdown aisense_bpf: >/dev/null 2>&1");

	rc = NgMkSockNode("src", &cs_src, &ds_src);
	if (rc < 0) {
		perror("NgMkSockNode(src)");
		return 2;
	}
	rc = NgMkSockNode("sink", &cs_sink, &ds_sink);
	if (rc < 0) {
		perror("NgMkSockNode(sink)");
		return 2;
	}
	(void)cs_sink;
	flen = build_frame(frame, sizeof frame, sni, &sni_off);
	CHECK(flen > 60 && sni_off > 0, "built a frame containing the SNI");

	/* --- mkpeer: hang bpf off src:out --- */
	memset(&mp, 0, sizeof mp);
	strcpy(mp.type, "bpf");
	strcpy(mp.ourhook, "out");
	strcpy(mp.peerhook, "in");
	rc = NgSendMsg(cs_src, "src:", NGM_GENERIC_COOKIE, NGM_MKPEER, &mp,
	               sizeof mp);
	CHECK(rc >= 0, "mkpeer created the bpf node");

	/* --- the addressing trap: name it via the hook path --- */
	rc = NgNameNode(cs_src, "src:out", "%s", "live_bpf");
	CHECK(rc >= 0, "resolved the auto-created node through the hook path "
	               "(mkpeer leaves it unnamed, so 'bpf:' never resolves)");
	if (rc < 0) {
		printf("RESULT: cannot address the node; later cases would be "
		       "vacuous. Stopping.\n");
		return 1;
	}

	/* --- connect the match output to the sink --- */
	memset(&cn, 0, sizeof cn);
	strcpy(cn.path, "sink:");
	strcpy(cn.ourhook, "match");
	strcpy(cn.peerhook, "in");
	rc = NgSendMsg(cs_src, "live_bpf:", NGM_GENERIC_COOKIE, NGM_CONNECT,
	               &cn, sizeof cn);
	CHECK(rc >= 0, "connected the matcher output to the sink");

	/* --- THE CONTROL: accept-all program, prove frames arrive --- */
	{
		struct ng_bpf_hookprog *p;
		int sz = (int)NG_BPF_HOOKPROG_SIZE(1);

		p = calloc(1, (size_t)sz);
		strncpy(p->thisHook, "in", NG_HOOKSIZ - 1);
		strncpy(p->ifMatch, "match", NG_HOOKSIZ - 1);
		p->ifNotMatch[0] = '\0';
		p->bpf_prog_len = 1;
		p->bpf_prog[0].code = BPF_RET | BPF_K;
		p->bpf_prog[0].k = 0xffffffff;
		rc = NgSendMsg(cs_src, "live_bpf:", NGM_BPF_COOKIE,
		               NGM_BPF_SET_PROGRAM, p, (size_t)sz);
		free(p);
		CHECK(rc >= 0, "installed an accept-all program (the control)");
	}

	rc = NgSendData(ds_src, "out", frame, flen);
	CHECK(rc >= 0, "injected the frame from userspace");
	rc = (int)try_recv(ds_sink, rbuf, sizeof rbuf, 3000);
	control_ok = rc > 0;
	CHECK(control_ok, "CONTROL: the frame ARRIVES -- so later silence means "
	                  "the MATCH, not a dead graph");
	if (!control_ok) {
		printf("\nRESULT: the graph cannot deliver a frame even when told "
		       "to accept everything. Later cases would be vacuous; "
		       "stopping.\n");
		return 1;
	}

	/* --- now install the real ClientHello matcher --- */
	{
		struct ng_bpf_hookprog *p;
		int sz = (int)NG_BPF_HOOKPROG_SIZE(7);

		p = calloc(1, (size_t)sz);
		strncpy(p->thisHook, "in", NG_HOOKSIZ - 1);
		strncpy(p->ifMatch, "match", NG_HOOKSIZ - 1);
		p->ifNotMatch[0] = '\0';
		p->bpf_prog_len = 7;
		/*
		 * Offsets are 54 (TLS record header: 14 eth + 20 ip + 20 tcp)
		 * and 59 (handshake message type). Getting these wrong is
		 * INVISIBLE: the program installs fine and simply never
		 * matches, which looks identical to working correctly.
		 */
		p->bpf_prog[0].code = BPF_LD | BPF_H | BPF_ABS;
		p->bpf_prog[0].k = 54;
		p->bpf_prog[1].code = BPF_JMP | BPF_JEQ | BPF_K;
		p->bpf_prog[1].k = 0x1603;
		p->bpf_prog[1].jt = 1; p->bpf_prog[1].jf = 0;
		p->bpf_prog[2].code = BPF_RET | BPF_K;
		p->bpf_prog[2].k = 0;
		p->bpf_prog[3].code = BPF_LD | BPF_B | BPF_ABS;
		p->bpf_prog[3].k = 59;
		p->bpf_prog[4].code = BPF_JMP | BPF_JEQ | BPF_K;
		p->bpf_prog[4].k = 0x01;
		p->bpf_prog[4].jt = 1; p->bpf_prog[4].jf = 0;
		p->bpf_prog[5].code = BPF_RET | BPF_K;
		p->bpf_prog[5].k = 0;
		p->bpf_prog[6].code = BPF_RET | BPF_K;
		p->bpf_prog[6].k = 0xffffffff;
		rc = NgSendMsg(cs_src, "live_bpf:", NGM_BPF_COOKIE,
		               NGM_BPF_SET_PROGRAM, p, (size_t)sz);
		free(p);
		CHECK(rc >= 0, "installed the in-kernel ClientHello matcher");
	}

	/* CASE 1: a real ClientHello must reach us, name readable */
	NgSendData(ds_src, "out", frame, flen);
	rc = (int)try_recv(ds_sink, rbuf, sizeof rbuf, 3000);
	CHECK(rc > 0, "CASE 1: the ClientHello reached userspace");
	if (rc > 0) {
		char host[SNI_MAX_NAME];
		const unsigned char *pl = NULL;
		size_t pl_len = 0, need = 0;
		enum sni_result sr;
		int found = 0;
		size_t k;

		for (k = 0; k + strlen(sni) <= (size_t)rc; k++)
			if (memcmp(rbuf + k, sni, strlen(sni)) == 0)
				found = 1;
		CHECK(found, "CASE 1: the SNI hostname is present in the bytes "
		             "that reached userspace");

		/* and the parser recovers it, which is what a decision needs */
		sr = sni_extract_frame(rbuf, (size_t)rc, host, sizeof host, &need,
		                       &pl, &pl_len);
		CHECK(sr == SNI_FOUND, "CASE 1: sni_extract_frame parses it");
		CHECK(strcmp(host, sni) == 0,
		      "CASE 1: and recovers exactly the injected hostname");
	}

	/* CASE 2: a non-ClientHello must NOT reach us */
	{
		unsigned char other[2048];

		memcpy(other, frame, flen);
		other[59] = 0x02;   /* handshake type: ServerHello, not Client */
		NgSendData(ds_src, "out", other, flen);
		rc = (int)try_recv(ds_sink, rbuf, sizeof rbuf, 2000);
		CHECK(rc <= 0, "CASE 2: a ServerHello did NOT reach userspace, so "
		               "the kernel matcher is actually filtering");
	}

	/* CASE 3: a non-TLS frame must NOT reach us */
	{
		unsigned char ssh[128];

		memset(ssh, 0x02, 12);
		ssh[12] = 0x08; ssh[13] = 0x00;
		memcpy(ssh + 14, "GET / HTTP/1.1\r\n\r\n", 18);
		NgSendData(ds_src, "out", ssh, 32);
		rc = (int)try_recv(ds_sink, rbuf, sizeof rbuf, 2000);
		CHECK(rc <= 0, "CASE 3: plain HTTP did not reach userspace");
	}

	system("/usr/sbin/ngctl shutdown src:  >/dev/null 2>&1");
	system("/usr/sbin/ngctl shutdown sink: >/dev/null 2>&1");

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
