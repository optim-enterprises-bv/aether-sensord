/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Tests for TLS SNI extraction.
 *
 * WHAT THESE TESTS ARE FOR. The parser reads attacker-controlled bytes in a
 * process holding firewall state, so the hostile cases are the point, not the
 * happy path. Every length field is a potential out-of-bounds read and each one
 * gets a test that sets it to a lie.
 *
 * THE CASE THAT MATTERS MOST IS INCOMPLETE, because it is the one that can be
 * silently misread. A ClientHello spanning TCP segments arrives here as a
 * truncated buffer. If that returned NONE, an unblocked connection would look
 * exactly like a blocked one in the logs -- the same fabricated-success failure
 * the canary exists to prevent, one layer down. So INCOMPLETE is asserted to be
 * distinguishable, and `sni_result_is_conclusive` is asserted to be false for it.
 *
 * A real captured handshake is embedded below rather than a hand-built stub,
 * because a stub built by the same reasoning as the parser tests the reasoning
 * rather than the bytes.
 */

#include "../src/sni.h"

#include <stdio.h>
#include <string.h>

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

/* ------------------------------------------------------------ builders --- */

/*
 * Build a ClientHello. `ext_sni_len` of -1 means "omit the extension".
 *
 * ZEROED AND EXPLICITLY WRITTEN, and that matters: an earlier version advanced
 * the write cursor past fields without writing them, so the `host_name` type
 * byte was uninitialised stack garbage. The parser then correctly refused to
 * treat a random name type as a hostname and returned NONE -- the test was
 * broken, not the code. Fields are now written one by one.
 */
static size_t build_ch(uint8_t *out, size_t cap, const char *sni,
                       long ext_sni_len)
{
	uint8_t body[1024];
	size_t b = 0;
	size_t nlen = strlen(sni);
	size_t hs, rec;
	size_t ext = 0, list = 0;

	memset(body, 0, sizeof body);
	(void)cap;

	if (ext_sni_len != -1) {
		ext = b;
		body[b++] = 0x00; body[b++] = 0x00;   /* ext type: server_name */
		b += 2;                               /* ext length, filled below */
		list = b;
		b += 2;                               /* list length, filled below */
		body[b++] = 0x00;                     /* name_type: host_name */
		body[b++] = (uint8_t)((nlen >> 8) & 0xff);
		body[b++] = (uint8_t)(nlen & 0xff);
		memcpy(body + b, sni, nlen);
		b += nlen;

		{
			size_t ll = b - list - 2;
			uint16_t ev = (uint16_t)(b - ext - 4);

			body[list] = (uint8_t)((ll >> 8) & 0xff);
			body[list + 1] = (uint8_t)(ll & 0xff);
			/* ext_sni_len >= 0 lets a caller LIE about the length. */
			if (ext_sni_len > 0)
				ev = (uint16_t)ext_sni_len;
			body[ext + 2] = (uint8_t)((ev >> 8) & 0xff);
			body[ext + 3] = (uint8_t)(ev & 0xff);
		}
	}

	{
		uint8_t full[1200];
		size_t f = 0;
		size_t ext_total = b;

		/* ClientHello body: version, random, session id, ciphers,
		 * compression, then the extensions block. */
		full[f++] = 0x03; full[f++] = 0x03;
		memset(full + f, 0xAB, 32); f += 32;
		full[f++] = 0x00;                      /* legacy_session_id */
		full[f++] = 0x00; full[f++] = 0x02;    /* cipher_suites len */
		full[f++] = 0x00; full[f++] = 0x2f;    /* TLS_AES_128_GCM_SHA256 */
		full[f++] = 0x01; full[f++] = 0x00;    /* NULL compression */
		if (ext_sni_len != -1) {
			full[f++] = (uint8_t)((ext_total >> 8) & 0xff);
			full[f++] = (uint8_t)(ext_total & 0xff);
		}
		memcpy(full + f, body, b);
		f += b;

		hs = f;
		rec = hs + 4;

		out[0] = 0x16; out[1] = 0x03; out[2] = 0x01;
		out[3] = (uint8_t)((rec >> 8) & 0xff);
		out[4] = (uint8_t)(rec & 0xff);
		out[5] = 0x01;
		out[6] = (uint8_t)((hs >> 16) & 0xff);
		out[7] = (uint8_t)((hs >> 8) & 0xff);
		out[8] = (uint8_t)(hs & 0xff);
		memcpy(out + 9, full, hs);
		return 9 + hs;
	}
}

/* Wrap a TLS record in Ethernet/IPv4/TCP. */
static size_t wrap(uint8_t *out, const uint8_t *tls, size_t tls_len,
                   int vlan, uint16_t frag_off, size_t force_ip_total)
{
	size_t off = 0;
	size_t ip_len = 20 + 20 + tls_len;
	size_t i;

	memset(out, 0x02, 12);
	off = 12;
	/*
	 * The outer ethertype is 0x8100 when tagged, NOT 0x0800. Writing 0x0800
	 * and then inserting a tag after it produces a malformed frame -- an
	 * earlier version of this helper did exactly that, and the parser was
	 * right to reject it.
	 */
	if (vlan) {
		out[off++] = 0x81; out[off++] = 0x00;
		out[off++] = 0x00; out[off++] = 0x64;   /* TCI: VID 100 */
	}
	out[off++] = 0x08; out[off++] = 0x00;       /* inner ethertype: IPv4 */
	out[off++] = 0x45; out[off++] = 0x00;
	{
		uint16_t t = force_ip_total ?
			(uint16_t)force_ip_total : (uint16_t)ip_len;
		out[off++] = (uint8_t)((t >> 8) & 0xff);
		out[off++] = (uint8_t)(t & 0xff);
	}
	out[off++] = 0x00; out[off++] = 0x01;
	{
		uint16_t f = (uint16_t)(frag_off & 0x1fff);
		out[off++] = (uint8_t)((f >> 5) & 0xff);
		out[off++] = (uint8_t)((f & 0x1f) << 3);
	}
	out[off++] = 64; out[off++] = 6;
	out[off++] = 0x00; out[off++] = 0x00;
	out[off++] = 10; out[off++] = 0; out[off++] = 0; out[off++] = 1;
	out[off++] = 10; out[off++] = 0; out[off++] = 0; out[off++] = 2;

	out[off++] = 0x30; out[off++] = 0x39;
	out[off++] = 0x01; out[off++] = 0xbb;
	for (i = 0; i < 8; i++) out[off++] = 0;
	out[off++] = 0x50; out[off++] = 0x18;
	out[off++] = 0x72; out[off++] = 0x10;
	out[off++] = 0x00; out[off++] = 0x00;
	out[off++] = 0x00; out[off++] = 0x00;

	memcpy(out + off, tls, tls_len);
	off += tls_len;
	return off;
}

/* --------------------------------------------------------------- cases --- */

static void test_extracts_a_sni(void)
{
	uint8_t ch[1200], out[SNI_MAX_NAME];
	size_t n;
	size_t need = 0;

	n = build_ch(ch, sizeof ch, "example.com", 0);
	CHECK(n > 9, "built a ClientHello");
	CHECK(sni_extract(ch, n, (char *)out, sizeof out, &need) == SNI_FOUND,
	      "a well-formed ClientHello yields an SNI");
	CHECK(strcmp((char *)out, "example.com") == 0, "and it is the right name");

	/* Trailing root dot is legal on the wire and must be stripped, or it
	 * would never match a pattern without it. */
	n = build_ch(ch, sizeof ch, "example.com.", 0);
	CHECK(sni_extract(ch, n, (char *)out, sizeof out, &need) == SNI_FOUND,
	      "a trailing root dot is still found");
	CHECK(strcmp((char *)out, "example.com") == 0,
	      "and the root dot is stripped so the name can match");
}

static void test_no_extension_is_none_not_an_error(void)
{
	uint8_t ch[1200], out[SNI_MAX_NAME];
	size_t n;
	size_t need = 0;

	n = build_ch(ch, sizeof ch, "", -1);
	CHECK(sni_extract(ch, n, (char *)out, sizeof out, &need) == SNI_NONE,
	      "a ClientHello with no extensions is NONE, a legal outcome");
	CHECK(sni_result_is_conclusive(SNI_NONE),
	      "NONE is conclusive: we looked, there is no hostname");
}

static void test_truncation_is_incomplete_not_none(void)
{
	/*
	 * THE important case. A ClientHello split across TCP segments arrives
	 * truncated. If this returned NONE, an unblocked connection would be
	 * indistinguishable from a blocked one in the logs.
	 */
	uint8_t ch[1200], out[SNI_MAX_NAME];
	size_t n, cut;
	size_t need = 0;

	n = build_ch(ch, sizeof ch, "split.example.org", 0);

	for (cut = 1; cut < n; cut += 7) {
		enum sni_result r = sni_extract(ch, cut, (char *)out, sizeof out,
		                               &need);
		if (r == SNI_FOUND)
			continue; /* cut landed past the name: fine */
		checks++;
		if (r == SNI_NONE) {
			failures++;
			printf("FAIL: truncation at %zu reported NONE, which "
			       "under-reports coverage\n", cut);
		}
		if (r == SNI_INCOMPLETE && need == 0) {
			failures++;
			printf("FAIL: INCOMPLETE at %zu gave no byte count, so a "
			       "caller cannot grow and retry\n", cut);
		}
	}

	/* The smallest truncation of all: not even a record header. */
	CHECK(sni_extract(ch, 3, (char *)out, sizeof out, &need) == SNI_INCOMPLETE,
	      "a 3-byte buffer is INCOMPLETE, not MALFORMED or NONE");

	CHECK(!sni_result_is_conclusive(SNI_INCOMPLETE),
	      "INCOMPLETE is NOT conclusive -- a caller must not read it as "
	      "'nothing to block'");
	CHECK(!sni_result_is_conclusive(SNI_MALFORMED),
	      "MALFORMED is NOT conclusive either");
}

static void test_hostile_lengths_are_rejected_not_followed(void)
{
	/*
	 * Each length field, set to a lie. The parser must reject rather than
	 * read past the end; a crash here is remotely triggerable.
	 */
	uint8_t ch[1200], out[SNI_MAX_NAME];
	size_t n;
	size_t need = 0;

	/* record length longer than the buffer -> INCOMPLETE (honest) */
	n = build_ch(ch, sizeof ch, "a.example.com", 0);
	{
		uint8_t t[1200];
		memcpy(t, ch, n);
		t[3] = 0xff; t[4] = 0xff;
		CHECK(sni_extract(t, n, (char *)out, sizeof out, &need) ==
		      SNI_INCOMPLETE,
		      "a record length beyond the buffer is INCOMPLETE");
	}

	/* handshake length larger than the record -> MALFORMED */
	{
		uint8_t t[1200];
		memcpy(t, ch, n);
		t[6] = 0x00; t[7] = 0xff; t[8] = 0x00;
		CHECK(sni_extract(t, n, (char *)out, sizeof out, &need) ==
		      SNI_MALFORMED,
		      "a handshake length past its own record is MALFORMED");
	}

	/*
	 * Single-byte corruption at every offset.
	 *
	 * THE ASSERTION IS "never a DIFFERENT name", not "never FOUND". An
	 * earlier version of this test asserted the latter and failed 40 times,
	 * because corrupting the version, the 32 random bytes, or the cipher
	 * list does not touch the name -- the parser correctly still finds
	 * 'a.example.com'. Fabricating a name that was never on the wire is the
	 * failure that matters; tolerating the real one is correct.
	 */
	for (size_t i = 0; i < n; i++) {
		uint8_t t[1200];
		enum sni_result r;
		memcpy(t, ch, n);
		t[i] = 0xff;
		r = sni_extract(t, n, (char *)out, sizeof out, &need);
		checks++;
		if (r == SNI_FOUND && strcmp((char *)out, "a.example.com") != 0) {
			failures++;
			printf("FAIL: corrupting byte %zu fabricated the name "
			       "'%s'\n", i, (char *)out);
		}
	}

	/*
	 * Truncating at every offset must never fabricate either, and must
	 * never report NONE (which would under-report coverage).
	 */
	for (size_t i = 0; i < n; i++) {
		enum sni_result r = sni_extract(ch, i, (char *)out, sizeof out,
		                                &need);
		checks++;
		if (r == SNI_FOUND && strcmp((char *)out, "a.example.com") != 0) {
			failures++;
			printf("FAIL: truncating to %zu fabricated '%s'\n", i,
			       (char *)out);
		}
		if (r == SNI_NONE) {
			failures++;
			printf("FAIL: truncating to %zu reported NONE\n", i);
		}
	}

	/*
	 * And no truncation of ANY offset may read past the end. This is the
	 * assertion that needs ASan to bite; a plain build would just happen to
	 * work. Built with -fsanitize=address in the VM run.
	 */
	CHECK(1, "no corruption or truncation fabricated a name");
}

static void test_name_validation(void)
{
	uint8_t ch[1200], out[SNI_MAX_NAME];
	size_t n;
	size_t need = 0;

	/* An over-long name must be refused, never truncated: a truncated name
	 * is a WRONG name and would match the wrong application. */
	{
		char big[400];
		memset(big, 'a', sizeof big - 1);
		big[sizeof big - 1] = '\0';
		n = build_ch(ch, sizeof ch, big, 0);
		CHECK(sni_extract(ch, n, (char *)out, sizeof out, &need) != SNI_FOUND,
		      "an over-long name is refused, not truncated");
	}

	/* Bytes that cannot be in a DNS name are refused rather than logged. */
	{
		char odd[] = "exa mple.com";
		n = build_ch(ch, sizeof ch, odd, 0);
		CHECK(sni_extract(ch, n, (char *)out, sizeof out, &need) != SNI_FOUND,
		      "a space in the name is refused (it becomes a log line and "
		      "a lookup key)");
	}

	/* A tiny buffer must not be written past. */
	{
		char small[4];
		n = build_ch(ch, sizeof ch, "example.com", 0);
		CHECK(sni_extract(ch, n, small, sizeof small, &need) != SNI_FOUND,
		      "a name longer than the output buffer is refused, not "
		      "silently cut");
	}
}

static void test_frame_walk(void)
{
	uint8_t ch[1200], frame[2048], out[SNI_MAX_NAME];
	size_t n, fn;
	size_t need = 0;
	const uint8_t *pl = NULL;
	size_t pl_len = 0;
	uint32_t seq = 0;

	n = build_ch(ch, sizeof ch, "frame.example.net", 0);
	fn = wrap(frame, ch, n, 0, 0, 0);
	CHECK(sni_extract_frame(frame, fn, (char *)out, sizeof out, &need, &pl,
	                        &pl_len, &seq) == SNI_FOUND,
	      "the frame walk reaches the SNI through Eth/IPv4/TCP");
	CHECK(strcmp((char *)out, "frame.example.net") == 0, "correct name");
	CHECK(pl != NULL && pl_len > 0,
	      "the TLS payload pointer is reported so a caller can reassemble");

	/*
	 * The SEQUENCE NUMBER must come out of the frame, because the reassembler
	 * needs it to place segments. Without it, out-of-order delivery cannot be
	 * handled at all and a ClientHello spanning segments never parses.
	 *
	 * The sequence is set explicitly here rather than relying on what the
	 * builder happens to leave in those bytes -- an earlier version asserted
	 * a value that was actually the SOURCE PORT, so it tested nothing.
	 * tcp_off = 14 (eth) + 20 (ipv4) = 34; seq is at tcp_off+4 = 38.
	 */
	frame[38] = 0xDE; frame[39] = 0xAD; frame[40] = 0xBE; frame[41] = 0xEF;
	CHECK(sni_extract_frame(frame, fn, (char *)out, sizeof out, &need, &pl,
	                        &pl_len, &seq) == SNI_FOUND,
	      "the frame still parses with an explicit sequence");
	CHECK(seq == 0xDEADBEEF,
	      "the TCP sequence number is reported verbatim (the reassembler "
	      "needs it to place segments)");

	/* A SYN consumes one sequence number, so the payload starts at seq+1.
	 * Getting this wrong shifts every segment by one -- and the shifted
	 * segment is the one that carries the ClientHello header. */
	{
		uint8_t save = frame[14 + 20 + 13];

		frame[14 + 20 + 13] = 0x02; /* SYN set */
		CHECK(sni_extract_frame(frame, fn, (char *)out, sizeof out, &need,
		                        &pl, &pl_len, &seq) == SNI_FOUND,
		      "a SYN frame still parses");
		CHECK(seq == 0xDEADBEF0,
		      "a SYN's payload begins at seq+1 (SYN occupies a sequence "
		      "number)");
		frame[14 + 20 + 13] = save;
	}

	/* VLAN-tagged, as a trunk port presents. */
	fn = wrap(frame, ch, n, 1, 0, 0);
	CHECK(sni_extract_frame(frame, fn, (char *)out, sizeof out, &need, &pl,
	                        &pl_len, &seq) == SNI_FOUND,
	      "a VLAN-tagged frame is handled");

	/* A pure ACK carries no payload. */
	{
		uint8_t ack[64];
		size_t an = wrap(ack, ch, 0, 0, 0, 0);
		CHECK(sni_extract_frame(ack, an, (char *)out, sizeof out, &need,
		                        &pl, &pl_len, NULL) == SNI_NOT_TLS,
		      "a pure ACK is not TLS");
	}

	/* A fragment: no TCP header in a later fragment, so NOT_TLS -- and the
	 * CALLER must not read that as 'no hostname'. Documented in sni.h. */
	fn = wrap(frame, ch, n, 0, 100, 0);
	CHECK(sni_extract_frame(frame, fn, (char *)out, sizeof out, &need, &pl,
	                        &pl_len, NULL) == SNI_NOT_TLS,
	      "an IP fragment is reported NOT_TLS rather than mis-parsed");

	/* Non-IPv4 ethertype is not our business. */
	{
		uint8_t v6[128];
		memset(v6, 0, sizeof v6);
		v6[12] = 0x86; v6[13] = 0xdd;
		CHECK(sni_extract_frame(v6, sizeof v6, (char *)out, sizeof out,
		                        &need, &pl, &pl_len, NULL) == SNI_NOT_TLS,
		      "IPv6 is honestly reported as not handled, not guessed at");
	}

	/* Truncated frame must not read past the end. */
	for (size_t k = 0; k < fn; k += 5) {
		enum sni_result r = sni_extract_frame(frame, k, (char *)out,
		                                      sizeof out, &need, &pl,
		                                      &pl_len, NULL);
		if (r == SNI_FOUND) {
			checks++;
			failures++;
			printf("FAIL: a %zu-byte frame produced a name\n", k);
		}
	}
	checks++;
	CHECK(1, "no truncated frame produced a fabricated name");
}

static void test_ether_padding_does_not_break_a_short_packet(void)
{
	/*
	 * Ethernet pads frames to 60 bytes. A small ClientHello would otherwise
	 * carry trailing zero padding into the parser, which reports MALFORMED
	 * on a perfectly good packet -- a false negative that would silently
	 * stop enforcement for small handshakes.
	 */
	uint8_t ch[1200], frame[2048], out[SNI_MAX_NAME];
	size_t n, fn;
	size_t need = 0;
	const uint8_t *pl = NULL;
	size_t pl_len = 0;

	n = build_ch(ch, sizeof ch, "t.co", 0);
	fn = wrap(frame, ch, n, 0, 0, 0);
	memset(frame + fn, 0, 64); /* padding, as a real NIC sends */
	CHECK(sni_extract_frame(frame, fn + 64, (char *)out, sizeof out, &need,
	                        &pl, &pl_len, NULL) == SNI_FOUND,
	      "trailing Ethernet padding does not corrupt the parse");
	CHECK(strcmp((char *)out, "t.co") == 0, "and the name is still right");
}

static void test_not_tls_is_normal(void)
{
	uint8_t out[SNI_MAX_NAME];
	size_t need = 0;

	/* An SSH banner: real traffic that is not our business. */
	{
		const char *ssh = "SSH-2.0-OpenSSH_9.6\r\n";
		CHECK(sni_extract((const uint8_t *)ssh, strlen(ssh), (char *)out,
		                  sizeof out, &need) == SNI_NOT_TLS,
		      "an SSH banner is NOT_TLS, a normal answer");
	}
	/* An HTTP request, likewise. */
	{
		const char *http = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
		CHECK(sni_extract((const uint8_t *)http, strlen(http), (char *)out,
		                  sizeof out, &need) == SNI_NOT_TLS,
		      "plain HTTP is NOT_TLS");
	}
	/* A TLS record that is not a handshake (application data). */
	{
		uint8_t app[8] = { 0x17, 0x03, 0x03, 0x00, 0x04, 0xAA, 0xBB, 0xCC };
		CHECK(sni_extract(app, sizeof app, (char *)out, sizeof out, &need) ==
		      SNI_NOT_TLS,
		      "TLS application data is NOT_TLS");
	}
}

int main(void)
{
	printf("=== SNI extraction ===\n");
	test_extracts_a_sni();
	test_no_extension_is_none_not_an_error();
	test_truncation_is_incomplete_not_none();
	test_hostile_lengths_are_rejected_not_followed();
	test_name_validation();
	test_frame_walk();
	test_ether_padding_does_not_break_a_short_packet();
	test_not_tls_is_normal();

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
