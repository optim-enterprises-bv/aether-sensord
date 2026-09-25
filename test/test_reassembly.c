/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Tests for TCP stream reassembly.
 *
 * THE CASES THAT MATTER, and why each is here rather than the happy path:
 *
 *   1. OUT-OF-ORDER is the whole reason this file exists. The naive
 *      "append every segment" implementation passes an in-order test and fails
 *      this one by parsing reordered bytes as garbage -- which is then reported
 *      as malformed, i.e. as "nothing to block". An attacker reorders two
 *      segments and the filter stops working. Tested at every split point.
 *
 *   2. A GAP must not become NEED_MORE forever. A flow that never resolves and
 *      is never evicted is a memory leak an attacker drives.
 *
 *   3. WRAPAROUND. Sequence numbers are 32-bit and wrap. A plain `<` comparison
 *      breaks a flow whose numbering sits near the wrap, which would look like a
 *      huge backwards jump and discard a legitimate ClientHello.
 *
 *   4. OVERFLOW must drop bytes and say so, rather than growing. An attacker
 *      choosing our footprint is how a filter becomes a DoS target.
 */

#include "../src/reassembly.h"

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

/* Build a ClientHello, same construction as test_sni.c. */
static size_t build_ch(uint8_t *out, const char *sni)
{
	uint8_t body[1024];
	size_t b = 0, nlen = strlen(sni), hs, rec;
	size_t ext, list;

	memset(body, 0, sizeof body);
	ext = b;
	body[b++] = 0x00; body[b++] = 0x00;
	b += 2;
	list = b;
	b += 2;
	body[b++] = 0x00;
	body[b++] = (uint8_t)((nlen >> 8) & 0xff);
	body[b++] = (uint8_t)(nlen & 0xff);
	memcpy(body + b, sni, nlen);
	b += nlen;
	{
		size_t ll = b - list - 2;
		uint16_t ev = (uint16_t)(b - ext - 4);
		body[list] = (uint8_t)((ll >> 8) & 0xff);
		body[list + 1] = (uint8_t)(ll & 0xff);
		body[ext + 2] = (uint8_t)((ev >> 8) & 0xff);
		body[ext + 3] = (uint8_t)(ev & 0xff);
	}

	{
		uint8_t full[1200];
		size_t f = 0, ext_total = b;

		full[f++] = 0x03; full[f++] = 0x03;
		memset(full + f, 0xAB, 32); f += 32;
		full[f++] = 0x00;
		full[f++] = 0x00; full[f++] = 0x02;
		full[f++] = 0x00; full[f++] = 0x2f;
		full[f++] = 0x01; full[f++] = 0x00;
		full[f++] = (uint8_t)((ext_total >> 8) & 0xff);
		full[f++] = (uint8_t)(ext_total & 0xff);
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

static void test_single_segment(void)
{
	struct reasm_flow f;
	uint8_t ch[1200];
	char out[SNI_MAX_NAME];
	size_t n;
	enum reasm_result r;

	n = build_ch(ch, "one.example.com");
	reasm_init(&f);
	r = reasm_feed(&f, 1000, ch, n, out, sizeof out);
	CHECK(r == REASM_FOUND, "a whole ClientHello in one segment resolves");
	CHECK(strcmp(out, "one.example.com") == 0, "with the right name");
	CHECK(!reasm_wants_more(&f, r), "and the caller is told it can stop");
}

static void test_every_split_point(void)
{
	/*
	 * Split the ClientHello at every possible boundary, feed the two halves
	 * IN ORDER, and require the name every time. This covers the boundary
	 * cases that a single hand-picked split misses: a split inside the
	 * 2-byte extension length, one mid-name, one between the record header
	 * and the body.
	 */
	uint8_t ch[1200];
	size_t n, i;

	n = build_ch(ch, "split.example.com");
	CHECK(n > 60, "built a ClientHello big enough to split meaningfully");

	for (i = 1; i < n; i++) {
		struct reasm_flow f;
		char out[SNI_MAX_NAME];
		enum reasm_result r1, r2;

		reasm_init(&f);
		r1 = reasm_feed(&f, 5000, ch, i, out, sizeof out);
		checks++;
		if (r1 == REASM_FOUND) {
			/* split landed after the name: fine, must still be right */
			if (strcmp(out, "split.example.com") != 0) {
				failures++;
				printf("FAIL: split at %zu found '%s'\n", i, out);
			}
			continue;
		}
		if (r1 == REASM_INVALID || r1 == REASM_ABSOLUTE_NONE) {
			failures++;
			printf("FAIL: split at %zu gave %s before the rest "
			       "arrived\n", i, reasm_result_str(r1));
			continue;
		}

		r2 = reasm_feed(&f, 5000 + (uint32_t)i, ch + i, n - i, out,
		                sizeof out);
		checks++;
		if (r2 != REASM_FOUND || strcmp(out, "split.example.com") != 0) {
			failures++;
			printf("FAIL: in-order split at %zu -> %s ('%s')\n", i,
			       reasm_result_str(r2), out);
		}
	}
}

static void test_out_of_order(void)
{
	/*
	 * THE test this file exists for. Feed the second half FIRST.
	 *
	 * The naive append-everything implementation passes test_every_split_point
	 * and fails here, because it places the later bytes before the earlier
	 * ones and parses garbage.
	 */
	uint8_t ch[1200];
	size_t n, i;

	n = build_ch(ch, "ooo.example.com");

	for (i = 1; i < n; i++) {
		struct reasm_flow f;
		char out[SNI_MAX_NAME];
		enum reasm_result r;

		reasm_init(&f);
		r = reasm_feed(&f, 7000 + (uint32_t)i, ch + i, n - i, out,
		               sizeof out);
		checks++;
		if (r == REASM_FOUND) {
			/*
			 * The tail alone must never yield the full name: the
			 * name lives near the front, so a tail-only parse
			 * producing it would mean the offset logic is wrong.
			 */
			if (strcmp(out, "ooo.example.com") == 0 && i > 20) {
				failures++;
				printf("FAIL: tail-only segment at %zu yielded the "
				       "full name, so bytes were mis-placed\n", i);
			}
			continue;
		}
		r = reasm_feed(&f, 7000, ch, i, out, sizeof out);
		checks++;
		if (r != REASM_FOUND || strcmp(out, "ooo.example.com") != 0) {
			failures++;
			printf("FAIL: out-of-order split at %zu -> %s ('%s')\n",
			       i, reasm_result_str(r), out);
		}
	}
}

static void test_three_segments_out_of_order(void)
{
	/* A three-way split delivered as 3,1,2: the realistic reorder. */
	uint8_t ch[1200];
	char out[SNI_MAX_NAME];
	struct reasm_flow f;
	size_t n = build_ch(ch, "tri.example.org");
	size_t a = n / 3, b = (2 * n) / 3;
	enum reasm_result r;

	reasm_init(&f);
	(void)reasm_feed(&f, 9000 + (uint32_t)b, ch + b, n - b, out, sizeof out);
	(void)reasm_feed(&f, 9000, ch, a, out, sizeof out);
	r = reasm_feed(&f, 9000 + (uint32_t)a, ch + a, b - a, out, sizeof out);
	CHECK(r == REASM_FOUND && strcmp(out, "tri.example.org") == 0,
	      "a 3,1,2 reorder still resolves (appending would not)");
}

static void test_retransmission_is_harmless(void)
{
	uint8_t ch[1200];
	char out[SNI_MAX_NAME];
	struct reasm_flow f;
	size_t n = build_ch(ch, "retx.example.com");
	size_t half = n / 2;
	enum reasm_result r;

	reasm_init(&f);
	(void)reasm_feed(&f, 2000, ch, half, out, sizeof out);
	/* the same first segment again, as a retransmit */
	(void)reasm_feed(&f, 2000, ch, half, out, sizeof out);
	r = reasm_feed(&f, 2000 + (uint32_t)half, ch + half, n - half, out,
	               sizeof out);
	CHECK(r == REASM_FOUND && strcmp(out, "retx.example.com") == 0,
	      "a duplicated segment does not corrupt the stream");
}

static void test_gap_reports_will_not_resolve(void)
{
	/*
	 * A hole that never fills must become terminal, not NEED_MORE forever.
	 * A flow stuck in NEED_MORE is never evicted, which is a memory leak an
	 * attacker drives by sending one hole per connection.
	 *
	 * THE HOLE HAS TO BE A REAL ONE. An earlier version started the flow
	 * mid-stream and expected NEED_MORE; that actually returns NOT_TLS,
	 * because buf[0] is not a handshake byte -- correct and terminal, but it
	 * never exercises the gap path. A genuine interleaved hole is head bytes
	 * followed by bytes from LATER in the stream, leaving a middle missing.
	 */
	uint8_t ch[1200];
	char out[SNI_MAX_NAME];
	struct reasm_flow f;
	size_t n = build_ch(ch, "gap.example.com");
	size_t head = 12;        /* enough to hold the record header */
	/*
	 * The hole must cover the DECISIVE bytes, not just any middle chunk.
	 * An earlier version left the gap after the name, so the parse resolved
	 * from the head bytes alone and the test asserted the opposite of what
	 * it exercised. The name sits at the end of this ClientHello, so the
	 * hole is placed over it.
	 */
	size_t hole_at = n - 8;
	enum reasm_result r;
	int i;

	reasm_init(&f);
	r = reasm_feed(&f, 3000, ch, head, out, sizeof out);
	CHECK(r == REASM_NEED_MORE,
	      "the head alone waits for the body, it is not declared invalid");

	/* Now the bytes AFTER the hole, so a middle chunk including the name
	 * is missing. */
	r = reasm_feed(&f, 3000 + (uint32_t)hole_at, ch + hole_at, n - hole_at,
	               out, sizeof out);
	CHECK(r == REASM_NEED_MORE || r == REASM_WILL_NOT_RESOLVE,
	      "a hole still reports 'need more' while the budget lasts");

	/* Keep feeding further-along segments that never fill the hole. */
	for (i = 0; i < REASM_MAX_SEGS + 4 && r != REASM_WILL_NOT_RESOLVE; i++) {
		r = reasm_feed(&f, 3000 + (uint32_t)(n + i * 16), ch, 16, out,
		               sizeof out);
	}
	CHECK(r == REASM_WILL_NOT_RESOLVE,
	      "an unfilled hole eventually reports WILL_NOT_RESOLVE so the "
	      "flow can be evicted rather than buffered forever");
	CHECK(!reasm_wants_more(&f, r),
	      "and the caller is told to stop feeding it");

	/* And the hole FILLING IN must still resolve -- the same flow, fixed. */
	reasm_init(&f);
	(void)reasm_feed(&f, 3000, ch, head, out, sizeof out);
	r = reasm_feed(&f, 3000 + (uint32_t)hole_at, ch + hole_at, n - hole_at,
	               out, sizeof out);
	(void)r;
	r = reasm_feed(&f, 3000 + (uint32_t)head, ch + head, hole_at - head,
	               out, sizeof out);
	CHECK(r == REASM_FOUND && strcmp(out, "gap.example.com") == 0,
	      "the missing middle arriving late resolves the flow after all");
}

static void test_sequence_wraparound(void)
{
	/*
	 * Sequence numbers wrap at 2^32. A flow starting near the wrap must not
	 * look like an enormous backwards jump -- a plain `<` comparison gets
	 * this wrong and discards a legitimate ClientHello.
	 */
	uint8_t ch[1200];
	char out[SNI_MAX_NAME];
	struct reasm_flow f;
	size_t n = build_ch(ch, "wrap.example.net");
	size_t half = n / 2;
	uint32_t start = 0xFFFFFF00u; /* wraps during the handshake */
	enum reasm_result r;

	reasm_init(&f);
	(void)reasm_feed(&f, start, ch, half, out, sizeof out);
	r = reasm_feed(&f, start + (uint32_t)half, ch + half, n - half, out,
	               sizeof out);
	CHECK(r == REASM_FOUND && strcmp(out, "wrap.example.net") == 0,
	      "a sequence number that wraps mid-handshake still resolves");

	/* And the wrap as the very first segment boundary. */
	reasm_init(&f);
	(void)reasm_feed(&f, 0xFFFFFFFFu, ch, 1, out, sizeof out);
	r = reasm_feed(&f, 0u, ch + 1, n - 1, out, sizeof out);
	CHECK(r == REASM_FOUND && strcmp(out, "wrap.example.net") == 0,
	      "wrapping from 0xFFFFFFFF to 0 is handled");
}

static void test_overflow_drops_and_reports(void)
{
	/*
	 * Bounded memory. An attacker must not choose our footprint, so past the
	 * cap bytes are dropped and the flow says it was truncated.
	 *
	 * The junk is fed as ONE segment placed far ahead of the window, NOT as
	 * a long in-order stream: a long in-order stream of 0x41 is decided as
	 * NOT_TLS on its first byte, which is correct behaviour and tells us
	 * nothing about the cap. The cap is only exercised by a placement that
	 * runs off the end of the window.
	 */
	struct reasm_flow f;
	char out[SNI_MAX_NAME];
	uint8_t big[REASM_CAP + 512];
	enum reasm_result r;

	memset(big, 0x41, sizeof big);
	/* make the front look like a TLS handshake so nothing decides early */
	big[0] = 0x16; big[1] = 0x03; big[2] = 0x01;

	reasm_init(&f);
	r = reasm_feed(&f, 100, big, sizeof big, out, sizeof out);
	CHECK(f.len <= REASM_CAP, "the buffer never exceeds its cap");
	CHECK(reasm_was_truncated(&f),
	      "an overflowing flow reports truncation, so a capacity problem is "
	      "visible rather than silent");
	CHECK(r == REASM_NEED_MORE || r == REASM_INVALID ||
	      r == REASM_WILL_NOT_RESOLVE || r == REASM_NOT_TLS,
	      "and does not claim to have found a name in junk");

	/* A segment landing entirely beyond the window is terminal. */
	reasm_init(&f);
	r = reasm_feed(&f, 100, big, 16, out, sizeof out);
	(void)r;
	r = reasm_feed(&f, 100 + REASM_CAP + 64, big, 16, out, sizeof out);
	CHECK(r == REASM_WILL_NOT_RESOLVE,
	      "a segment beyond the window is terminal, not buffered");
	CHECK(reasm_was_truncated(&f), "and is reported as truncated");
}

static void test_not_tls_is_recognised_quickly(void)
{
	struct reasm_flow f;
	char out[SNI_MAX_NAME];
	enum reasm_result r;

	/* plain HTTP */
	reasm_init(&f);
	r = reasm_feed(&f, 10, (const uint8_t *)"GET / HTTP/1.1\r\n", 16, out,
	               sizeof out);
	CHECK(r == REASM_NOT_TLS, "HTTP is identified as not a ClientHello");
	CHECK(!reasm_wants_more(&f, r), "and no more segments are wanted");

	/* a lone 0x16 must NOT be called NOT_TLS: a ClientHello may follow */
	reasm_init(&f);
	r = reasm_feed(&f, 10, (const uint8_t *)"\x16", 1, out, sizeof out);
	CHECK(r == REASM_NEED_MORE,
	      "a single handshake-type byte waits for the rest, so a "
	      "one-byte-at-a-time ClientHello still gets parsed");
}

static void test_conclusive_none(void)
{
	/*
	 * A complete ClientHello with NO extensions at all.
	 *
	 * An earlier version of this test called build_ch(ch, "") and expected
	 * NONE -- but build_ch with an empty name still emits a server_name
	 * extension containing a zero-length name, which the parser correctly
	 * rejects as malformed. A hand-built record is used instead so the test
	 * actually constructs the case it claims to.
	 */
	struct reasm_flow f;
	char out[SNI_MAX_NAME];
	enum reasm_result r;
	uint8_t t[64];
	size_t n = 0;

	t[n++] = 0x16; t[n++] = 0x03; t[n++] = 0x01;
	t[n++] = 0x00; t[n++] = 0x2a;            /* record len 42 */
	t[n++] = 0x01;                            /* ClientHello */
	t[n++] = 0x00; t[n++] = 0x00; t[n++] = 0x26; /* hs len 38 */
	t[n++] = 0x03; t[n++] = 0x03;
	memset(t + n, 0xAB, 32); n += 32;
	t[n++] = 0x00;                            /* session id len 0 */
	t[n++] = 0x00; t[n++] = 0x02;             /* cipher suites len 2 */
	t[n++] = 0x00; t[n++] = 0x2f;
	t[n++] = 0x01; t[n++] = 0x00;             /* compression: NULL */

	/*
	 * Body so far: 2 + 32 + 1 + 2 + 2 + 1 + 1 = 41 bytes, so the handshake
	 * body length is 41 and the record body is 41 + 4 = 45. An earlier
	 * version hard-coded 0x2a/0x26 and the parser -- correctly -- called the
	 * mismatch malformed. The lengths are now derived from the data rather
	 * than asserted, so this test cannot drift out of step with what it
	 * builds.
	 */
	{
		size_t body = n - 9;      /* everything after the handshake header */

		t[6] = (uint8_t)((body >> 16) & 0xff);
		t[7] = (uint8_t)((body >> 8) & 0xff);
		t[8] = (uint8_t)(body & 0xff);
		t[3] = 0;
		t[4] = (uint8_t)(body + 4);
	}

	reasm_init(&f);
	r = reasm_feed(&f, 42, t, n, out, sizeof out);
	CHECK(r == REASM_ABSOLUTE_NONE,
	      "a complete ClientHello with no extensions is conclusive NONE");
	CHECK(!reasm_wants_more(&f, r), "and nothing more is wanted");
}

int main(void)
{
	printf("=== TCP reassembly for SNI ===\n");
	test_single_segment();
	test_every_split_point();
	test_out_of_order();
	test_three_segments_out_of_order();
	test_retransmission_is_harmless();
	test_gap_reports_will_not_resolve();
	test_sequence_wraparound();
	test_overflow_drops_and_reports();
	test_not_tls_is_recognised_quickly();
	test_conclusive_none();

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
