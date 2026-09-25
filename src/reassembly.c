/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * TCP stream reassembly for TLS SNI. See reassembly.h for the measured problem
 * and the deliberate limits.
 *
 * THE SHAPE OF THE BUG THIS AVOIDS. The obvious implementation -- append every
 * segment to a buffer and parse the buffer -- is wrong in a way that is easy to
 * miss: it silently reorders. If segment 2 arrives before segment 1, appending
 * puts the bytes in the wrong order and the ClientHello parses as garbage. That
 * garbage is then reported as MALFORMED, which a caller may treat as "nothing to
 * block" -- so an attacker reorders two segments and the filter stops working,
 * while the logs look like ordinary malformed traffic. Placing each segment at
 * its sequence offset is what makes the reorder case correct rather than quietly
 * broken.
 *
 * The second trap is reporting a gap as NEED_MORE forever. A gap in a TCP stream
 * sometimes fills in (reordering) and sometimes never does (a lost segment the
 * peer gave up on). Saying NEED_MORE for the second case means a flow that sits
 * in the table forever, which is a memory leak an attacker can drive. Past the
 * segment budget the answer becomes WILL_NOT_RESOLVE, which is honest and lets
 * the caller evict.
 */

#include "reassembly.h"

#include <string.h>

const char *reasm_result_str(enum reasm_result r)
{
	switch (r) {
	case REASM_FOUND:
		return "found";
	case REASM_ABSOLUTE_NONE:
		return "conclusive: no server_name";
	case REASM_NEED_MORE:
		return "need more bytes";
	case REASM_NOT_TLS:
		return "not a TLS ClientHello";
	case REASM_INVALID:
		return "invalid";
	case REASM_WILL_NOT_RESOLVE:
		return "will not resolve (gap or overflow)";
	default:
		return "?";
	}
}

void reasm_init(struct reasm_flow *f)
{
	memset(f, 0, sizeof *f);
}

bool reasm_was_truncated(const struct reasm_flow *f)
{
	return f->truncated;
}

bool reasm_wants_more(const struct reasm_flow *f, enum reasm_result r)
{
	(void)f;
	switch (r) {
	case REASM_NEED_MORE:
		return true;
	case REASM_FOUND:
	case REASM_ABSOLUTE_NONE:
	case REASM_NOT_TLS:
	case REASM_INVALID:
	case REASM_WILL_NOT_RESOLVE:
		return false;
	default:
		return false;
	}
}

/*
 * Sequence arithmetic. TCP sequence numbers wrap at 2^32, so a plain `<`
 * comparison breaks across the wrap -- a flow that happens to start near 2^32
 * would look like an enormous backwards jump. Subtracting as unsigned gives the
 * distance modulo 2^32, which is correct for any gap smaller than 2^31. That is
 * the standard idiom and it is used here deliberately rather than assumed.
 */
static int32_t seq_diff(uint32_t a, uint32_t b)
{
	return (int32_t)(a - b);
}

static enum reasm_result try_parse(struct reasm_flow *f, char *out,
                                   size_t out_len)
{
	size_t need = 0;
	enum sni_result r;

	if (f->len == 0)
		return REASM_NEED_MORE;

	r = sni_extract(f->buf, f->len, out, out_len, &need);

	switch (r) {
	case SNI_FOUND:
		return REASM_FOUND;
	case SNI_NONE:
		/* A complete ClientHello with no server_name. Definitive. */
		return REASM_ABSOLUTE_NONE;
	case SNI_NOT_TLS:
		/*
		 * Distinguish "this is not TLS at all" from "we have the first
		 * byte of a TLS handshake but nothing else yet". A single 0x16
		 * is not enough to conclude anything, and concluding NOT_TLS
		 * there would stop us buffering a ClientHello that is arriving
		 * one byte at a time.
		 */
		if (f->len < 5)
			return REASM_NEED_MORE;
		if (f->buf[0] != 0x16)
			return REASM_NOT_TLS;
		/* It is a handshake record but not a ClientHello yet, or a
		 * later handshake message: nothing more to wait for. */
		return REASM_NOT_TLS;
	case SNI_INCOMPLETE:
		/*
		 * The stream is structurally fine but short. If we are truncated
		 * we cannot complete it, and saying NEED_MORE would pin the flow
		 * forever. If a gap was seen, the missing bytes may never come --
		 * but they may, so keep waiting while under the segment budget.
		 */
		if (f->truncated)
			return REASM_WILL_NOT_RESOLVE;
		return REASM_NEED_MORE;
	case SNI_MALFORMED:
		/*
		 * Structurally broken. Three cases that look alike and need
		 * different answers:
		 *
		 *   - A KNOWN HOLE may still fill. The hole bytes are zeros, so a
		 *     hole over the name reads as a name of NULs and the parser
		 *     calls it malformed. That verdict is about OUR buffer, not
		 *     the traffic, so it must not be terminal while the hole can
		 *     still be filled -- this is the ordinary out-of-order case,
		 *     and calling it invalid would drop a ClientHello that is
		 *     about to resolve.
		 *
		 *   - The same hole, once the segment budget is spent, is a gap
		 *     that is not going to fill. That is WILL_NOT_RESOLVE, not
		 *     INVALID: the bytes were fine, we simply never saw them. The
		 *     caller's action differs -- evict the flow rather than
		 *     distrust the traffic.
		 *
		 *   - No hole at all means the bytes really are broken, or we
		 *     joined mid-stream so buf[0] is the middle of a record and no
		 *     later data fixes the front. INVALID.
		 */
		if (f->truncated)
			return REASM_WILL_NOT_RESOLVE;
		if (f->saw_gap) {
			if (f->segs < REASM_MAX_SEGS)
				return REASM_NEED_MORE;
			return REASM_WILL_NOT_RESOLVE;
		}
		if (f->len < 6)
			return REASM_NEED_MORE; /* cannot even see a header yet */
		return REASM_INVALID;
	default:
		return REASM_INVALID;
	}
}

enum reasm_result reasm_feed(struct reasm_flow *f, uint32_t seq,
                             const uint8_t *data, size_t len, char *out,
                             size_t out_len)
{
	size_t off;
	int32_t d;

	if (out_len == 0)
		return REASM_INVALID;
	if (!out)
		return REASM_INVALID;
	out[0] = '\0';

	if (!f->started) {
		f->started = true;
		f->start_seq = seq;
		f->next_seq = seq;
	}

	/* Where does this segment sit relative to what we have? */
	d = seq_diff(seq, f->start_seq);

	if (d < 0) {
		/*
		 * The segment starts BEFORE our window. This is the ordinary
		 * out-of-order case -- the tail arrived first, so the window was
		 * anchored too far forward -- and it must be handled by sliding
		 * the window back, not by discarding the bytes.
		 *
		 * AN EARLIER VERSION GOT THIS WRONG: it treated "before the
		 * window" as "already seen", skipped the whole segment, and then
		 * parsed a mid-stream buffer. Every out-of-order split came out
		 * NOT_TLS -- a silently dead filter, which is precisely the
		 * failure this whole file exists to prevent. The test that caught
		 * it is test_out_of_order, which fails on the naive
		 * append-everything implementation too.
		 *
		 * Keeping the earlier bytes is only possible if they fit: the
		 * window is bounded on purpose, so a jump further back than the
		 * cap is unparseable rather than an invitation to grow.
		 */
		size_t back = (size_t)(-(int64_t)d);

		if (back >= REASM_CAP || f->len + back > REASM_CAP) {
			/* Cannot slide far enough without losing what we have. */
			f->truncated = true;
			f->saw_gap = true;
			return REASM_WILL_NOT_RESOLVE;
		}
		memmove(f->buf + back, f->buf, f->len);
		memset(f->buf, 0, back);
		f->len += back;
		f->start_seq -= (uint32_t)back; /* wraps correctly, unsigned */
		d = 0;
	}

	off = (size_t)d;
	if (off >= REASM_CAP) {
		/*
		 * Beyond the window. Bounded on purpose: an attacker choosing our
		 * footprint is how a filter becomes a DoS target. Reported as
		 * truncation rather than silently ignored, because "our window was
		 * too small for this traffic" is a capacity fact an operator needs
		 * to see.
		 */
		f->truncated = true;
		f->saw_gap = true;
		f->segs++;
		return REASM_WILL_NOT_RESOLVE;
	}

	if (off > f->len) {
		/*
		 * A hole before this segment. Record it: if it never fills, this
		 * flow will never resolve and must not be buffered forever.
		 * Still place the bytes -- the hole may fill in later.
		 */
		f->saw_gap = true;
	}

	{
		size_t copy = len;
		size_t copied = 0;

		if (off + copy > REASM_CAP) {
			copy = REASM_CAP - off; /* drop the tail, explicitly */
			f->truncated = true;
		}
		if (copy > 0) {
			memcpy(f->buf + off, data, copy);
			copied = copy;
			if (off + copy > f->len) {
				/*
				 * Zero-fill any hole so the buffer is contiguous
				 * for the parser. A hole is a gap, not a wall of
				 * zeros, and the parse of it will fail -- which is
				 * why saw_gap is recorded separately and the
				 * result is WILL_NOT_RESOLVE rather than INVALID.
				 */
				if (off > f->len)
					memset(f->buf + f->len, 0,
					       off - f->len);
				f->len = off + copy;
			}
		}

		{
			enum reasm_result r = try_parse(f, out, out_len);

			/*
			 * Count only segments that actually contributed bytes
			 * to the window: a retransmission is not progress, so
			 * counting it would let a peer hold a flow open by
			 * resending the same segment. Retransmits return the
			 * parse result unchanged.
			 */
			if (copied)
				f->segs++;

			/*
			 * A gap that the parser cannot resolve becomes
			 * WILL_NOT_RESOLVE rather than NEED_MORE, but only
			 * once the segment budget is spent. Reporting terminal
			 * too early would drop flows that would have resolved;
			 * never reporting it means a flow that never resolves
			 * is buffered forever, which an attacker drives with
			 * one hole per connection.
			 */
			if (r == REASM_NEED_MORE &&
			    (f->saw_gap || f->truncated) &&
			    f->segs >= REASM_MAX_SEGS)
				return REASM_WILL_NOT_RESOLVE;
			return r;
		}
	}
}
