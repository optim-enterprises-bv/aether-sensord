/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * TLS SNI extraction. See sni.h for why this exists and what it deliberately
 * does not do.
 *
 * THE DISCIPLINE IN THIS FILE: every field length is validated against the
 * remaining buffer BEFORE it is used to advance, and no length is ever assumed
 * self-consistent. The input is attacker-controlled -- it is whatever arrived on
 * the wire -- so "the length field says 5000 but 40 bytes remain" is a case that
 * must be rejected, not trusted. A read past the end here would be a remotely
 * triggerable crash in a process that holds firewall state.
 *
 * The walk is a sequence of explicit bounds checks rather than pointer
 * arithmetic, because it is read far more often than it is written.
 */

#include "sni.h"

#include <string.h>

enum {
	TLS_RECORD_HANDSHAKE = 0x16,
	TLS_HANDSHAKE_CLIENT_HELLO = 0x01,
	TLS_EXT_SERVER_NAME = 0x0000,
	TLS_SNI_HOST_NAME = 0x00,
	ETHERTYPE_IPV4 = 0x0800,
	ETHERTYPE_VLAN = 0x8100,
	ETHERTYPE_QINQ = 0x88a8,
	IPPROTO_TCP = 6
};

const char *sni_result_str(enum sni_result r)
{
	switch (r) {
	case SNI_FOUND:
		return "found";
	case SNI_NONE:
		return "no server_name in the ClientHello";
	case SNI_INCOMPLETE:
		return "incomplete (needs more bytes)";
	case SNI_NOT_TLS:
		return "not a TLS handshake";
	case SNI_MALFORMED:
		return "malformed";
	default:
		return "?";
	}
}

bool sni_result_is_conclusive(enum sni_result r)
{
	/* Only these two mean "we looked and there is genuinely no hostname".
	 * INCOMPLETE and MALFORMED mean we do not know, which is a different
	 * statement and must not be logged as the first. */
	return r == SNI_NONE || r == SNI_NOT_TLS;
}

static uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t rd24(const uint8_t *p)
{
	return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

/*
 * Read a 16-bit length at `p` and check that that many bytes are present after
 * it. Returns the length, or -1 if the field is not fully present.
 *
 * Every length in TLS is a 16-bit big-endian value followed by its contents, so
 * this one helper covers the whole parse -- which is why the checks are
 * consistent instead of hand-rolled per field.
 */
static long take16(const uint8_t *base, size_t len, size_t off, size_t *advance)
{
	uint16_t v;

	if (off + 2 > len)
		return -1;
	v = rd16(base + off);
	if (off + 2 + (size_t)v > len)
		return -1;
	*advance = (size_t)v;
	return (long)v;
}

/* Copy a wire hostname out, refusing anything that cannot be a DNS name. */
static int emit_name(const uint8_t *name, size_t name_len, char *out,
                     size_t out_len)
{
	size_t n;
	int dots = 0;

	if (name_len == 0)
		return -1;
	if (name_len >= out_len)
		return -1; /* would truncate: a truncated name is a WRONG name */
	if (name_len >= SNI_MAX_NAME)
		return -1;

	/*
	 * Validate the characters. This is not cosmetic: the value becomes a
	 * lookup key and appears in logs, so allowing arbitrary bytes here is
	 * how a log line gets forged or a match gets confused. Lowercase
	 * letters, digits, '.', '-' and '_' cover real names; anything else is
	 * refused rather than passed through.
	 */
	for (n = 0; n < name_len; n++) {
		uint8_t c = name[n];
		if (c == '.')
			dots++;
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'))
			return -1;
	}
	if (dots == 0 && name_len < 4)
		return -1; /* a single label this short is not a server name */

	memcpy(out, name, name_len);
	out[name_len] = '\0';

	/* Strip a trailing root dot, which is legal on the wire and would make
	 * the name never match a pattern that lacks it. */
	if (name_len > 1 && out[name_len - 1] == '.')
		out[name_len - 1] = '\0';
	return 0;
}

enum sni_result sni_extract(const uint8_t *data, size_t len, char *out,
                            size_t out_len, size_t *need)
{
	size_t off;
	size_t rec_len, hs_len, body_len;
	const uint8_t *p;
	size_t body_off, body_end;
	size_t sid_len, cs_len, comp_len;
	long ext_total;

	if (need)
		*need = 0;
	if (!data || !out || out_len == 0)
		return SNI_MALFORMED;
	out[0] = '\0';

	/* --- handshake record header (5 bytes) --- */
	if (len < 5)
		goto incomplete;
	if (data[0] != TLS_RECORD_HANDSHAKE)
		return SNI_NOT_TLS;

	rec_len = rd16(data + 3);
	/* The record body must be fully present before we parse it. A record
	 * header claiming more than we have is truncation, not corruption --
	 * TCP will deliver the rest. */
	if (5 + rec_len > len) {
		if (need)
			*need = 5 + rec_len;
		return SNI_INCOMPLETE;
	}

	/* --- handshake header (4 bytes) inside the record --- */
	if (rec_len < 4)
		return SNI_MALFORMED;
	if (data[5] != TLS_HANDSHAKE_CLIENT_HELLO)
		return SNI_NOT_TLS; /* ServerHello etc.: nothing to extract */

	hs_len = rd24(data + 6);
	if (hs_len < 34 || hs_len > rec_len - 4)
		return SNI_MALFORMED;
	if (4 + hs_len > rec_len) {
		if (need)
			*need = 5 + 4 + hs_len;
		return SNI_INCOMPLETE;
	}

	/* Body starts after record(5) + handshake(4). */
	body_off = 9;
	body_end = body_off + hs_len;
	off = body_off;

	/* legacy_version(2) + random(32) = 34 fixed bytes */
	if (off + 34 > body_end)
		return SNI_MALFORMED;
	off += 34;

	/* legacy_session_id<0..32> */
	if (off + 1 > body_end)
		return SNI_MALFORMED;
	sid_len = data[off];
	off += 1;
	if (off + sid_len > body_end)
		return SNI_MALFORMED;
	off += sid_len;

	/* cipher_suites<2..2^16-2> */
	{
		size_t adv;
		long v = take16(data, body_end, off, &adv);
		if (v < 0)
			return SNI_MALFORMED;
		cs_len = (size_t)v;
		if (cs_len < 2 || (cs_len % 2) != 0)
			return SNI_MALFORMED; /* suites are 2 bytes each */
		off += 2 + cs_len;
	}

	/* legacy_compression_methods<1..2^8-1> */
	if (off + 1 > body_end)
		return SNI_MALFORMED;
	comp_len = data[off];
	off += 1;
	if (comp_len < 1 || off + comp_len > body_end)
		return SNI_MALFORMED;
	off += comp_len;

	/* extensions<0..2^16-1> -- may be absent entirely (TLS 1.2 and older
	 * with no extensions), in which case there is no SNI. */
	if (off == body_end)
		return SNI_NONE;
	if (off + 2 > body_end)
		return SNI_MALFORMED;

	ext_total = take16(data, body_end, off, &(size_t){0});
	if (ext_total < 0)
		return SNI_MALFORMED;
	off += 2;
	{
		size_t ext_end = off + (size_t)ext_total;
		if (ext_end > body_end)
			return SNI_MALFORMED;

		/* --- walk the extensions --- */
		while (off + 4 <= ext_end) {
			uint16_t ext_type = rd16(data + off);
			uint16_t ext_len = rd16(data + off + 2);
			size_t ext_data_off = off + 4;
			size_t ext_data_end = ext_data_off + ext_len;

			if (ext_data_end > ext_end)
				return SNI_MALFORMED;

			if (ext_type != TLS_EXT_SERVER_NAME) {
				off = ext_data_end;
				continue;
			}

			/* server_name extension: ServerNameList<1..2^16-1> */
			{
				size_t sl_off = ext_data_off;
				size_t sl_end = ext_data_end;

				if (sl_off + 2 > sl_end)
					return SNI_MALFORMED;
				{
					uint16_t list_len = rd16(data + sl_off);
					size_t entry = sl_off + 2;

					if (entry + list_len > sl_end)
						return SNI_MALFORMED;

					/* entries are (name_type, HostName<1..2^16-1>) */
					while (entry + 3 <= sl_off + 2 + list_len) {
						uint8_t ntype = data[entry];
						uint16_t nlen = rd16(data + entry + 1);
						size_t name_off = entry + 3;

						if (name_off + nlen > sl_off + 2 + list_len)
							return SNI_MALFORMED;
						if (ntype != TLS_SNI_HOST_NAME) {
							/* Not a hostname (e.g. a
							 * future type): skip it and
							 * keep looking, rather than
							 * failing the whole parse. */
							entry = name_off + nlen;
							continue;
						}
						if (emit_name(data + name_off, nlen, out,
						              out_len) != 0)
							return SNI_MALFORMED;
						return SNI_FOUND;
					}
				}
			}
			off = ext_data_end;
		}
	}

	/* A complete, parsed ClientHello with no server_name extension: a real
	 * and legal outcome, not a failure. */
	return SNI_NONE;

incomplete:
	/*
	 * We could not even see the record header. Report a minimal need so the
	 * caller asks for more rather than concluding anything.
	 */
	if (need)
		*need = 5;
	return SNI_INCOMPLETE;

	(void)p;
	(void)body_len;
}

enum sni_result sni_frame_tuple(const uint8_t *frame, size_t len,
                                struct sni_tuple *out)
{
	size_t off = 0;
	uint16_t ethertype;
	size_t ihl, ip_hdr, l4;
	uint32_t ip_total;
	uint8_t proto;

	if (!out)
		return SNI_MALFORMED;
	memset(out, 0, sizeof *out);

	if (!frame || len < 14)
		return SNI_INCOMPLETE;

	/* the source MAC is readable as soon as the Ethernet header is */
	memcpy(out->smac, frame + 6, 6);
	out->have_smac = true;

	ethertype = (uint16_t)((frame[12] << 8) | frame[13]);
	while (ethertype == 0x8100 || ethertype == 0x88a8) {
		if (len < off + 18)
			return SNI_INCOMPLETE;
		off += 4;
		ethertype = (uint16_t)((frame[off + 12] << 8) |
		                       frame[off + 13]);
	}
	if (ethertype != 0x0800)
		return SNI_NOT_TLS; /* not IPv4: no tuple this layer uses */

	if (len < off + 14 + 20)
		return SNI_INCOMPLETE;

	{
		const uint8_t *ip = frame + off + 14;
		ihl = (size_t)(ip[0] & 0x0f) * 4;
		ip_total = ((uint32_t)ip[2] << 8) | ip[3];
		proto = ip[9];
		ip_hdr = off + 14;

		/*
		 * Reject fragments below the first. A non-first fragment has no
		 * transport header, so reading ports out of it would produce a
		 * plausible-looking tuple from the middle of a payload.
		 */
		{
			uint16_t flags_frag =
			    (uint16_t)((ip[6] << 8) | ip[7]);
			if ((flags_frag & 0x1fff) != 0)
				return SNI_INCOMPLETE;
		}

		if (ihl < 20 || len < ip_hdr + ihl)
			return SNI_MALFORMED;
		if (ip_total < ihl)
			return SNI_MALFORMED;

		memcpy(out->saddr, ip + 12, 4);
		memcpy(out->daddr, ip + 16, 4);
		out->family = 4;
		out->proto = proto;

		l4 = ip_hdr + ihl;
		if (proto == 6 || proto == 17) {
			if (len < l4 + 4)
				return SNI_INCOMPLETE;
			out->sport = (uint16_t)((frame[l4] << 8) |
			                        frame[l4 + 1]);
			out->dport = (uint16_t)((frame[l4 + 2] << 8) |
			                        frame[l4 + 3]);
			/*
			 * TCP with a data offset below the minimum is
			 * malformed; report it rather than returning a tuple
			 * whose header length the caller would trust.
			 */
			if (proto == 6) {
				size_t doff;

				if (len < l4 + 13)
					return SNI_INCOMPLETE;
				doff = (size_t)(frame[l4 + 12] >> 4) * 4;
				if (doff < 20)
					return SNI_MALFORMED;
			}
		}
	}

	return SNI_FOUND;
}

bool sni_frame_src_mac(const uint8_t *frame, size_t len, uint8_t out[6])
{
	size_t off = 0;
	uint16_t ethertype;

	if (!frame || !out)
		return false;
	/*
	 * Need at least a full Ethernet header to read the source address. A
	 * shorter frame is a truncated capture, not a MAC-less client, so it is
	 * refused rather than zero-filled: a zero MAC would compare equal to the
	 * zero MAC the policy layer uses for "no subject", which would silently
	 * turn a truncated frame into a subject lookup.
	 */
	if (len < 14)
		return false;

	memcpy(out, frame + 6, 6);

	ethertype = (uint16_t)((frame[12] << 8) | frame[13]);
	/* Walk 802.1Q VLAN tags exactly as the frame parser does. */
	while (ethertype == 0x8100 || ethertype == 0x88a8) {
		if (len < off + 18)
			return false;
		off += 4;
		ethertype = (uint16_t)((frame[off + 12] << 8) |
		                       frame[off + 13]);
	}
	/*
	 * Only IPv4 is accepted. A frame that is not IPv4 is not a failure to
	 * read a MAC -- the MAC was read fine -- but the caller asks "which
	 * client is this flow from", and for a non-IPv4 frame the flow is not
	 * one this policy layer can evaluate. Returning the MAC would invite the
	 * caller to treat it as a subject.
	 */
	if (ethertype != 0x0800)
		return false;

	return true;
}

enum sni_result sni_extract_frame(const uint8_t *frame, size_t len, char *out,
                                  size_t out_len, size_t *need,
                                  const uint8_t **tcp_payload,
                                  size_t *tcp_payload_len,
                                  uint32_t *tcp_seq)
{
	size_t off = 0;
	uint16_t ethertype;
	size_t ihl;
	size_t i;
	uint32_t ip_total;
	size_t ip_hdr;
	uint32_t frag;
	size_t tcp_off;
	size_t tcp_hdr;
	size_t payload_off;

	if (tcp_payload)
		*tcp_payload = NULL;
	if (tcp_payload_len)
		*tcp_payload_len = 0;
	if (tcp_seq)
		*tcp_seq = 0;
	if (need)
		*need = 0;
	if (!frame || len < 14)
		return SNI_NOT_TLS;

	/* --- Ethernet --- */
	ethertype = rd16(frame + 12);
	off = 14;

	/* 802.1Q / QinQ VLAN tags, which a trunk port will present. */
	for (i = 0; i < 2 && (ethertype == ETHERTYPE_VLAN ||
	                      ethertype == ETHERTYPE_QINQ); i++) {
		if (off + 4 > len)
			return SNI_NOT_TLS;
		ethertype = rd16(frame + off + 2);
		off += 4;
	}
	if (ethertype != ETHERTYPE_IPV4)
		return SNI_NOT_TLS; /* IPv6 and non-IP: not handled, see sni.h */

	/* --- IPv4 --- */
	if (off + 20 > len)
		return SNI_NOT_TLS;
	if ((frame[off] >> 4) != 4)
		return SNI_NOT_TLS;
	ihl = (size_t)(frame[off] & 0x0f) * 4;
	if (ihl < 20 || off + ihl > len)
		return SNI_MALFORMED;
	ip_total = rd16(frame + off + 2);
	if (ip_total < ihl)
		return SNI_MALFORMED;
	if (frame[off + 9] != IPPROTO_TCP)
		return SNI_NOT_TLS;

	/*
	 * Fragments. A non-first fragment has no TCP header, and a first
	 * fragment has a truncated payload. Either way we cannot parse, and
	 * saying NOT_TLS is the honest answer -- but the caller must not read
	 * that as "no hostname", which is why this is worth distinguishing in
	 * the coverage counters rather than silently folding in.
	 */
	frag = ((uint32_t)rd16(frame + off + 6) << 3) |
	       (frame[off + 7] & 0x07);
	if ((frag & 0x1fff) != 0)
		return SNI_NOT_TLS;

	ip_hdr = off;
	tcp_off = off + ihl;
	if (tcp_off + 20 > len)
		return SNI_INCOMPLETE;

	/* --- TCP --- */
	tcp_hdr = (size_t)(frame[tcp_off + 12] >> 4) * 4;
	if (tcp_hdr < 20 || tcp_off + tcp_hdr > len)
		return SNI_MALFORMED;

	payload_off = tcp_off + tcp_hdr;

	/*
	 * The sequence number of the FIRST PAYLOAD byte. TCP's header sequence
	 * counts SYN and FIN as occupying one sequence number each, so a SYN or
	 * FIN segment's payload begins at seq+1. Getting this wrong shifts
	 * every segment by one and breaks reassembly in a way that only shows
	 * up on the first data segment -- which is exactly the segment carrying
	 * a ClientHello's header.
	 */
	{
		uint32_t seq = ((uint32_t)frame[tcp_off + 4] << 24) |
		               ((uint32_t)frame[tcp_off + 5] << 16) |
		               ((uint32_t)frame[tcp_off + 6] << 8) |
		               (uint32_t)frame[tcp_off + 7];
		uint8_t flags = frame[tcp_off + 13];

		if (flags & 0x02) /* SYN */
			seq += 1;
		if (tcp_seq)
			*tcp_seq = seq;
	}

	/*
	 * Clamp the payload to the IP total length when it is sane. Ethernet
	 * pads short frames, so trusting the frame length alone would hand
	 * trailing zero padding to the TLS parser -- which then reports
	 * MALFORMED on a perfectly good packet.
	 */
	{
		size_t ip_end = ip_hdr + ip_total;

		if (ip_end < len && ip_end > payload_off)
			len = ip_end;
		if (payload_off > len)
			return SNI_NOT_TLS;
	}

	if (tcp_payload)
		*tcp_payload = frame + payload_off;
	if (tcp_payload_len)
		*tcp_payload_len = len - payload_off;

	if (len - payload_off == 0)
		return SNI_NOT_TLS; /* pure ACK */

	return sni_extract(frame + payload_off, len - payload_off, out, out_len,
	                   need);
}
