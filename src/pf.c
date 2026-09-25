/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * pf (FreeBSD/OPNsense) enforcement rendering. See pf.h for the four ways this
 * differs from the nftables renderer and why each is not cosmetic.
 *
 * Portability note: this compiles on both FreeBSD and Linux. The only
 * Linux-flavoured include is that the original used `-D_GNU_SOURCE`; here
 * everything needed (`inet_pton`, `inet_ntop`, `snprintf`) is POSIX, so the
 * file builds under `-std=c11` on either. `strdup` is deliberately not used.
 */

#include "pf.h"

/*
 * `<sys/socket.h>` before `<arpa/inet.h>`: glibc's arpa/inet.h happens to pull
 * in the AF_* constants, FreeBSD's does not, so omitting it builds on Linux and
 * fails on the actual target. Found by building on FreeBSD 16.0.
 */
#include <sys/socket.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *pf_reject_str(enum pf_reject r)
{
	switch (r) {
	case PF_OK:
		return "ok";
	case PF_REJECT_MALFORMED:
		return "malformed";
	case PF_REJECT_PREFIX:
		return "prefix_out_of_range";
	case PF_REJECT_TOO_BROAD:
		return "too_broad";
	case PF_REJECT_HOSTBITS:
		return "host_bits_set";
	case PF_REJECT_UNSAFE_CHARS:
		return "unsafe_characters";
	case PF_REJECT_TIMEOUT_UNSUPPORTED:
		return "per_element_timeout_unsupported";
	default:
		return "unknown";
	}
}

/*
 * Only characters that can appear in an IPv4/IPv6 address or prefix. Anything
 * else -- a space, a semicolon, a quote, a backtick -- is refused here rather
 * than left for inet_pton to reject incidentally.
 *
 * This matters more on pf than on nftables: the element ends up as its own
 * argv entry to pfctl, and an argument is still only safe if it cannot be
 * mistaken for an option or for a second argument.
 */
static bool safe_chars(const char *s, size_t *len_out)
{
	size_t n = 0;
	for (const char *p = s; *p; p++, n++) {
		if (n > PF_ELEM_TEXT_MAX)
			return false;
		char c = *p;
		/* No leading '-' can pass: '-' is not in the alphabet at all, so
		 * an element can never be read as a pfctl flag. */
		bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
		          (c >= 'A' && c <= 'F') || c == '.' || c == ':' || c == '/';
		if (!ok)
			return false;
	}
	*len_out = n;
	return n > 0;
}

/* Are any bits set below `prefix`? A feed entry like 10.1.2.3/8 is ambiguous:
 * it may mean the host or the network. Refusing beats guessing, because the two
 * readings differ by 16.7 million addresses. */
static bool has_host_bits(const uint8_t *addr, uint8_t bytes, uint8_t prefix)
{
	for (uint8_t i = 0; i < bytes; i++) {
		uint8_t keep;
		if (prefix >= (uint8_t)((i + 1) * 8))
			keep = 0xFF;
		else if (prefix <= (uint8_t)(i * 8))
			keep = 0x00;
		else
			keep = (uint8_t)(0xFF << (8 - (prefix - (uint8_t)(i * 8))));
		if (addr[i] & (uint8_t)~keep)
			return true;
	}
	return false;
}

enum pf_reject pf_elem_parse(const char *text, uint32_t timeout_sec,
                             struct pf_elem *out)
{
	if (!text || !out)
		return PF_REJECT_MALFORMED;

	size_t len = 0;
	if (!safe_chars(text, &len))
		return PF_REJECT_UNSAFE_CHARS;

	char buf[PF_ELEM_TEXT_MAX + 1];
	memcpy(buf, text, len);
	buf[len] = '\0';

	char *slash = strchr(buf, '/');
	long prefix = -1;
	if (slash) {
		*slash = '\0';
		char *endp = NULL;
		prefix = strtol(slash + 1, &endp, 10);
		if (!endp || *endp != '\0' || prefix < 0)
			return PF_REJECT_MALFORMED;
	}

	memset(out, 0, sizeof(*out));
	out->timeout_sec = timeout_sec;

	if (inet_pton(AF_INET, buf, out->addr) == 1) {
		out->family = 4;
		out->prefix = (uint8_t)(slash ? prefix : 32);
		if (out->prefix > 32)
			return PF_REJECT_PREFIX;
		if (out->prefix < PF_MIN_PREFIX_V4)
			return PF_REJECT_TOO_BROAD;
		if (has_host_bits(out->addr, 4, out->prefix))
			return PF_REJECT_HOSTBITS;
		return PF_OK;
	}

	if (inet_pton(AF_INET6, buf, out->addr) == 1) {
		out->family = 6;
		out->prefix = (uint8_t)(slash ? prefix : 128);
		if (out->prefix > 128)
			return PF_REJECT_PREFIX;
		if (out->prefix < PF_MIN_PREFIX_V6)
			return PF_REJECT_TOO_BROAD;
		if (has_host_bits(out->addr, 16, out->prefix))
			return PF_REJECT_HOSTBITS;
		return PF_OK;
	}

	return PF_REJECT_MALFORMED;
}

size_t pf_elem_render(const struct pf_elem *e, char *out, size_t out_len)
{
	if (!e || !out || out_len == 0)
		return 0;
	if (e->family != 4 && e->family != 6)
		return 0;

	char addr[INET6_ADDRSTRLEN];
	int af = (e->family == 4) ? AF_INET : AF_INET6;
	if (!inet_ntop(af, e->addr, addr, sizeof(addr)))
		return 0;

	/*
	 * No `timeout` suffix: that is nft set syntax and pfctl rejects it. A
	 * bare address is a host route; a prefixed one goes into an interval
	 * table. Both are plain text that came from inet_ntop over parsed
	 * binary, so no caller byte can reach this output.
	 */
	int n = snprintf(out, out_len, "%s/%u", addr, e->prefix);
	if (n < 0 || (size_t)n >= out_len)
		return 0;
	return (size_t)n;
}

static const char *verb_word(bool add)
{
	return add ? "add" : "delete";
}

size_t pf_render_argv_prefix(const struct pf_target *t, bool is_v6, bool add,
                             const char **argv, size_t argv_len)
{
	if (!t || !argv || argv_len < 5)
		return 0;
	const char *table = is_v6 ? t->table_v6 : t->table_v4;
	if (!table)
		return 0;

	argv[0] = "pfctl";
	argv[1] = "-t";
	argv[2] = table;
	argv[3] = "-T";
	argv[4] = verb_word(add);
	return 5;
}

size_t pf_render_argc(const struct pf_target *t, size_t n)
{
	if (!t || !t->table_v4)
		return 0;
	/* 5 fixed args (pfctl -t <table> -T add) + one per element + NULL. */
	return 5 + n + 1;
}

static size_t render_batch(const struct pf_target *t, bool add,
                           const struct pf_elem *elems, size_t n, char *out,
                           size_t out_len, size_t *n_rendered)
{
	if (n_rendered)
		*n_rendered = 0;
	if (!t || !elems || !out || out_len == 0)
		return 0;
	if (n > PF_BATCH_MAX)
		n = PF_BATCH_MAX;

	size_t used = 0;
	size_t done = 0;

	for (int pass = 0; pass < 2; pass++) {
		uint8_t fam = (pass == 0) ? 4 : 6;
		const char *table = (pass == 0) ? t->table_v4 : t->table_v6;
		if (!table)
			continue;

		size_t count = 0;
		for (size_t i = 0; i < n; i++)
			if (elems[i].family == fam)
				count++;
		if (count == 0)
			continue;

		const char *verb = verb_word(add);
		int w = snprintf(out + used, out_len - used, "pfctl -t %s -T %s",
		                 table, verb);
		if (w < 0 || (size_t)w >= out_len - used)
			return 0;
		used += (size_t)w;

		for (size_t i = 0; i < n; i++) {
			if (elems[i].family != fam)
				continue;

			char text[PF_ELEM_TEXT_MAX];
			if (pf_elem_render(&elems[i], text, sizeof(text)) == 0)
				continue; /* unrenderable: skip, never emit partial */

			w = snprintf(out + used, out_len - used, " %s", text);
			if (w < 0 || (size_t)w >= out_len - used)
				return 0;
			used += (size_t)w;
			done++;
		}

		w = snprintf(out + used, out_len - used, "\n");
		if (w < 0 || (size_t)w >= out_len - used)
			return 0;
		used += (size_t)w;
	}

	if (n_rendered)
		*n_rendered = done;
	return used;
}

size_t pf_render_add(const struct pf_target *t, const struct pf_elem *elems,
                     size_t n, char *out, size_t out_len, size_t *n_rendered)
{
	return render_batch(t, true, elems, n, out, out_len, n_rendered);
}

size_t pf_render_del(const struct pf_target *t, const struct pf_elem *elems,
                     size_t n, char *out, size_t out_len, size_t *n_rendered)
{
	return render_batch(t, false, elems, n, out, out_len, n_rendered);
}

size_t pf_render_table_decl(const struct pf_target *t, uint32_t expire_sec,
                            char *out, size_t out_len)
{
	if (!t || !out || out_len == 0)
		return 0;

	/*
	 * Rendered as a record rather than pf.conf text, because OPNsense does
	 * not read a pf.conf fragment from a plugin: the table has to be
	 * registered as a static alias and OPNsense generates the rules that
	 * reference it. This is the content of that registration.
	 */
	int n = snprintf(
	    out, out_len,
	    "/* register in OPNsense: Firewall > Aliases > static_aliases */\n"
	    "{\n"
	    "  \"%s\": {\n"
	    "    \"enabled\": \"1\",\n"
	    "    \"name\": \"%s\",\n"
	    "    \"type\": \"external\",\n"
	    "    \"description\": \"AIsense reputation feed (aether-sensord)\",\n"
	    "    \"expire\": \"%u\",\n"
	    "    \"content\": \"\"\n"
	    "  }\n"
	    "}\n"
	    "# pf equivalent, for reference only -- OPNsense regenerates pf.conf:\n"
	    "#   table <%s> persist\n",
	    t->table_v4, t->table_v4, expire_sec, t->table_v4);
	if (n < 0 || (size_t)n >= out_len)
		return 0;
	return (size_t)n;
}
