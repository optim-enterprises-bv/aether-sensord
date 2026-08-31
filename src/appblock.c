/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 */

#include "appblock.h"

#include "afpush.h"
#include "match.h"

#include <string.h>

const char *appblock_reason_str(enum appblock_reason r)
{
	switch (r) {
	case ABR_ENFORCED:     return "enforced";
	case ABR_NO_HOST:      return "no server name recovered";
	case ABR_UNKNOWN_APP:  return "hostname matches no signature";
	case ABR_NO_SUBJECT:   return "flow not attributable to a device";
	case ABR_ALLOWED:      return "allowed by policy";
	case ABR_AMBIGUOUS:    return "hostname claimed by several applications";
	case ABR_DNS_PEER:     return "named by a DNS query; the peer is the resolver, not the application";
	default:               return "?";
	}
}

/*
 * Which endpoint is the peer?
 *
 * A block must land on the far side, not on the subscriber's own device. The
 * subject is whichever endpoint is private (the LAN device); the peer is the
 * other one. When neither or both are private this returns false and the
 * caller enforces nothing -- guessing here would block a LAN host.
 */
static bool pick_peer(const struct dpi_result *f, const struct obs_addr **peer)
{
	bool s_priv = obs_addr_is_private(&f->src);
	bool d_priv = obs_addr_is_private(&f->dst);

	if (s_priv && !d_priv) {
		*peer = &f->dst;
		return true;
	}
	if (d_priv && !s_priv) {
		*peer = &f->src;
		return true;
	}
	return false;
}

const char *appblock_reason_wire(enum appblock_reason r)
{
	switch (r) {
	case ABR_ENFORCED:    return "enforced";
	case ABR_NO_HOST:     return "no_host";
	case ABR_UNKNOWN_APP: return "unknown_app";
	case ABR_NO_SUBJECT:  return "no_subject";
	case ABR_ALLOWED:     return "allowed";
	case ABR_AMBIGUOUS:   return "ambiguous";
	case ABR_DNS_PEER:    return "dns_peer";
	default:              return "unknown";
	}
}

struct appblock_decision appblock_decide(const struct dpi_result *flow,
                                         const struct sig_db *sigs,
                                         const struct pol_db *pol,
                                         const uint8_t *subject_mac,
                                         struct pol_time now,
                                         uint32_t used_today_sec,
                                         uint32_t addr_timeout_sec)
{
	struct appblock_decision d;
	struct match_result m;
	struct pol_verdict v;
	const struct obs_addr *peer = NULL;

	memset(&d, 0, sizeof(d));
	d.action = ACT_NONE;

	if (!flow || !sigs || !pol || !flow->classified) {
		d.reason = ABR_NO_HOST;
		return d;
	}
	if (!flow->have_host || flow->host[0] == '\0') {
		/* nDPI knew the protocol but recovered no name. There is
		 * nothing to look up: a protocol is not an application. */
		d.reason = ABR_NO_HOST;
		return d;
	}

	m = match_flow(sigs, flow->host, flow->l4proto, flow->dport);
	if (m.kind == MATCH_NONE || !m.app) {
		d.reason = ABR_UNKNOWN_APP;
		return d;
	}

	/*
	 * Refuse to act on an ambiguous hostname.
	 *
	 * 30 host patterns in the shipped database are claimed by more than one
	 * application, and the matcher picks whichever rule it reached first --
	 * `en.wikipedia.org` resolves to a Malware-class signature among six
	 * claimants. Blocking on an arbitrary winner would enforce a rule the
	 * operator never wrote, so this stops and says why.
	 */
	if (m.ambiguous_apps > 1) {
		snprintf(d.app_tag, sizeof(d.app_tag), "%s", m.app->tag);
		d.reason = ABR_AMBIGUOUS;
		return d;
	}

	snprintf(d.app_tag, sizeof(d.app_tag), "%s", m.app->tag);

	if (!subject_mac) {
		/* Policy is per-device. An unattributed flow cannot be judged
		 * without applying somebody else's rules to it. */
		d.reason = ABR_NO_SUBJECT;
		return d;
	}

	v = pol_evaluate(pol, subject_mac, d.app_tag, NULL, now, used_today_sec);
	if (v.action != POL_BLOCK) {
		/*
		 * pol_evaluate returns ALLOW for BOTH "a rule permits this" and
		 * "this device is not under policy at all". Reporting them the
		 * same way hid a whole class of failure on the BPI-R4: every
		 * flow read as ABR_ALLOWED while no_subject stayed at zero, so
		 * an unmatched subject looked like a deliberate permit.
		 */
		d.reason = (v.reason == POL_REASON_NO_SUBJECT) ? ABR_NO_SUBJECT
		                                               : ABR_ALLOWED;
		return d;
	}

	/* Blocked. Now: where can it actually be enforced? */
	if (flow->scope == DPI_SCOPE_NAME_HASH) {
		d.action = ACT_HASH;
		d.reason = ABR_ENFORCED;
		d.name_hash = afpush_hash_name(flow->host, strlen(flow->host));
		return d;
	}

	/* Address scope: the kernel cannot re-derive this name. */
	if (addr_timeout_sec == 0) {
		/* Refused rather than treated as "no timeout". A permanent
		 * block from a single heuristic classification is not
		 * something this should express by accident. */
		d.reason = ABR_ALLOWED;
		return d;
	}
	/*
	 * Never address-block a DNS transaction.
	 *
	 * A DNS query for a blocked application is correctly named after that
	 * application, but the peer of that flow is the RESOLVER. Blocking it
	 * does not block the app -- it removes name resolution for everything.
	 *
	 * The addresses worth blocking are the ones the reply carries, and they
	 * reach the set through the resolved-address path, not this one.
	 */
	if (flow->l4proto == 17 || flow->l4proto == 6) {
		if (flow->sport == 53 || flow->dport == 53 ||
		    flow->sport == 5353 || flow->dport == 5353 ||
		    flow->sport == 853 || flow->dport == 853) {
			d.reason = ABR_DNS_PEER;
			return d;
		}
	}

	if (!pick_peer(flow, &peer)) {
		d.reason = ABR_NO_SUBJECT;
		return d;
	}

	memset(&d.elem, 0, sizeof(d.elem));
	memcpy(d.elem.addr, peer->bytes, peer->len);
	d.elem.family = (peer->len == 16) ? 6 : 4;
	d.elem.prefix = (peer->len == 16) ? 128 : 32;
	d.elem.timeout_sec = addr_timeout_sec;
	d.action = ACT_ADDR;
	d.reason = ABR_ENFORCED;
	return d;
}
