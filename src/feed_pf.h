/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Everything needed to build the *unmodified* src/feed.c against pf.
 *
 * feed.c is the reputation protocol: serial, delta, gap-triggered resync. It is
 * correctness-critical in a way that is invisible when it breaks -- a gap applied
 * across a hole leaves the device silently diverged from the controller, and both
 * ends believe they agree. So this port does NOT fork it. It substitutes the two
 * datapath-specific pieces through the macros feed.h exposes:
 *
 *   FEED_ELEM_TYPE    struct pf_elem  (addr/family/prefix, same layout)
 *   feed_elem_parse   pf_elem_parse
 *   feed_elem_set_timeout
 *
 * Include this header BEFORE feed.h (or via -include) and feed.c compiles for
 * pf with no source change.
 *
 * ON THE TIMEOUT. pf has no per-element expiry; decay is a table property, which
 * OPNsense exposes as `expire` on a static alias. So the setter admits the
 * element and records `timeout_unrepresentable` rather than refusing it. The
 * alternative -- rejecting every element that carries a timeout, which is all of
 * them -- would leave the firewall enforcing nothing while appearing configured,
 * and would do it silently. The table's `expire` is what actually provides decay
 * on this platform, and the canary reports whether enforcement is real.
 */

#ifndef AETHER_SENSORD_FEED_PF_H
#define AETHER_SENSORD_FEED_PF_H

#include "pf.h"

/*
 * The pf element type carries a uint32 timeout_sec field of its own (for API
 * compatibility with the nftables build and the feed that produces it), so the
 * protocol's element slots are struct pf_elem directly.
 */
#define FEED_ELEM_TYPE struct pf_elem

/*
 * pf rejects anything wider than /16 (v4) or /32 (v6), matching the nftables
 * renderer and the backend allowlist. A feed entry refused here is counted in
 * feed_msg.rejected, so a feed shipping junk is visible rather than presenting
 * as a small update.
 */
#define feed_elem_parse(text, out) (pf_elem_parse((text), 0, (out)) == PF_OK)

/*
 * Carry the default timeout, and record that pf cannot honour it.
 *
 * Returns 0 deliberately: the element IS admitted. See the file comment for why
 * refusing would be the worse failure. `timeout_unrepresentable` is the flag a
 * caller or a log can surface, so the capability gap is stated rather than
 * silently assumed to be working.
 */
static inline int feed_elem_set_timeout(struct pf_elem *e, uint32_t t)
{
	if (!e)
		return -1;
	e->timeout_sec = t;
	e->timeout_unrepresentable = (t > 0);
	return 0;
}

/*
 * Default timeout to attach to feed elements, in seconds.
 *
 * Seven days, the value the OpenWrt daemon uses for the nft set default. On pf
 * this is the number that belongs in the static alias's `expire` field, which is
 * where decay actually happens -- so rendering the alias declaration and the
 * feed must agree, or an operator sees a decay period different from the one in
 * force.
 */
#define FEED_ELEM_TIMEOUT 604800u

#endif /* AETHER_SENSORD_FEED_PF_H */
