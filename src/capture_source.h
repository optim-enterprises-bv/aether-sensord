/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * The netgraph-backed flow source for the daemon's local pass.
 *
 * Declared unconditionally, implemented per platform: on FreeBSD it drives
 * ng_sni; elsewhere it reports an ERROR rather than "no traffic", because a
 * build that cannot capture must not be indistinguishable from one that
 * captured nothing.
 */

#ifndef AETHER_SENSORD_CAPTURE_SOURCE_H
#define AETHER_SENSORD_CAPTURE_SOURCE_H

#include "daemon_pf.h"

#include <stdbool.h>

struct capture_source;

/*
 * Attach to `ifname` and start capturing.
 *
 * Returns NULL when the interface could not be captured, INCLUDING on a
 * platform with no capture implementation. A caller that treats NULL as
 * "capture off" will therefore also treat "capture broken" as off -- which is
 * why the daemon records capture_enforce separately and why the canary reads
 * capture_source_is_healthy rather than inferring health from flow counts.
 *
 * NEVER pass the interface carrying the management session. The attach
 * temporarily takes the interface out of the kernel's path; a failure between
 * detach and reattach takes the session with it.
 */
struct capture_source *capture_source_open(const char *ifname);

void capture_source_close(struct capture_source *cs);

/* Is the interface still passing traffic? False when unusable. */
bool capture_source_is_healthy(const struct capture_source *cs);

/* The dpf_flow_source_fn. See dpf_flow_source_fn for the return contract. */
int capture_source_drain(void *user, struct dpf_local_flow *out, size_t cap);

#endif /* AETHER_SENSORD_CAPTURE_SOURCE_H */
