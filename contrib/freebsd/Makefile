# Copyright (C) 2026 Optim Enterprises BV
#
# This is free software, licensed under the BSD 3-Clause License.
#
# FreeBSD/OPNsense port of net/aether-sensord.
#
# This is an OPNsense plugin package (`os-` prefix), because the parts that are
# portable are the parts that must integrate with OPNsense's own firewall, and
# an OPNsense plugin is the only shape that gets a GUI, a config.xml model, and
# a ruleset that survives a filter reload.
#
# WHAT PORTS AND WHAT DOES NOT. From the OpenWrt package:
#
#   ports unchanged (pure C, no kernel dependency):
#     src/nft.c semantics  -> src/pf.c    (this package's renderer)
#     src/canary.c logic   -> src/canary_pf.c
#     src/policy.c, src/sigdb.c, src/match.c, aether-appdb data
#
#   ports with a different mechanism:
#     nftables sets        -> pf tables + OPNsense static aliases (see below)
#     NFLOG                -> pflog, or OPNsense's own flow logging
#     /etc/config (UCI)    -> OPNsense MVC model + config.xml
#     procd init           -> rc.subr / rc.d
#
#   does NOT port:
#     kmod-aether-af       a Linux kernel module hashing TLS SNI/HTTP host for
#                          in-kernel matching. FreeBSD has no equivalent hook, so
#                          the name-hash half of enforcement has no datapath
#                          here. Address/tuple enforcement via pf is unaffected.
#     libndpi dissection   linked on OpenWrt for protocol ID. Its value here is
#                          classification, not enforcement, and OPNsense ships
#                          its own flow tooling. Left out of the first cut so the
#                          package has no LGPL dependency it does not yet use.
#
# THE ENFORCEMENT SEAM, AND WHY IT IS NOT AN ANCHOR. OPNsense regenerates its
# whole pf ruleset from config.xml on every filter reload, and measured on
# 26.7.2_2 the generated ruleset contains ZERO `anchor` lines. A plugin that
# loads rules into an anchor therefore installs a DORMANT configuration: the
# anchor exists, `pfctl -a <name> -s rules` prints your rules, and nothing is
# ever evaluated. That is the same silent-degradation shape as the nftables
# failure this daemon was built to catch (sets existed, daemon logged
# "enforcement is live", no rule referenced them).
#
# So the table is registered as an OPNsense STATIC ALIAS of type `external`:
#
#   /usr/local/opnsense/mvc/app/models/OPNsense/Firewall/static_aliases/core.json
#
# OPNsense then GENERATES the rule that references it (precedent: `sshlockout`
# is referenced 4 times in the generated ruleset, `virusprot` 3 times), and
# `expire` gives kernel-side decay so a feed that stops refreshing stops
# blocking instead of leaving a stale table enforcing forever.
#
# THE CANARY IS THE POINT. src/canary_pf.c exists because configuration state is
# not enforcement. It puts a documentation-space address (192.0.2.199) into the
# live table, then checks whether the MAIN ruleset references that table --
# deliberately NOT the per-table `Rules:` count from `pfctl -vvsT`, which counts
# rules inside unreferenced anchors. Measured state where that count lies:
#
#     References:  [ Anchors: 1   Rules: 1  ]     <- looks enforced
#     pfctl -s rules | grep -c '<aisense_rep4>' -> 0
#
# Verdicts: enforced / set_missing / add_rejected / not_held / not_enforced /
# cleanup_failed / inconclusive. `not_enforced` is the one this exists to catch.
# Exit status is non-zero for everything except `enforced`, so a monitor cannot
# be fooled by "could not check".

PORTNAME=	aether-sensord
DISTVERSIONPREFIX=	v
DISTVERSION=	0.1.0
CATEGORIES=	security net
COMMENT=	Aether reputation enforcement for OPNsense (pf), with proof of enforcement

# BSD-3-Clause for this port's new sources; the daemon it derives from is
# BUSL-1.1 (source-available, production use granted for use with the Aether
# platform). The BUSL text applies to the derived work as a whole -- this port
# adds files but does not relicense the original.
LICENSE=	BUSL-1.1
LICENSE_FILE=	${WRKSRC}/LICENSE

USES=		compiler:c11

# The sources are in the port's own files/ tree rather than fetched: the port
# adds pf-specific files that do not exist upstream, and pinning a moving
# upstream commit would change what a given port revision contains. When this
# lands in the optim-wrt feed the same source lives at net/aether-sensord.
NO_WRKSUBDIR=	yes
PLIST_FILES=	sbin/aether-sensord-pfcanary \
		share/doc/aether-sensord/README.pf

OPTIONS_DEFINE=	DOCS

do-build:
	${CC} ${CFLAGS} -std=c11 -Wall -Wextra -Werror \
		-o ${WRKDIR}/aether-sensord-pfcanary \
		${WRKSRC}/src/canary_pf_main.c ${WRKSRC}/src/canary_pf.c
	${CC} ${CFLAGS} -std=c11 -Wall -Wextra -Werror -c \
		-o ${WRKDIR}/pf.o ${WRKSRC}/src/pf.c
	${CC} ${CFLAGS} -std=c11 -Wall -Wextra -Werror -c \
		-o ${WRKDIR}/canary_pf.o ${WRKSRC}/src/canary_pf.c

do-install:
	${INSTALL_PROGRAM} ${WRKDIR}/aether-sensord-pfcanary \
		${STAGEDIR}${PREFIX}/sbin/aether-sensord-pfcanary
	${MKDIR} ${STAGEDIR}${PREFIX}/share/doc/aether-sensord
	${INSTALL_DATA} ${WRKSRC}/README.pf \
		${STAGEDIR}${PREFIX}/share/doc/aether-sensord/README.pf

do-test:
	${CC} ${CFLAGS} -std=c11 -Wall -Wextra -Werror \
		-o ${WRKDIR}/test_pf ${WRKSRC}/test/test_pf.c ${WRKSRC}/src/pf.c
	${WRKDIR}/test_pf
	${CC} ${CFLAGS} -std=c11 -Wall -Wextra -Werror \
		-o ${WRKDIR}/test_canary_pf \
		${WRKSRC}/test/test_canary_pf.c ${WRKSRC}/src/canary_pf.c
	${WRKDIR}/test_canary_pf

.include <bsd.port.mk>
