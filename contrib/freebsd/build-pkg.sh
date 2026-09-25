#!/bin/sh
# Copyright (C) 2026 Optim Enterprises BV
#
# This is free software, licensed under the BSD 3-Clause License.
#
# Build a FreeBSD/OPNsense .pkg for the pf port, reproducibly, without a ports
# tree. Verified on FreeBSD 16.0-CURRENT / pkg 2.8.4.
#
# WHY NOT `pkg create -m`: -m expects a metadata DIRECTORY in a specific layout
# and aborts (core-dumps) if a field is absent.
#
# WHY NOT `pkg create -M` WITH THE MANIFEST ALONE: -M takes the manifest
# VERBATIM and packs NO payload. Measured: a 473-byte package containing only
# +MANIFEST and +COMPACT_MANIFEST, reporting `Flat size: 0.00B`. The fix is to
# include an explicit `files:` map -- pkg then packs the listed paths and fills
# in their checksums itself.
#
# WHY `pkg add` NOT `pkg install`: `pkg install <file>` insists on updating
# remote repositories first and fails on an air-gapped or DNS-limited host.
# `pkg add` installs a local package directly.
#
# Usage: ./build-pkg.sh [srcdir] [outdir]
set -e

SRCDIR=${1:-$(cd "$(dirname "$0")/../.." && pwd)}
OUTDIR=${2:-/tmp}
STAGE=$(mktemp -d /tmp/aether-pf-stage.XXXXXX)
MANIFEST=$(mktemp /tmp/aether-pf-manifest.XXXXXX)

VERSION=0.1.0
PREFIX=/usr/local

command -v pkg >/dev/null 2>&1 || { echo "pkg not found" >&2; exit 1; }
command -v cc  >/dev/null 2>&1 || { echo "cc not found"  >&2; exit 1; }

echo "src:  $SRCDIR"
echo "out:  $OUTDIR"

# feed.c is compiled with feed_pf.h included, which is how the pf build reuses
# the UNMODIFIED upstream protocol source. Getting this wrong does not fail the
# build -- it fails to link, or worse, compiles a differently-shaped struct.
FEED_DEFS="-include ${SRCDIR}/src/feed_pf.h"
COMMON="-std=c11 -Wall -Wextra -Werror"

echo
echo "=== 1. tests (must pass before anything is packaged) ==="
cc $COMMON -O1 -o "$STAGE/test_pf" "$SRCDIR/test/test_pf.c" "$SRCDIR/src/pf.c"
"$STAGE/test_pf"
cc $COMMON -O1 -o "$STAGE/test_canary_pf" \
	"$SRCDIR/test/test_canary_pf.c" "$SRCDIR/src/canary_pf.c"
"$STAGE/test_canary_pf"
cc $COMMON -O1 -o "$STAGE/test_apply_pf" \
	"$SRCDIR/test/test_apply_pf.c" "$SRCDIR/src/apply_pf.c" "$SRCDIR/src/pf.c"
"$STAGE/test_apply_pf"
cc $COMMON -O1 -I"$SRCDIR/src" $FEED_DEFS -o "$STAGE/test_daemon_pf" \
	"$SRCDIR/test/test_daemon_pf.c" \
	"$SRCDIR/src/daemon_pf.c" "$SRCDIR/src/apply_pf.c" "$SRCDIR/src/pf.c" \
	"$SRCDIR/src/feed.c" "$SRCDIR/src/canary_pf.c" \
	"$SRCDIR/src/local_decide.c" "$SRCDIR/src/local_enforce.c" \
	"$SRCDIR/src/capture_source.c" "$SRCDIR/src/ng_sni.c" \
	"$SRCDIR/src/sni.c" "$SRCDIR/src/reassembly.c" "$SRCDIR/src/policy.c" \
	"$SRCDIR/src/sigdb.c" "$SRCDIR/src/match.c" -lnetgraph
"$STAGE/test_daemon_pf"

# The local decision path and its enforcement bridge. Both are portable, so
# they run here even though the CAPTURE half needs FreeBSD.
cc $COMMON -O1 -o "$STAGE/test_local_decide" \
	"$SRCDIR/test/test_local_decide.c" \
	"$SRCDIR/src/local_decide.c" "$SRCDIR/src/policy.c" "$SRCDIR/src/sigdb.c" \
	"$SRCDIR/src/match.c" "$SRCDIR/src/pf.c"
"$STAGE/test_local_decide"
cc $COMMON -O1 -o "$STAGE/test_local_enforce" \
	"$SRCDIR/test/test_local_enforce.c" \
	"$SRCDIR/src/local_enforce.c" "$SRCDIR/src/local_decide.c" \
	"$SRCDIR/src/policy.c" "$SRCDIR/src/sigdb.c" "$SRCDIR/src/match.c" \
	"$SRCDIR/src/pf.c" "$SRCDIR/src/apply_pf.c"
"$STAGE/test_local_enforce"
cc $COMMON -O1 -o "$STAGE/test_sni" \
	"$SRCDIR/test/test_sni.c" "$SRCDIR/src/sni.c"
"$STAGE/test_sni"


echo
echo "=== 2. build the binaries ==="
mkdir -p "$STAGE/root${PREFIX}/sbin" \
         "$STAGE/root${PREFIX}/etc/rc.d" \
         "$STAGE/root${PREFIX}/share/doc/aether-sensord" \
         "$STAGE/root${PREFIX}/etc"

cc $COMMON -O2 -o "$STAGE/root${PREFIX}/sbin/aether-sensord-pfcanary" \
	"$SRCDIR/src/canary_pf_main.c" "$SRCDIR/src/canary_pf.c"
chmod 0555 "$STAGE/root${PREFIX}/sbin/aether-sensord-pfcanary"

# The daemon links the FULL local path: capture -> signature -> policy -> pf.
# `-lnetgraph` because the capture source drives netgraph directly; there is no
# kernel module to build (ng_bpf/ng_ether ship with the base system).
cc $COMMON -O2 -I"$SRCDIR/src" $FEED_DEFS \
	-o "$STAGE/root${PREFIX}/sbin/aether-sensord-pf" \
	"$SRCDIR/src/daemon_pf_main.c" \
	"$SRCDIR/src/daemon_pf.c" "$SRCDIR/src/apply_pf.c" "$SRCDIR/src/pf.c" \
	"$SRCDIR/src/feed.c" "$SRCDIR/src/canary_pf.c" \
	"$SRCDIR/src/capture_source.c" "$SRCDIR/src/ng_sni.c" \
	"$SRCDIR/src/sni.c" "$SRCDIR/src/reassembly.c" \
	"$SRCDIR/src/local_decide.c" "$SRCDIR/src/local_enforce.c" \
	"$SRCDIR/src/policy.c" "$SRCDIR/src/sigdb.c" "$SRCDIR/src/match.c" \
	"$SRCDIR/src/polcfg.c" -lnetgraph
chmod 0555 "$STAGE/root${PREFIX}/sbin/aether-sensord-pf"

install -m 0755 "$SRCDIR/contrib/freebsd/aether_sensord" \
	"$STAGE/root${PREFIX}/etc/rc.d/aether_sensord"
install -m 0644 "$SRCDIR/contrib/freebsd/aether-sensord.conf.sample" \
	"$STAGE/root${PREFIX}/etc/aether-sensord.conf.sample"

# Ship the OpenWrt signature database, unmodified. It is the SAME file the
# OpenWrt daemon uses, so a fleet and a firewall cannot disagree about what an
# app is.
install -d -m 0755 "$STAGE/root${PREFIX}/share/aether-sensord"
if [ -f "$SRCDIR/../optim-wrt/net/aether-appdb/files/appdb.cfg" ]; then
	install -m 0644 "$SRCDIR/../optim-wrt/net/aether-appdb/files/appdb.cfg" \
		"$STAGE/root${PREFIX}/share/aether-sensord/appdb.cfg"
elif [ -n "$APPDB" ] && [ -f "$APPDB" ]; then
	install -m 0644 "$APPDB" \
		"$STAGE/root${PREFIX}/share/aether-sensord/appdb.cfg"
else
	echo "NOTE: appdb.cfg not found; local capture needs APPDB=/path/to/appdb.cfg" >&2
fi
install -m 0644 "$SRCDIR/contrib/freebsd/policy.conf.sample" \
	"$STAGE/root${PREFIX}/etc/aether-sensord-policy.conf.sample" 2>/dev/null || true
install -m 0644 "$SRCDIR/contrib/freebsd/README.pf" \
	"$STAGE/root${PREFIX}/share/doc/aether-sensord/README.pf"

echo
echo "=== 3. manifest with an explicit files: map (see note above) ==="
cat > "$MANIFEST" <<EOF
name: aether-sensord-pf
version: "$VERSION"
origin: security/aether-sensord-pf
comment: "Aether reputation enforcement for OPNsense (pf), with proof of enforcement"
desc: "Applies the Aether controller's attacker-reputation set to pf tables registered as OPNsense static aliases, and CONFIRMS it took effect. Ships a canary that verifies the MAIN ruleset references the table, because configuration state is not enforcement."
maintainer: "optim@optimcloud.com"
www: "https://github.com/optim-enterprises-bv/aether-sensord"
prefix: "$PREFIX"
licenses: ["BUSL-1.1"]
categories: ["security", "net"]
scripts: {
  post-install: "if [ ! -f ${PREFIX}/etc/aether-sensord.conf ]; then cp ${PREFIX}/etc/aether-sensord.conf.sample ${PREFIX}/etc/aether-sensord.conf; fi; mkdir -p /var/spool/aether/in /var/spool/aether/out; chmod 0750 /var/spool/aether; echo 'aether-sensord: register table aisense_rep4 as an OPNsense static alias before starting, or the daemon will refuse to start.'"
}
files: {
  "${PREFIX}/sbin/aether-sensord-pf": "",
  "${PREFIX}/sbin/aether-sensord-pfcanary": "",
  "${PREFIX}/etc/rc.d/aether_sensord": "",
  "${PREFIX}/etc/aether-sensord.conf.sample": "",
  "${PREFIX}/share/doc/aether-sensord/README.pf": "",
  "${PREFIX}/share/aether-sensord/appdb.cfg": "",
  "${PREFIX}/etc/aether-sensord-policy.conf.sample": ""
}
EOF

cd "$STAGE/root"
pkg create -M "$MANIFEST" -r . -o "$OUTDIR"

PKG="$OUTDIR/aether-sensord-pf-$VERSION.pkg"
echo
echo "=== 4. result ==="
ls -l "$PKG"
echo "  payload:"
tar -tf "$PKG" | sed 's/^/    /'

rm -rf "$STAGE" "$MANIFEST"
echo
echo "Installed with:  pkg add $PKG"
echo "Then:            sysrc aether_sensord_enable=YES"
echo "Verified with:   service aether_sensord start   # exits non-zero unless it can enforce"
echo "                 aether-sensord-pfcanary aisense_rep4   # exit 0 only when enforcing"
