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

command -v pkg >/dev/null 2>&1 || { echo "pkg not found" >&2; exit 1; }
command -v cc  >/dev/null 2>&1 || { echo "cc not found"  >&2; exit 1; }

echo "src:  $SRCDIR"
echo "out:  $OUTDIR"

echo
echo "=== 1. tests (must pass before anything is packaged) ==="
cc -std=c11 -Wall -Wextra -Werror -O1 -o "$STAGE/test_pf" \
	"$SRCDIR/test/test_pf.c" "$SRCDIR/src/pf.c"
"$STAGE/test_pf"
cc -std=c11 -Wall -Wextra -Werror -O1 -o "$STAGE/test_canary_pf" \
	"$SRCDIR/test/test_canary_pf.c" "$SRCDIR/src/canary_pf.c"
"$STAGE/test_canary_pf"

echo
echo "=== 2. build the canary ==="
mkdir -p "$STAGE/root/usr/local/sbin" \
         "$STAGE/root/usr/local/share/doc/aether-sensord"
cc -std=c11 -Wall -Wextra -Werror -O2 \
	-o "$STAGE/root/usr/local/sbin/aether-sensord-pfcanary" \
	"$SRCDIR/src/canary_pf_main.c" "$SRCDIR/src/canary_pf.c"
chmod 0555 "$STAGE/root/usr/local/sbin/aether-sensord-pfcanary"

if [ -f "$SRCDIR/contrib/freebsd/README.pf" ]; then
	install -m 0644 "$SRCDIR/contrib/freebsd/README.pf" \
		"$STAGE/root/usr/local/share/doc/aether-sensord/README.pf"
fi

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
prefix: "/usr/local"
licenses: ["BUSL-1.1"]
categories: ["security", "net"]
files: {
  "/usr/local/sbin/aether-sensord-pfcanary": "",
  "/usr/local/share/doc/aether-sensord/README.pf": ""
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
echo "Verified with:   aether-sensord-pfcanary <table>   # exit 0 only when enforcing"
