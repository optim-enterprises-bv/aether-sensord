#!/bin/sh
#
# Copyright (C) 2026 Optim Enterprises BV
#
# This is free software, licensed under the BSD 3-Clause License.
#
# ADR-020 blocking gate: what new-flow classification rate can a userspace
# nDPI classifier sustain on this SoC?
#
# New-flow rate is the number that decides the design. ADR-020 classifies the
# first few packets of every flow and then stops looking, so cost scales with
# connection setups rather than with bytes. A box that forwards 2 Gbit/s of
# established traffic can still be swamped by a few thousand new connections
# per second.
#
# Method: replay a pcap containing an exactly-known flow population through a
# standalone nDPId instance, wired to a throwaway collector so no benchmark
# data reaches the live analytics pipeline. Measure wall time, CPU time and
# peak RSS; derive flows/sec and packets/sec.
#
# The instance under test is nDPId 1.7 over libnDPI 5.0 -- the same library
# aether-sensord would link, exercised through an equivalent capture path.
# It is a proxy for our classifier, not our classifier; see LIMITS below.
#
# Usage:  ./bench-classify.sh /tmp/flows20k.pcap 20000 [repeats]

set -u

PCAP="${1:-/tmp/flows20k.pcap}"
FLOWS="${2:-20000}"
REPEATS="${3:-3}"

NDPID=/usr/sbin/nDPId-testing
NDPISRVD=/usr/bin/nDPIsrvd-testing

BENCH_DIR=/tmp/aether-bench
COLLECTOR="$BENCH_DIR/collector.sock"
DISTRIB="$BENCH_DIR/distributor.sock"
SRVD_PID="$BENCH_DIR/srvd.pid"
RESULTS="$BENCH_DIR/results.txt"

die() { echo "FATAL: $*" >&2; exit 1; }

[ -r "$PCAP" ] || die "pcap not readable: $PCAP"
[ -x "$NDPID" ] || die "nDPId not found: $NDPID"
[ -x "$NDPISRVD" ] || die "nDPIsrvd not found: $NDPISRVD"

mkdir -p "$BENCH_DIR"
: > "$RESULTS"

cleanup() {
    [ -f "$SRVD_PID" ] && kill "$(cat "$SRVD_PID")" 2>/dev/null
    rm -f "$COLLECTOR" "$DISTRIB" "$SRVD_PID"
}
trap cleanup EXIT INT TERM

PKTS=$(tcpdump -r "$PCAP" -nn 2>/dev/null | wc -l)
SIZE=$(wc -c < "$PCAP")

{
    echo "# aether-sensord classification benchmark (ADR-020 gate)"
    echo "date=$(date -Iseconds 2>/dev/null || date)"
    echo "model=$(cat /tmp/sysinfo/model 2>/dev/null)"
    echo "kernel=$(uname -r)"
    echo "cores=$(grep -c ^processor /proc/cpuinfo)"
    echo "mem_total_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo)"
    echo "ndpid=$($NDPID -v 2>&1 | head -1)"
    echo "pcap=$PCAP flows=$FLOWS packets=$PKTS bytes=$SIZE"
    echo "load_before=$(cut -d' ' -f1-3 /proc/loadavg)"
    echo
} | tee -a "$RESULTS"

# Throwaway collector. Keeps synthetic benchmark flows out of the live
# nDPIsrvd pipeline entirely (ADR-003 -- benchmark input must not be
# indistinguishable from field data downstream).
rm -f "$COLLECTOR" "$DISTRIB"
"$NDPISRVD" -c "$COLLECTOR" -s "$DISTRIB" -p "$SRVD_PID" -d \
    || die "could not start throwaway collector"

i=0
while [ "$i" -lt "$REPEATS" ]; do
    i=$((i + 1))

    # busybox date has no %N, so /proc/uptime is the portable clock here --
    # centisecond resolution, present on every OpenWrt target.
    A=$(cut -d" " -f1 /proc/uptime)
    "$NDPID" -i "$PCAP" -c "$COLLECTOR" >/dev/null 2>&1
    B=$(cut -d" " -f1 /proc/uptime)

    awk -v a="$A" -v b="$B" -v f="$FLOWS" -v p="$PKTS" -v i="$i" \
        'BEGIN{ e=b-a; if (e<=0) e=0.01;
                printf "run=%s wall_s=%.2f flows_per_sec=%.0f packets_per_sec=%.0f\n",
                       i, e, f/e, p/e }' | tee -a "$RESULTS"
done

# Peak RSS of a single run, sampled while it executes.
"$NDPID" -i "$PCAP" -c "$COLLECTOR" -l >/dev/null 2>/dev/null &
BPID=$!
PEAK=0
while kill -0 "$BPID" 2>/dev/null; do
    R=$(awk '/VmRSS/{print $2}' "/proc/$BPID/status" 2>/dev/null)
    [ -n "${R:-}" ] && [ "$R" -gt "$PEAK" ] 2>/dev/null && PEAK=$R
done
wait "$BPID" 2>/dev/null

{
    echo
    echo "peak_rss_kb=$PEAK"
    echo "load_after=$(cut -d' ' -f1-3 /proc/loadavg)"
    echo
    echo "# LIMITS -- read before quoting any number above:"
    echo "#  * nDPId 1.7 is a proxy for aether-sensord, not aether-sensord."
    echo "#    It shares libnDPI 5.0 and an equivalent capture path; it does"
    echo "#    NOT run our 1,347-signature matcher, our policy engine, or any"
    echo "#    enforcement. Real cost is HIGHER than measured here."
    echo "#  * pcap replay reads from tmpfs, so this excludes live-capture"
    echo "#    overhead (AF_PACKET/TPACKETv3, ring contention, kernel copies)."
    echo "#  * synthetic flow population -- a rate ceiling, not field traffic."
    echo "#  * says NOTHING about hardware-offload bypass, which is a separate"
    echo "#    gate item and cannot be measured by replay."
} | tee -a "$RESULTS"

echo
echo "results written to $RESULTS"
