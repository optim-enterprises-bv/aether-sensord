# ADR-020 gate: classification throughput on BPI-R4

Measured 2026-08-22. Reproduce with `bench-classify.sh` and `mkflows.py`.

## Device under test

| | |
|---|---|
| Board | Banana Pi BPI-R4 (2x SFP+), MediaTek filogic |
| Kernel | 6.18.44 |
| Cores | 4 |
| RAM | 4,022,660 kB (~3.8 GB) |
| Classifier | nDPId 1.7.0-release over libnDPI 5.0 |

## Result

Two pcaps with an identical packet population (100,000) split across different
flow counts, so per-flow cost separates from per-packet cost. Three runs each,
on an otherwise idle board.

| Flows | Packets | Wall time (3 runs) | flows/sec | packets/sec | Peak RSS |
|---|---|---|---|---|---|
| 20,000 | 100,000 | 5.19 / 5.20 / 5.19 s | **3,850** | 19,250 | 35.9 MB |
| 2,000 | 100,000 | 1.34 / 1.33 / 1.34 s | 1,500 | 75,000 | 29.8 MB |

Solving the pair:

```
20,000·F + 100,000·P = 5.19
 2,000·F + 100,000·P = 1.34
```

| | |
|---|---|
| **Per-flow cost** | **214 µs** |
| **Per-packet cost** | **9.1 µs** |

The model reproduces both measurements to the centisecond (5.19 s and 1.34 s
predicted). Flow-setup-only ceiling is ~4,670 flows/sec; with the five packets
each flow carries, the sustained figure is **~3,850 new flows/sec**.

**Cost is dominated by per-flow work, not per-packet work** — which is what
ADR-020 predicted, and why new-flow rate is the gate rather than throughput.
The per-packet path is fast: with long-lived flows the same board sustains
75,000 packets/sec.

## Verdict

**PASS on filogic.** A subscriber gateway sees tens to low hundreds of new
flows per second at peak; a busy household with many IoT devices, some
hundreds. 3,850/sec is roughly 10–40× that, on two of four cores.

**NOT a pass on IPQ5018.** The BPI-R4 is the optimistic case. Firmware review
supplied the extrapolation; it is recorded here so the headline number is not
quoted as a platform figure:

| | BPI-R4 (measured) | D50 / IPQ5018 (extrapolated) |
|---|---|---|
| Cores × clock | 4 × ~1.8 GHz | 2 × ~1.0 GHz |
| RAM | ~3.9 GB | 512 MB |
| New-flow rate | **3,850/sec** | **~900-1,000/sec** |
| 35.9 MB RSS as share of RAM | ~1% | ~7% |

Roughly 4x less CPU and 8x less memory. ~900-1,000/sec is still likely ample
for a household -- this board idles near 100 concurrent conntrack entries
against a 65,536 table -- but it is arithmetic, not a measurement. The gate is
per-SoC and is cleared only for filogic.

**Not yet measured, and it matters:** burst behaviour. A device waking and
opening 200 connections at once is 200 x 214 us = 43 ms if serialised, which is
fine -- provided flow setup is not contending with the packet path. An average
dominated by flow setup hides exactly that collision.

## What this measurement does not say

Read before quoting the headline number.

- **nDPId is a proxy, not `aether-sensord`.** It shares libnDPI 5.0 and an
  equivalent capture path, but it does not run our 1,347-signature matcher,
  our policy engine, or any enforcement. Our per-flow cost will be **higher**.
- **It also pays a cost we would not.** nDPId serialises a JSON record per flow
  to a separate collector process; that collector consumed 1.73 s of CPU per
  20,000 flows (~86 µs/flow) in a side measurement. `aether-sensord` matches
  in-process and emits aggregates, so some of the 214 µs is architecture we
  are not adopting. These two effects push in opposite directions and the net
  is unknown until our own daemon exists.
- **pcap replay from tmpfs excludes live-capture overhead** — AF_PACKET /
  TPACKETv3 ring handling, kernel copies, ring contention.
- **The flow population is synthetic.** It is a rate ceiling under an
  exactly-countable load, not field traffic, and no classification result from
  it is evidence that anything works in production (ADR-003). The realism leg
  of the gate still needs a capture of real traffic.
- **The measured figure is TLS/SNI flows, and at a ~25% miss rate.** Review
  ran the harness's 16 hostnames against the real 1,347-signature database:
  12 hit, 4 miss. Real subscriber traffic is dominated by misses -- most
  hostnames a household visits are in no signature database -- so a realistic
  mix is nearer 60-90%. A miss is the expensive case in a linear scan (it
  walks every signature and fails), so **214 us/flow is a floor, not a typical
  value**, plausibly by 2-3x. Two fixes for the next run: pad the SNI list
  with unmatched long-tail hostnames to a realistic miss rate, and randomise
  the order rather than cycling `i % 16`, which is perfectly
  branch-predictable over 20,000 flows.

  **This caveat is about nDPI, not about our matcher.** `match_flow` in
  `net/aether-sensord` scans every rule to find the most specific match, so a
  hit and a miss cost it the same and no miss-rate correction applies to it.
  The 214 us floor is entirely a property of nDPI's internal matching. Worth
  saying explicitly, because a reader who knows our matcher is exhaustive
  might otherwise conclude the caveat does not apply to anything.
- **QUIC is not measured at all.** The harness is TLS-with-SNI only. QUIC on
  UDP/443 is a large and growing share of real traffic and carries no visible
  SNI -- it is why OAF ships `disable_quic`. Quote the figure as "3,850
  TLS/SNI flows/sec", never as "3,850 flows/sec".
- **It says nothing about hardware-offload bypass.** That is a separate gate
  item and cannot be measured by replay — offload is bypassed precisely
  because packets never reach the classifier, which a file replay cannot
  reproduce.

## Method notes

- Benchmark instances write to a throwaway `nDPIsrvd` collector on a separate
  socket, so no synthetic flow reaches the live analytics pipeline.
- busybox `date` has no `%N`; `/proc/uptime` is the portable clock (centisecond
  resolution, present on every OpenWrt target).
- An earlier run set showed 7.25 → 9.86 s and was discarded: an abandoned
  `nDPId-testing-test` process from a timed-out invocation was still running at
  182 MB RSS and contending for CPU. Always check `load_before` in the results
  header before trusting a number.
- `tcpdump-mini` was installed on the board for packet counting and remains
  installed.

---

# ADR-003 hardware gate: RESULTS (2026-08-22, BPI-R4)

Cross-compiled aarch64_cortex-a53 musl, gcc 14.4.0, installed via `apk add`.
No sysupgrade, no `fw4 reload`, fw4's own ruleset never re-rendered.

## Gate 1 — full signature database loads on-device: PASS

```
apps        : 1319      rules: 1348      merged_by_tag: 28
refused_malformed: 0    refused_apps_full: 0    refused_rules_full: 0
highest_class: 42       format: v2.0
OK: every line in the database was accounted for.
```

Identical to the host, which also validates the cross-compile: musl/aarch64
produces the same result as glibc/x86-64. This is the gate the reference
implementation could not answer at all -- `/proc/sys/oaf/feature_init` is dead
code and reports 0 forever.

## Gate 2 — feed applied and verified against the kernel: PASS

12 real Spamhaus DROP prefixes fed as a snapshot:

```
feed serial 1 applied and verified (+12 -0)
stopping: 0 deltas, 1 snapshots applied, 0 resyncs,
          1 batches applied, 0 failed, 0 verify mismatches
```

The kernel afterwards held **11** elements, not 12 -- `auto-merge` collapsed
`2.57.232.0/23` + `2.57.234.0/23` into `2.57.232.0/22`. That is correct
behaviour, and it is exactly why `apply_and_verify` checks a FLOOR rather than
an exact count. An exact comparison would have failed here on a correct result.
Entries carry `expires 6d23h59m59s` from the 7-day set timeout.

## Gate 3 — a packet actually dies: PASS

Run in an isolated `inet aether_test` table so fw4's live rules were never
touched:

```
before: ip daddr @rep4 counter packets 0 bytes 0 drop
        ping 192.0.2.1 -> leaves the box

after adding 192.0.2.1 to the set:
        ping: sendto: Operation not permitted
        ip daddr @rep4 counter packets 1 bytes 84 drop
```

Not "config applied successfully" -- a counter incrementing and the kernel
refusing to send. This is the claim ADR-017 says cannot be inferred from an
exit code.

## Still NOT proven

- **Nothing references the sets.** `nft.c` renders set declarations, elements
  and flush, but NO rule using them. Populated sets block nothing until a rule
  exists. Found before the test rather than after, but it means gates 2 and 3
  prove the mechanism separately and not the product.
- Adding `ip saddr @aether_rep4 drop` to fw4's live input chain was NOT done --
  this board is the household's gateway.
- Offload interaction: unchanged and still unmeasured.
- Burst behaviour and the D50/IPQ lane: unchanged, still open.

## Board state left behind

Sets `aether_rep4`/`aether_rep6` exist in `inet fw4` holding 11 real prefixes,
INERT because no rule references them. One persistent file:
`/usr/share/nftables.d/table-pre/inet/fw4/10-aether-sensord.nft` (389 bytes),
which recreates the declarations on the next `fw4 reload`. `apk del
aether-sensord aether-sigtool` plus removing that file reverses everything.
