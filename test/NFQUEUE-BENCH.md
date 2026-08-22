# Is a kernel module faster than userspace? Measured.

BPI-R4 (filogic, 4 cores, kernel 6.18.44), 2026-08-22. Loopback only, so no
household traffic entered the queue. Sources: `nfq_accept.c`, `connbench.c`,
`echoserv.c` -- benchmark scaffolding, never shipped.

## Result

New-flow rate, 3,000 connections per run, three runs each, reproducible:

| | conn/s | us/conn |
|---|---|---|
| Baseline, kernel path only | **9,600** | 104 |
| With NFQUEUE, every packet to userspace | **6,245** | 160 |
| **Cost of the userspace crossing** | **-35%** | **+56 us** |

Handler: 53,984 packets in 1.444s = **37,394 pkt/s, 26.7 us/packet**, doing
nothing but issuing ACCEPT. That is the FLOOR -- real classification is on top.

## Answer: yes, the kernel is faster. No, it does not decide this.

**The 6,245 figure is the worst case.** The rule queued EVERY packet of every
flow -- roughly six per connection. The actual design queues only until the
ClientHello, two or three, then verdicts the conntrack entry and lets the rest
fly. That roughly halves the penalty.

**Scale settles it.** A busy household peaks at tens to low hundreds of new
connections per second. Even queueing everything, this board sustains 6,245/s
-- 20-60x that. Applying the 4x CPU derating for D50/IPQ5018 gives ~1,500/s,
still 5-15x a household peak.

## The finding that actually matters

**The userspace crossing is not the bottleneck.**

    NFQUEUE crossing      56 us/conn
    DPI classification   214 us/flow   (measured separately, BENCH-RESULTS.md)

Classification is roughly 4x the queueing overhead. So a kernel module would
eliminate the SMALLER of the two costs -- and you would still pay the larger
one, in an environment where it is considerably harder: no nDPI, no QUIC
ClientHello decryption, no libc, and a bug is a kernel panic on a remote
subscriber router rather than a wrong verdict in a log.

That is the argument against the module, and it is a performance argument
rather than a licence one. It stands even if the licence question resolves in
the module's favour.

## What this does not measure

- Classification cost inside the queue path. The handler inspects nothing.
  Adding nDPI + our matcher raises per-packet cost; the 214 us/flow figure is
  the closest proxy and was measured on a different path (pcap replay).
- Bounded queueing. Queueing only the first N packets per flow is the design;
  this measured all-or-nothing. The real figure sits between 104 and 160.
- Concurrency under load. Single client, sequential connects. A household has
  many devices opening flows at once.
- D50/IPQ5018. Extrapolated at 4x, never run there.
