# aether-sensord

Device-side security service for aether: attacker-reputation enforcement,
application policy, and firewall-drop sensing in one daemon.

One `poll()` loop watches several sources, so there is one config surface, one
identity and one health surface rather than several daemons that can disagree.

## What it does

**Reputation enforcement** — applies the attacker set published by the aether
controller to nftables, and confirms it took effect. Feed messages arrive as
files in a spool directory, delivered by `ac-client`, which already holds the
device's mTLS identity. This daemon opens no network socket and holds no
credential. The delta/serial/resync protocol means a missed update leaves the
set untouched and demands a snapshot, rather than applying across the gap and
diverging invisibly from both ends.

**Application policy** — loads UCI policy, resolves it against the signature
database, and compiles it to host-pattern hashes pushed to the
[`aether-af`](https://github.com/optim-enterprises-bv/aether-af) kernel module
over netlink. Sends in as many messages as it takes; if any batch fails it does
**not** commit, so the module keeps enforcing the last ruleset that committed
whole.

**Firewall-drop sensing** — aggregates NFLOG records into NDJSON batches.
**Off by default and consented separately** from enforcement: the rest of the
daemon blocks hostile inbound and collects nothing about the subscriber, while
this reports attacker addresses, which are personal data.

## What it refuses, and why that is the point

A control that reports healthy while enforcing nothing is worse than one that
fails loudly. Throughout, anything that cannot be used is **counted and
reported by category** rather than skipped:

- signature entries refused for capacity, separately from malformed ones
- policy lines refused across nine categories, including a rule naming an
  undeclared device (never auto-created — a typo should not become a rule that
  enforces against nothing)
- NFLOG binds that the kernel refused, rather than reporting a live sensor that
  receives nothing
- rule batches that failed to send, which abandon the push instead of
  committing short

## Known coverage limit

`SIGNATURE-COVERAGE.md` measures what "block this app" actually blocks against
the shipped database. **64% of applications match only `www.<domain>`**, an
exact hostname, so blocking most messaging apps stops the marketing site and
nothing else — while every counter correctly reports success. Read it before
trusting an app block.

## Building

Packaging lives in the `optim-wrt` feed under `net/aether-sensord/` and fetches
this repository at a pinned commit.

Host tests need no device, no root and no ubus:

```sh
make -C test check                       # 520 checks
AETHER_SIGDB=/path/to/feature_en.cfg \
  make -C test check                     # 529, incl. real-database checks
```

The shipped signature database lives in a different feed package. Without
`AETHER_SIGDB` the nine checks against it SKIP and say so, rather than
silently passing.

## Licence

**Business Source License 1.1** — source-available, not open source.

You may read, modify, redistribute and make non-production use of this freely.
**Production use is granted for use with the Aether platform**; production use
with any other controller or cloud service requires a commercial licence.
Converts to **GPL-2.0-or-later on 2030-08-22**.

The gate is not "are you a commercial entity" — it is which controller you
point at. An ISP running Aether is covered; the same ISP pointing this at a
different platform is not.

For commercial licensing: `licensing@optimcloud.com`.

### Why not BSD, given OpenSync is

The device agent is open in the sense that matters — you can read it, build it,
and put it on your own hardware. But unlike OpenSync, which is inert without a
controller, this daemon's application-filtering half runs standalone on a local
UCI policy and a local signature database. That standalone value is what the
licence protects.

No GPL library is linked: the NFLOG receive path and the netlink push are
written directly against sockets rather than `libnetfilter_log` or `libmnl`, so
the declared licence is true rather than merely intended. The kernel module it
drives, `aether-af`, is separately GPL-2.0 and holds only hashes — the netlink
boundary between them is what keeps these two licences independent.
