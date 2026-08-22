# Signature coverage: what "block this app" actually blocks

Measured 2026-08-22 against the shipped database, `feature_en.cfg`
`#format v2.0` `#version v11.08.23`, 1347 signature entries / 1344 with a host
pattern.

This is a **data** finding, not a code one. The matcher does what it is
specified to do; the patterns it is given are narrower than the product
promises. It is recorded here because the failure is invisible from every
health surface we have — the daemon reports the policy loaded, the rules
compiled, and the push committed, and all three are true.

## Headline

**855 of 1344 applications (64%) can only be matched at `www.<domain>` — an
exact hostname.** For most of those the `www` host is the marketing website,
not the endpoint the application talks to. Blocking them stops the brochure
page and nothing else.

## How matching actually behaves

Established by running `aether-sigtool classify` against the real database.

| Pattern form | Semantics | Example | Covers |
|---|---|---|---|
| `roblox.com` (bare domain) | **suffix** | `roblox.com` | `roblox.com`, `api.roblox.com`, `deep.nested.roblox.com` |
| `youtube` (dotless) | **label prefix** | `youtube` | `youtube.com`, `youtubei.googleapis.com` |
| `www.whatsapp.com` | **effectively exact** | `www.whatsapp.com` | `www.whatsapp.com` only |

The third row is the problem. Suffix matching on a pattern that already begins
with `www.` requires the hostname to *end* with `www.whatsapp.com`, so nothing
but the literal host matches.

Distribution across the database:

```
apps with host patterns:                1344
  ONLY 'www.<domain>' exact hostnames    855  (64%)
  only dotless label prefixes             10  ( 1%)
  mixed / bare domain                    479  (36%)
```

Every app carries exactly **one** host pattern per signature line. Apps with
two patterns have them because two numeric ids merged into one tag.

## Measured examples

`aether-sigtool classify <host> 443`:

```
WhatsApp   (pattern: www.whatsapp.com)
  www.whatsapp.com            tag=whatsapp
  web.whatsapp.com            unclassified
  g.whatsapp.net              unclassified
  mmg.whatsapp.net            unclassified
  static.whatsapp.net         unclassified

Instagram  (pattern: www.instagram.com)
  www.instagram.com           tag=instagram
  i.instagram.com             unclassified     <- the mobile app's API
  scontent.cdninstagram.com   unclassified

Netflix    (patterns: netflix, www.netflix.com)
  www.netflix.com             tag=netflix
  ipv4-c001.nflxvideo.net     unclassified     <- the video itself
  occ-0-1.nflxso.net          unclassified

YouTube    (patterns: youtube, www.youtube.com)
  www.youtube.com             tag=youtube
  youtubei.googleapis.com     tag=youtube
  rr1---sn-abc.googlevideo.com unclassified    <- the video itself
  i.ytimg.com                 unclassified
```

WhatsApp is the clearest case: the messenger never contacts
`www.whatsapp.com`. Blocking it has no effect on the application at all. The
same shape applies to Snapchat, WeChat, Facebook-Messenger, KIK, Kakao-Talk
and Tencent-QQ, all of which are `www.`-only.

## Why this matters more than a normal coverage gap

A parent enables "block WhatsApp". Every layer reports success:

```
policy: 1 subjects, 1 rules accepted from 2 sections
aether-af: 1 host patterns compiled from 1 policy rules
aether-af: pushed 1 of 1 app rule hashes in 1 batch(es)
```

Nothing in that output is false, and nothing is blocked. This is exactly the
class ADR-017 exists to name: a control that reports healthy while enforcing
nothing. It is not detectable from counters, because the counters are correct.

## The obvious fix, and what it costs

Normalising `www.<domain>` to `<domain>` converts an exact match into a suffix
match, upgrading 855 applications from one hostname to a whole domain in a
single transformation.

Measured cost:

```
distinct patterns after stripping 'www.':                1283
patterns then claimed by >1 app:                           43
  (contested before stripping:                             30)
  net new ambiguities:                                     13
```

Most of the 13 are the same brand twice (`Adobe`/`Adobe`, `BBC`/`BBC`), which
already merge by tag and cost nothing. The genuine ones widen a block:

```
amazon.com   -> Amazon, Amazon-Assistant, Amazon-Devices, Kindle
apple.com    -> Apple, Apple-iTunes
bing.com     -> Bing, Bing-Maps
ea.com       -> Electronic-Arts, NHL-by-EA
```

That is a real trade — blocking Amazon would also block Kindle — and it is a
product decision, not an engineering one. It is stated here rather than made
quietly. **This normalisation has NOT been applied.**

It also does not fix the second-order problem: `nflxvideo.net`,
`googlevideo.com`, `cdninstagram.com` and `whatsapp.net` are separate domains
and no amount of normalising the existing patterns reaches them. Covering
those needs new patterns authored per application, which is ongoing data work,
not a transformation.

## Related

- `OAF-SIGNATURE-AMBIGUITY.md` — 30 hostnames already claimed by more than one
  application in this database, including `en.wikipedia.org` resolving to a
  Malware-class signature.
- ADR-017 — silent degradation; "config committed successfully is worthless as
  evidence".
- ADR-020 decision 4 — applications are addressed by stable tag, never numeric
  id.
