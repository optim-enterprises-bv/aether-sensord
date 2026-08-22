#!/usr/bin/env python3
"""
Generate a pcap of N distinct TCP flows, each carrying a real TLS ClientHello
with an SNI extension.

Purpose: measure the *new-flow classification rate* ceiling of an nDPI-based
userspace classifier (ADR-020's blocking gate). New-flow rate is the number
that matters, not throughput: the design classifies the first few packets of
every flow, so cost scales with connection setups, not bytes.

Deliberately synthetic and deliberately labelled as such. This measures a rate
ceiling under a known, exactly-countable flow population; it is a benchmark
input, not production data, and no classification result from it may be
presented as evidence that anything works (ADR-003). The realism leg of the
gate uses a capture of real traffic.

No scapy dependency -- packets are built byte by byte so this runs anywhere.

Usage:
    ./mkflows.py OUT.pcap [flow_count] [--sni-file FILE]
"""

import os
import struct
import sys

ETH_HDR = struct.pack("!6s6sH", b"\x02\x00\x00\x00\x00\x01",
                      b"\x02\x00\x00\x00\x00\x02", 0x0800)

# A spread of real hostnames so nDPI's matcher does representative work rather
# than hitting one cached answer.
DEFAULT_SNI = [
    "www.youtube.com", "i.instagram.com", "api.telegram.org",
    "github.com", "netflix.com", "play.google.com", "www.tiktok.com",
    "api.openai.com", "graph.facebook.com", "cdn.jsdelivr.net",
    "outlook.office365.com", "teams.microsoft.com", "slack.com",
    "www.amazon.com", "duckduckgo.com", "en.wikipedia.org",
]


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ipv4(src: int, dst: int, proto: int, payload: bytes) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, proto, 0,
                      struct.pack("!I", src), struct.pack("!I", dst))
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int,
        src: int, dst: int, payload: bytes = b"") -> bytes:
    off_flags = (5 << 12) | flags
    hdr = struct.pack("!HHIIHHHH", sport, dport, seq, ack, off_flags,
                      65535, 0, 0)
    pseudo = struct.pack("!4s4sBBH", struct.pack("!I", src),
                         struct.pack("!I", dst), 0, 6, len(hdr) + len(payload))
    csum = checksum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack("!H", csum) + hdr[18:]
    return hdr + payload


def client_hello(sni: str) -> bytes:
    """A minimal but structurally valid TLS 1.2 ClientHello carrying SNI."""
    host = sni.encode()
    sni_ext_body = struct.pack("!HBH", len(host) + 3, 0, len(host)) + host
    sni_ext = struct.pack("!HH", 0x0000, len(sni_ext_body)) + sni_ext_body

    # supported_versions, so the record does not look truncated to a dissector
    ver_ext_body = struct.pack("!BHH", 4, 0x0303, 0x0302)
    ver_ext = struct.pack("!HH", 0x002B, len(ver_ext_body)) + ver_ext_body

    exts = sni_ext + ver_ext
    body = (struct.pack("!H", 0x0303)          # client_version
            + b"\xab" * 32                      # random
            + b"\x00"                           # session_id length
            + struct.pack("!H", 2) + b"\xc0\x2f"  # one cipher suite
            + b"\x01\x00"                       # compression: null
            + struct.pack("!H", len(exts)) + exts)

    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def server_hello_ish() -> bytes:
    # A short server record so the flow is bidirectional; contents are not
    # parsed for SNI and only need to be well-formed at the record layer.
    body = b"\x02" + struct.pack("!I", 40)[1:] + struct.pack("!H", 0x0303) \
        + b"\xcd" * 32 + b"\x00" + b"\xc0\x2f" + b"\x00"
    return b"\x16\x03\x03" + struct.pack("!H", len(body)) + body


def pcap_packet(ts_us: int, data: bytes) -> bytes:
    return struct.pack("!IIII", ts_us // 1_000_000, ts_us % 1_000_000,
                       len(data), len(data)) + data


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    out = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
    # Extra data packets per flow. Lets the same packet population be split
    # across few or many flows, which is how per-flow cost is separated from
    # per-packet cost.
    pad = 0
    if "--pad" in sys.argv:
        pad = int(sys.argv[sys.argv.index("--pad") + 1])

    snis = DEFAULT_SNI
    if "--sni-file" in sys.argv:
        path = sys.argv[sys.argv.index("--sni-file") + 1]
        with open(path) as fh:
            snis = [l.strip() for l in fh if l.strip()]

    client_net = 0xC0A80100  # 192.168.1.0/24 clients
    ts = 0
    pkts = 0

    with open(out, "wb") as fh:
        # pcap global header, big-endian magic, DLT_EN10MB
        fh.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

        for i in range(count):
            sport = 1024 + (i % 64000)
            src = client_net + 10 + (i % 200)
            # Spread destinations across a /16 so the flow table is exercised.
            dst = 0x0A000000 + (i % 65535)
            sni = snis[i % len(snis)]

            frames = [
                tcp(sport, 443, 1000, 0, 0x02, src, dst),                   # SYN
                tcp(443, sport, 5000, 1001, 0x12, dst, src),                # SYN-ACK
                tcp(sport, 443, 1001, 5001, 0x10, src, dst),                # ACK
                tcp(sport, 443, 1001, 5001, 0x18, src, dst, client_hello(sni)),
                tcp(443, sport, 5001, 9999, 0x18, dst, src, server_hello_ish()),
            ]
            for k in range(pad):
                frames.append(tcp(sport, 443, 1100 + k, 9999, 0x18, src, dst,
                                  b"\x17\x03\x03" + struct.pack("!H", 32)
                                  + bytes(((k + n) % 251) for n in range(32))))
            for j, seg in enumerate(frames):
                if j in (1, 4):
                    frame = ETH_HDR + ipv4(dst, src, 6, seg)
                else:
                    frame = ETH_HDR + ipv4(src, dst, 6, seg)
                ts += 20  # 20us apart
                fh.write(pcap_packet(ts, frame))
                pkts += 1

    size = os.path.getsize(out)
    print(f"{out}: {count} flows, {pkts} packets, {size/1e6:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
