#!/usr/bin/env python3
"""
Generate the classic-BPF programs for the FreeBSD capture path, and SIMULATE
them locally before emitting any C.

Why simulate: BPF programs are validated and executed against real bytes on the
FreeBSD build VM, but each round trip is slow. A pure-Python interpreter for the
subset of classic BPF used here reproduces bpf_filter()'s semantics closely
enough to catch offset and jump errors before SSH-ing anywhere, and a
disagreement between the simulator and the kernel interpreter is itself a bug
worth knowing about.

Two programs are emitted, and the distinction between them is the central
lesson of this port:

  bpf_tls_clienthello  -- recognises the START of a TLS ClientHello.
  bpf_tcp_payload      -- the DELIVERY filter: IPv4 + TCP + not a fragment +
                          a non-empty payload.

Measured, which is why the second exists: OpenSSL 3.5 sends a 1545-byte
ClientHello (ML-KEM hybrid key shares), the first segment carries 1448 bytes and
the rest arrives in a second segment. That continuation segment does not begin
with 0x16, so gating DELIVERY on the ClientHello pattern dropped it, the
reassembler reported "need more bytes" forever, and no hostname was produced --
while the counters showed a healthy matcher.

Opcodes are symbolic C expressions taken from the platform header, so the
compiler resolves them. An earlier version emitted raw hex and was wrong in
three places at once (BPF_LDX is 0x01 not 0x00, BPF_MUL is 0x20 not 0x24, and
the JMP opcodes are 0x10/0x40 because the class is OR'd with the operation).
"""

import struct
import sys

# ---------------------------------------------------------------- symbolic opcodes
LD_H_ABS = "BPF_LD|BPF_H|BPF_ABS"
LD_B_ABS = "BPF_LD|BPF_B|BPF_ABS"
LD_H_IND = "BPF_LD|BPF_H|BPF_IND"
LD_B_IND = "BPF_LD|BPF_B|BPF_IND"
LD_MEM   = "BPF_LD|BPF_MEM"
LDX_MEM  = "BPF_LDX|BPF_MEM"
LDX_IMM  = "BPF_LDX|BPF_W|BPF_IMM"
ST_MEM   = "BPF_ST"
JEQ_K    = "BPF_JMP|BPF_JEQ|BPF_K"
JGT_K    = "BPF_JMP|BPF_JGT|BPF_K"
JSET_K   = "BPF_JMP|BPF_JSET|BPF_K"
JA       = "BPF_JMP|BPF_JA"
ADD_K    = "BPF_ALU|BPF_ADD|BPF_K"
ADD_X    = "BPF_ALU|BPF_ADD|BPF_X"
SUB_X    = "BPF_ALU|BPF_SUB|BPF_X"
AND_K    = "BPF_ALU|BPF_AND|BPF_K"
RSH_K    = "BPF_ALU|BPF_RSH|BPF_K"
MUL_K    = "BPF_ALU|BPF_MUL|BPF_K"
TAX      = "BPF_MISC|BPF_TAX"
TXA      = "BPF_MISC|BPF_TXA"
RET_K    = "BPF_RET|BPF_K"

# Numeric equivalents, FOR THE SIMULATOR ONLY (must match <net/bpf.h>).
NUM = {
    LD_H_ABS: 0x28, LD_B_ABS: 0x30, LD_H_IND: 0x48, LD_B_IND: 0x50,
    LD_MEM: 0x60, LDX_MEM: 0x61, LDX_IMM: 0x01, ST_MEM: 0x02,
    JEQ_K: 0x15, JGT_K: 0x25, JSET_K: 0x45, JA: 0x05,
    ADD_K: 0x04, ADD_X: 0x0c, SUB_X: 0x1c, AND_K: 0x54, RSH_K: 0x74,
    MUL_K: 0x24, TAX: 0x07, TXA: 0x87, RET_K: 0x06,
}

ACCEPT = 0xffff
SCRATCH = 16


class Prog:
    def __init__(self, name):
        self.name = name
        self.P = []
        self.labels = {}

    def emit(self, code, k=0, comment="", jt=None, jf=None):
        self.P.append({"code": code, "k": k, "c": comment,
                       "jt": jt, "jf": jf})

    def label(self, name):
        self.labels[name] = len(self.P)

    def resolve(self):
        problems = []
        for i, ins in enumerate(self.P):
            jt_r, jf_r = 0, 0
            for which, name in (("jt", ins["jt"]), ("jf", ins["jf"])):
                if name is None:
                    continue
                if name not in self.labels:
                    problems.append((i, which, name, "unknown label"))
                    continue
                delta = self.labels[name] - (i + 1)
                if delta < 0:
                    problems.append((i, which, name, "BACKWARD jump"))
                if ins["code"] == JA:
                    jf_r = delta
                elif which == "jt":
                    jt_r = delta
                else:
                    jf_r = delta
            ins["jt_r"], ins["jf_r"] = jt_r, jf_r
        for p in problems:
            print("   PROBLEM:", p)
        if problems:
            raise SystemExit(1)
        print(f"   {self.name}: {len(self.P)} instructions, "
              f"all branches forward and resolved")

    def text(self):
        out = []
        for i, ins in enumerate(self.P):
            out.append(f"\t{{ {ins['code']}, {ins['jt_r']}, {ins['jf_r']}, "
                       f"{ins['k']:#x} }},  /* {i:2d}: {ins['c']} */")
        return "\n".join(out)

    # ------------------------------------------------------------ simulator
    def simulate(self, frame):
        A = X = 0
        M = [0] * SCRATCH
        l3 = 0
        pc, steps = 0, 0
        while steps < 10000:
            steps += 1
            if pc < 0 or pc >= len(self.P):
                return 0
            ins = self.P[pc]
            code = ins["code"]
            k = ins["k"]
            num = NUM[code]
            # bounds: a load past buflen is rejected by bpf_filter
            def need(off, size, ind=False):
                base = (X if ind else 0) + off
                if base < 0 or base + size > len(frame):
                    return None
                return base

            if code == LD_H_ABS:
                o = need(k, 2)
                if o is None:
                    return 0
                A = struct.unpack_from(">H", frame, o)[0]
            elif code == LD_B_ABS:
                o = need(k, 1)
                if o is None:
                    return 0
                A = frame[o]
            elif code == LD_H_IND:
                o = need(k, 2, True)
                if o is None:
                    return 0
                A = struct.unpack_from(">H", frame, o)[0]
            elif code == LD_B_IND:
                o = need(k, 1, True)
                if o is None:
                    return 0
                A = frame[o]
            elif code == LD_MEM:
                A = M[k]
            elif code == LDX_MEM:
                X = M[k]
            elif code == LDX_IMM:
                X = k
            elif code == ST_MEM:
                M[k] = A
            elif code == JEQ_K:
                pc += ins["jt_r"] + 1 if A == k else ins["jf_r"] + 1
                continue
            elif code == JGT_K:
                pc += ins["jt_r"] + 1 if A > k else ins["jf_r"] + 1
                continue
            elif code == JSET_K:
                pc += ins["jt_r"] + 1 if (A & k) else ins["jf_r"] + 1
                continue
            elif code == JA:
                pc += ins["jf_r"] + 1
                continue
            elif code == ADD_K:
                A = (A + k) & 0xffffffff
            elif code == ADD_X:
                A = (A + X) & 0xffffffff
            elif code == SUB_X:
                A = (A - X) & 0xffffffff
            elif code == AND_K:
                A = (A & k) & 0xffffffff
            elif code == RSH_K:
                A = (A >> k) & 0xffffffff
            elif code == MUL_K:
                A = (A * k) & 0xffffffff
            elif code == TAX:
                X = A
            elif code == TXA:
                A = X
            elif code == RET_K:
                return k
            else:
                raise AssertionError(f"unhandled opcode {code}")
            pc += 1
        return 0


# ------------------------------------------------------------------- programs
def l3_preamble(p):
    p.label("L_untagged")
    p.emit(LDX_IMM, 12, "X = EtherType position (untagged)")
    p.emit(LD_H_IND, 0, "A = EtherType")
    p.emit(JEQ_K, 0x0800, "IPv4?", jt="L_setbase", jf="L_t1")
    p.label("L_t1")
    p.emit(JEQ_K, 0x8100, "802.1Q tag?", jt="L_tag1", jf="L_t2")
    p.label("L_t2")
    p.emit(JEQ_K, 0x88a8, "QinQ outer tag?", jt="L_tag1", jf="L_drop")
    p.label("L_tag1")
    p.emit(LDX_IMM, 16, "X = EtherType position after one tag")
    p.emit(LD_H_IND, 0, "A = inner EtherType")
    p.emit(JEQ_K, 0x0800, "IPv4?", jt="L_setbase", jf="L_t3")
    p.label("L_t3")
    p.emit(JEQ_K, 0x8100, "second tag?", jt="L_tag2", jf="L_t4")
    p.label("L_t4")
    p.emit(JEQ_K, 0x88a8, "QinQ after one tag?", jt="L_tag2", jf="L_drop")
    p.label("L_tag2")
    p.emit(LDX_IMM, 20, "X = EtherType position after two tags")
    p.emit(LD_H_IND, 0, "A = innermost EtherType")
    p.emit(JEQ_K, 0x0800, "IPv4?", jt="L_setbase", jf="L_drop")
    p.label("L_setbase")
    p.emit(TXA, 0, "A = EtherType position")
    p.emit(ADD_K, 2, "+2 = L3 header base")
    p.emit(TAX, 0, "X = L3 header base")
    p.emit(TXA, 0, "A = L3 base (to stash it)")
    p.emit(ST_MEM, 3, "M[3] = L3 base")


def build_clienthello():
    p = Prog("bpf_tls_clienthello")
    l3_preamble(p)
    p.label("L_ipv4")
    p.emit(LD_B_IND, 0, "A = version / IHL byte")
    p.emit(AND_K, 0xf0, "")
    p.emit(JEQ_K, 0x40, "IPv4?", jt="L_restore", jf="L_drop")
    p.label("L_restore")
    p.emit(LDX_MEM, 3, "X = L3 base again")
    p.emit(LD_B_IND, 9, "A = IP protocol")
    p.emit(JEQ_K, 6, "TCP?", jt="L_frag", jf="L_drop")
    p.label("L_frag")
    p.emit(LD_H_IND, 6, "A = flags + fragment offset")
    p.emit(JSET_K, 0x1fff, "fragment? drop", jt="L_drop", jf="L_hdr")
    p.label("L_hdr")
    p.emit(LD_B_IND, 0, "A = version / IHL byte")
    p.emit(AND_K, 0x0f, "")
    p.emit(MUL_K, 4, "IHL in bytes (honours IP options)")
    p.emit(ADD_X, 0, "+ L3 base = TCP header base")
    p.emit(TAX, 0, "X = TCP header base")
    p.emit(LD_B_IND, 12, "A = TCP data-offset byte")
    p.emit(AND_K, 0xf0, "")
    p.emit(RSH_K, 2, "TCP header length (honours TCP options)")
    p.emit(ADD_X, 0, "+ TCP base = TLS record base")
    p.emit(TAX, 0, "X = payload base")
    p.label("L_tls")
    p.emit(LD_B_IND, 0, "A = TLS record content type")
    p.emit(JEQ_K, 0x16, "handshake (0x16)?", jt="L_ver", jf="L_drop")
    p.label("L_ver")
    p.emit(LD_B_IND, 1, "A = TLS record major version")
    p.emit(JEQ_K, 0x03, "TLS 1.x (0x03)?", jt="L_hs", jf="L_drop")
    p.label("L_hs")
    p.emit(LD_B_IND, 5, "A = handshake message type")
    p.emit(JEQ_K, 0x01, "ClientHello (0x01)?", jt="L_accept", jf="L_drop")
    p.label("L_accept")
    p.emit(RET_K, ACCEPT, "ACCEPT")
    p.label("L_drop")
    p.emit(RET_K, 0, "DROP")
    return p


def build_tcp_payload():
    p = Prog("bpf_tcp_payload")
    l3_preamble(p)
    p.label("L_ipv4")
    p.emit(LD_B_IND, 0, "A = version / IHL byte")
    p.emit(AND_K, 0xf0, "")
    p.emit(JEQ_K, 0x40, "IPv4?", jt="L_proto", jf="L_drop")
    p.label("L_proto")
    p.emit(LD_B_IND, 9, "A = IP protocol")
    p.emit(JEQ_K, 6, "TCP?", jt="L_frag", jf="L_drop")
    p.label("L_frag")
    p.emit(LD_H_IND, 6, "A = flags + fragment offset")
    p.emit(JSET_K, 0x1fff, "fragment? drop", jt="L_drop", jf="L_total")
    p.label("L_total")
    p.emit(LD_H_IND, 2, "A = IP total length")
    p.emit(ST_MEM, 2, "M[2] = ip_total")
    p.emit(LD_B_IND, 0, "A = version / IHL byte")
    p.emit(AND_K, 0x0f, "")
    p.emit(MUL_K, 4, "IHL in bytes")
    p.emit(ADD_X, 0, "+ L3 base = TCP header base")
    p.emit(TAX, 0, "X = TCP header base")
    p.emit(LD_B_IND, 12, "A = TCP data-offset byte")
    p.emit(AND_K, 0xf0, "")
    p.emit(RSH_K, 2, "TCP header length")
    p.emit(ADD_X, 0, "+ TCP base = payload base")
    p.emit(ST_MEM, 1, "M[1] = payload base")
    p.emit(LD_MEM, 1, "A = payload base")
    p.emit(LDX_MEM, 3, "X = L3 base")
    p.emit(SUB_X, 0, "A = IP + TCP header bytes")
    p.emit(ST_MEM, 4, "M[4] = header bytes")
    p.emit(LD_MEM, 2, "A = ip_total")
    p.emit(LDX_MEM, 4, "X = header bytes")
    p.emit(SUB_X, 0, "A = payload length")
    p.emit(JEQ_K, 0, "zero payload (pure ACK)? drop", jt="L_drop",
           jf="L_under")
    p.label("L_under")
    p.emit(JGT_K, 0xffff, "underflow guard: ip_total < headers -> the "
           "subtraction wrapped; drop", jt="L_drop", jf="L_accept")
    p.label("L_accept")
    p.emit(RET_K, ACCEPT, "ACCEPT")
    p.label("L_drop")
    p.emit(RET_K, 0, "DROP")
    return p


# -------------------------------------------------------------- frame builder
def build_frame(payload, ip_opts=0, tcp_opts=12, vlan=0, frag=0, proto=6,
                ip_total=None):
    iph = 20 + ip_opts
    tcph = 20 + tcp_opts
    total = iph + tcph + len(payload) if ip_total is None else ip_total
    f = b"\x02" * 12
    if vlan == 0:
        f += b"\x08\x00"
    else:
        for _ in range(vlan - 1):
            f += b"\x81\x00\x00\x64"
        f += b"\x81\x00\x00\x63\x08\x00"
    l3 = 14 + 4 * vlan
    # IPv4 layout from l3: ver/ihl, tos, total(2), ident(2), flags+frag(2),
    # ttl, proto, checksum(2), src(4), dst(4). The identification field is easy
    # to drop and doing so shifts TTL/proto by two bytes, which makes every
    # protocol check miss -- exactly what the simulator caught here.
    f += bytes([0x40 | (iph // 4), 0]) + struct.pack(">H", total)
    f += b"\x00\x00" + struct.pack(">H", frag)
    f += b"\x40" + bytes([proto]) + b"\x00\x00"
    f += b"\x0a\x63\x63\x02\x0a\x63\x63\x01"
    f += b"\x01" * ip_opts
    f += b"\x30\x39\x01\xbb\x00\x00\x00\x00\x00\x00\x00\x00"
    f += bytes([(tcph // 4) << 4, 0x18]) + b"\x72\x10\x00\x00\x00\x00"
    f += b"\x01" * tcp_opts
    f += payload
    return f, l3


def clienthello(sni, rec_ver=1):
    b = bytearray()
    b += bytes([0x16, 0x03, rec_ver, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
    b += bytes([0x03, 0x03]) + b"\xab" * 32
    b += bytes([0x00, 0x00, 0x02, 0x00, 0x2f, 0x01, 0x00])
    ext = bytearray()
    name = sni.encode()
    ext += b"\x00\x00" + struct.pack(">H", len(name) + 5)
    ext += struct.pack(">H", len(name) + 3) + b"\x00"
    ext += struct.pack(">H", len(name)) + name
    b += struct.pack(">H", len(ext)) + ext
    b[6:9] = struct.pack(">I", len(b) - 9)[1:]
    b[3:5] = struct.pack(">H", len(b) - 5)
    return bytes(b)


# ------------------------------------------------------------------ self-test
def self_test(ch, tp):
    print("\n=== simulator self-test ===")
    fails = 0

    def expect(prog, frame, want, what):
        nonlocal fails
        got = prog.simulate(frame)
        ok = (got != 0) == want
        if not ok:
            fails += 1
        print(f"  {'ok  ' if ok else 'FAIL'}: {what} "
              f"(want {'accept' if want else 'drop'}, got {got})")

    ch_len = clienthello("self.test")
    f, l3 = build_frame(ch_len)
    expect(ch, f, True, "ClientHello, 32-byte TCP header (real-world default)")
    f, _ = build_frame(ch_len, tcp_opts=0)
    expect(ch, f, True, "ClientHello, 20-byte TCP header")
    f, _ = build_frame(ch_len, tcp_opts=24)
    expect(ch, f, True, "ClientHello, 40-byte TCP header")
    f, _ = build_frame(ch_len, ip_opts=12)
    expect(ch, f, True, "ClientHello, IP options")
    f, _ = build_frame(ch_len, ip_opts=12, tcp_opts=24)
    expect(ch, f, True, "ClientHello, IP + TCP options")
    f, _ = build_frame(ch_len, vlan=1)
    expect(ch, f, True, "ClientHello, 802.1Q")
    f, _ = build_frame(ch_len, vlan=2)
    expect(ch, f, True, "ClientHello, QinQ")

    expect(ch, build_frame(b"GET / HTTP/1.0\r\n\r\n")[0], False, "plain HTTP")
    bad = bytearray(ch_len)
    bad[0] = 0x17
    expect(ch, build_frame(bytes(bad))[0], False, "app data 0x17")
    bad = bytearray(ch_len)
    bad[5] = 0x02
    expect(ch, build_frame(bytes(bad))[0], False, "ServerHello")
    f, _ = build_frame(ch_len, proto=17)
    expect(ch, f, False, "UDP")
    f, _ = build_frame(ch_len, frag=0x0008)
    expect(ch, f, False, "non-first fragment")
    f, _ = build_frame(ch_len, frag=0x2000)
    expect(ch, f, True, "first fragment (MF, offset 0)")

    # delivery program
    f, _ = build_frame(ch_len)
    expect(tp, f, True, "payload: ClientHello start")
    cont = b"\x01\x02\x03\x04" * 100      # a continuation segment
    f, _ = build_frame(cont)
    expect(tp, f, True, "payload: CONTINUATION segment (no 0x16) -- this is "
                        "the case the pattern filter lost")
    f, _ = build_frame(b"")
    expect(tp, f, False, "pure ACK (no payload)")
    f, _ = build_frame(ch_len, proto=17)
    expect(tp, f, False, "payload: UDP")
    f, _ = build_frame(ch_len, frag=0x0008)
    expect(tp, f, False, "payload: non-first fragment")
    f, _ = build_frame(ch_len, ip_total=10)   # ip_total < headers
    expect(tp, f, False, "payload: ip_total below header size (underflow "
                         "guard)")
    f, _ = build_frame(ch_len, tcp_opts=0)
    expect(tp, f, True, "payload: 20-byte TCP header")
    f, _ = build_frame(ch_len, vlan=1)
    expect(tp, f, True, "payload: 802.1Q")

    print(f"  simulator: {fails} failures")
    return fails


TEMPLATE = """/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * The in-kernel coarse filters for the FreeBSD capture path.
 *
 * ===================== WHY THIS FILE EXISTS, AND WHAT IT COST ==============
 *
 * There are TWO programs here and the difference between them is the central
 * lesson of this port. Both replace versions that shipped broken.
 *
 * 1. bpf_tls_clienthello -- recognises the START of a TLS ClientHello.
 *
 *    The first version used FIXED offsets: record type at byte 54 (14 Ethernet
 *    + 20 IPv4 + 20 TCP) and handshake type at 59. That is correct only when
 *    the TCP header carries no options. MEASURED on FreeBSD 16.0:
 *    `sysctl net.inet.tcp.rfc1323` is 1, so TCP timestamps are on by default,
 *    the TCP header is 32 bytes, and the record actually starts at 66. Byte 54
 *    was a TCP option byte. The program installed cleanly, reported no error,
 *    and never matched anything -- indistinguishable from "no interesting
 *    traffic", which is the worst possible failure mode.
 *
 *    This version walks the header lengths instead:
 *
 *        X = 4 * (byte[14] & 0x0f)      ; IP header length, with IP options
 *        A = byte[X + 26] & 0xf0        ; TCP data-offset byte
 *        X = (A >> 2) + 14 + X          ; TLS record base
 *
 *    correct for 20-, 32- and 40-byte TCP headers and for IP options, and it
 *    handles VLAN and QinQ tags, which the old version silently mis-parsed.
 *
 * 2. bpf_tcp_payload -- the DELIVERY filter, and the fix for a second bug.
 *
 *    Gating DELIVERY on the ClientHello pattern is wrong, because a
 *    ClientHello commonly spans TCP segments and a CONTINUATION segment does
 *    not begin with 0x16. MEASURED: OpenSSL 3.5 sends a 1545-byte ClientHello
 *    (ML-KEM hybrid key shares), the first segment carries 1448 bytes, and the
 *    remainder arrives in a second segment which the pattern filter dropped.
 *    The userspace reassembler therefore reported "need more bytes" forever and
 *    no hostname was ever produced, while the counters showed a healthy
 *    matcher. With modern crypto this is the COMMON case, not an edge case.
 *
 *    So delivery is gated on "IPv4 + TCP + not a fragment + non-empty
 *    payload", and the precise per-flow decision belongs to the reassembler
 *    working on the completed stream. bpf_tls_clienthello still runs, as the
 *    cheap in-kernel classifier and for counters.
 *
 * ============================ HOW THIS IS VERIFIED =========================
 *
 * Both programs are validated with bpf_validate() and EXECUTED with
 * bpf_filter() -- the interpreter the kernel itself uses -- against synthetic
 * frames AND against bytes captured from a real openssl handshake on FreeBSD.
 * See test/test_bpf_tls.c, which also runs the OLD fixed-offset program against
 * the same real bytes to show it rejects them.
 *
 * A filter that is never executed against known input is a guess. Both of the
 * versions this file replaces were guesses, and both were wrong.
 *
 * ============================== GENERATED CODE =============================
 *
 * The instruction tables below are generated by the script that accompanies
 * this port (genbpf.py), which simulates every branch and runs a local
 * interpreter over a matrix of frames before emitting anything. DO NOT
 * hand-edit the tables: re-run the generator with the header as its argument.
 * Jump offsets were hand-counted in the version that failed in production.
 *
 * NOTE ON LENGTH: bpf_filter() receives the captured length as its buflen, so a
 * load past the end of a short frame is rejected by the interpreter rather than
 * reading out of bounds. The length checks in the delivery program are about
 * IP-header arithmetic -- a malformed ip_total must not underflow into a
 * spurious accept -- not about buffer safety.
 */

#ifndef AETHER_SENSORD_BPF_TLS_H
#define AETHER_SENSORD_BPF_TLS_H

#include <stddef.h>

/*
 * Where the BPF definitions come from, per platform.
 *
 * FreeBSD: <net/bpf.h> is in base and has the struct and the opcode constants.
 * Linux: there is no <net/bpf.h> unless a kernel-uapi package is installed, but
 * <pcap/bpf.h> (libpcap-devel) carries the SAME classic-BPF definitions -- same
 * struct layout, same opcode names -- and it is also where bpf_filter() lives,
 * which the test uses. Using it keeps the program byte-identical on both
 * platforms, so a Linux developer can run the whole suite rather than only read
 * it. _DEFAULT_SOURCE is needed first because pcap/bpf.h uses the BSD typedefs
 * (u_int, u_char) that glibc does not declare by default.
 */
#if defined(__FreeBSD__)
#include <sys/types.h>
#include <sys/socket.h>
#include <net/bpf.h>
#else
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include <sys/types.h>

#include <pcap/bpf.h>
#endif

/* Nonzero return = deliver the frame to userspace; 0 = drop. */
#define BPF_TLS_ACCEPT_ALL 0xffff

/*
 * Scratch memory used by bpf_tcp_payload. Scratch words are per-packet, so
 * there is no state to leak between frames.
 */
#define BPF_SCRATCH_TCP_BASE  0
#define BPF_SCRATCH_PAY_BASE  1
#define BPF_SCRATCH_IP_TOTAL  2
#define BPF_SCRATCH_L3_BASE   3
#define BPF_SCRATCH_HDR_BYTES 4

/*
 * Classifier: "does this packet START a TLS ClientHello?" -- in kernel, per
 * packet, cheap. Handles up to two VLAN tags and any IP/TCP header length.
 *
 * This is NOT the delivery gate: it cannot see a ClientHello that spans
 * segments. Use bpf_tcp_payload for delivery and let the reassembler decide.
 */
static const struct bpf_insn bpf_tls_clienthello[] = {
__CLIENTHELLO__
};

#define BPF_TLS_CLIENTHELLO_LEN \
	((int)(sizeof bpf_tls_clienthello / sizeof bpf_tls_clienthello[0]))

/*
 * Delivery: "IPv4 + TCP + not a fragment + non-empty payload".
 *
 * Deliberately NOT the ClientHello pattern -- see the header comment. A
 * continuation segment of a large ClientHello looks like any other TCP payload,
 * and it must be delivered or the reassembler can never finish.
 */
static const struct bpf_insn bpf_tcp_payload[] = {
__TCPPAYLOAD__
};

#define BPF_TCP_PAYLOAD_LEN \
	((int)(sizeof bpf_tcp_payload / sizeof bpf_tcp_payload[0]))

/*
 * Control program: accept everything.
 *
 * Required, not optional. An ng_bpf node with NO program installed drops every
 * frame, so "nothing arrived" cannot be read as a match decision unless the
 * graph has first been shown to deliver. Installing this is what makes a later
 * negative result meaningful.
 */
static const struct bpf_insn bpf_tls_accept_all[] = {
	{ BPF_LD|BPF_B|BPF_ABS, 0, 0, 0x0 },
	{ BPF_RET|BPF_K, 0, 0, 0xffff },
};

#define BPF_TLS_ACCEPT_ALL_LEN \
	((int)(sizeof bpf_tls_accept_all / sizeof bpf_tls_accept_all[0]))

#endif /* AETHER_SENSORD_BPF_TLS_H */
"""


def emit_header(path, ch, tp):
    for p in (ch, tp):
        assert p.P[-1]["code"] == RET_K and p.P[-1]["k"] == 0, p.name
        assert any(x["code"] == RET_K and x["k"] == ACCEPT for x in p.P), p.name
    text = TEMPLATE.replace("__CLIENTHELLO__", ch.text())
    text = text.replace("__TCPPAYLOAD__", tp.text())
    open(path, "w").write(text)
    print("wrote", path)


if __name__ == "__main__":
    ch = build_clienthello()
    ch.resolve()
    tp = build_tcp_payload()
    tp.resolve()
    bad = self_test(ch, tp)
    if bad:
        print("\nSIMULATION FAILED -- not emitting C")
        sys.exit(1)
    emit_header(sys.argv[1] if len(sys.argv) > 1 else "src/bpf_tls.h", ch, tp)
