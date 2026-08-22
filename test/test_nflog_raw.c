/*
 * Copyright (C) 2026 Optim Enterprises BV
 *
 * This is free software, licensed under the BSD 3-Clause License.
 *
 * Host tests for the raw-netlink NFLOG parser.
 *
 * This replaced libnetfilter_log (GPL-2.0-or-later) so the daemon can honestly
 * be BSD-3-Clause. Writing our own parser means owning its safety, so the
 * malformed cases come first -- this walks attributes in a buffer that
 * ultimately derives from off-device traffic.
 */
#include "../src/nflog_raw.h"
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

static int failures, checks;
#define CHECK(c, m) do { checks++; if (!(c)) { failures++; \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (m)); } } while (0)

static int seen;
static uint8_t last[256];
static uint32_t last_len;
static void on_pkt(const uint8_t *d, uint32_t n, void *u) {
    (void)u; seen++; last_len = n;
    memcpy(last, d, n < sizeof(last) ? n : sizeof(last));
}

/* Build one NFULNL_MSG_PACKET carrying `payload`. */
static size_t build_msg(uint8_t *b, size_t cap, const uint8_t *payload, size_t plen)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)b;
    size_t nfg = 4, off;
    struct nlattr *a;
    size_t alen = NLA_HDRLEN + plen;
    size_t total = NLMSG_LENGTH(nfg) + NLA_ALIGN(alen);
    if (cap < total) return 0;
    memset(b, 0, total);
    nlh->nlmsg_len = (uint32_t)total;
    nlh->nlmsg_type = (uint16_t)((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET);
    off = NLMSG_LENGTH(nfg);
    a = (struct nlattr *)(b + off);
    a->nla_len = (uint16_t)alen;
    a->nla_type = NFULA_PAYLOAD;
    memcpy((uint8_t *)a + NLA_HDRLEN, payload, plen);
    return total;
}

static void test_extracts_payload(void)
{
    struct nfr_conn c; memset(&c, 0, sizeof(c));
    uint8_t pkt[] = { 0x45, 0x00, 0x00, 0x3c, 0xab, 0xcd };
    uint8_t buf[512];
    size_t n = build_msg(buf, sizeof(buf), pkt, sizeof(pkt));
    seen = 0;
    CHECK(nfr_parse_buffer(&c, buf, n, on_pkt, NULL) == 1, "one packet");
    CHECK(seen == 1, "callback fired");
    CHECK(last_len == sizeof(pkt), "full payload length");
    CHECK(memcmp(last, pkt, sizeof(pkt)) == 0, "payload bytes intact");
}

static void test_truncation_at_every_offset(void)
{
    /* Same blunt instrument as the SNI parser: cut at every length, none may
     * crash or over-dispatch. */
    struct nfr_conn c; memset(&c, 0, sizeof(c));
    uint8_t pkt[16]; memset(pkt, 0xAA, sizeof(pkt));
    uint8_t buf[512];
    size_t n = build_msg(buf, sizeof(buf), pkt, sizeof(pkt));
    int bad = 0;
    for (size_t cut = 0; cut < n; cut++) {
        seen = 0;
        long r = nfr_parse_buffer(&c, buf, cut, on_pkt, NULL);
        if (r > 1) bad++;
    }
    CHECK(bad == 0, "no truncation over-dispatches");
}

static void test_lying_attribute_length(void)
{
    struct nfr_conn c; memset(&c, 0, sizeof(c));
    uint8_t pkt[8]; memset(pkt, 0xBB, sizeof(pkt));
    uint8_t buf[512];
    size_t n = build_msg(buf, sizeof(buf), pkt, sizeof(pkt));

    /* Attribute claims to be far longer than the message. */
    struct nlattr *a = (struct nlattr *)(buf + NLMSG_LENGTH(4));
    a->nla_len = 0xFFFF;
    seen = 0;
    nfr_parse_buffer(&c, buf, n, on_pkt, NULL);
    CHECK(seen == 0, "oversized attribute dispatches nothing");
    CHECK(c.malformed > 0, "and is counted as malformed");

    /* Attribute shorter than its own header. */
    memset(&c, 0, sizeof(c));
    n = build_msg(buf, sizeof(buf), pkt, sizeof(pkt));
    a = (struct nlattr *)(buf + NLMSG_LENGTH(4));
    a->nla_len = 1;
    seen = 0;
    nfr_parse_buffer(&c, buf, n, on_pkt, NULL);
    CHECK(seen == 0, "undersized attribute dispatches nothing");
}

static void test_wrong_subsystem_ignored(void)
{
    struct nfr_conn c; memset(&c, 0, sizeof(c));
    uint8_t pkt[8] = { 0 };
    uint8_t buf[512];
    size_t n = build_msg(buf, sizeof(buf), pkt, sizeof(pkt));
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = (uint16_t)((NFNL_SUBSYS_QUEUE << 8) | 1);
    seen = 0;
    nfr_parse_buffer(&c, buf, n, on_pkt, NULL);
    CHECK(seen == 0, "a different subsystem is not parsed");
}

static void test_nulls_and_empty(void)
{
    struct nfr_conn c; memset(&c, 0, sizeof(c));
    CHECK(nfr_parse_buffer(&c, NULL, 100, on_pkt, NULL) == 0, "null buffer");
    CHECK(nfr_parse_buffer(NULL, (uint8_t *)"x", 1, on_pkt, NULL) == 0, "null conn");
    uint8_t b[4] = { 0 };
    CHECK(nfr_parse_buffer(&c, b, 0, on_pkt, NULL) == 0, "zero length");
    CHECK(nfr_parse_buffer(&c, b, sizeof(b), NULL, NULL) == 0, "null callback");
}

/*
 * Guards the failure that hid for the whole life of the standalone sensor:
 * sendto() succeeds, the kernel refuses with EPERM, and the daemon reports
 * itself live while receiving nothing.
 */
static void test_ack_parsing(void)
{
    uint8_t buf[NLMSG_LENGTH(sizeof(struct nlmsgerr))];
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(nlh);

    memset(buf, 0, sizeof(buf));
    nlh->nlmsg_len = sizeof(buf);
    nlh->nlmsg_type = NLMSG_ERROR;

    e->error = 0;
    CHECK(nfr_parse_ack(buf, sizeof(buf)) == true,
          "explicit success ACK is accepted");

    e->error = -EPERM;
    CHECK(nfr_parse_ack(buf, sizeof(buf)) == false,
          "EPERM is a failure, not a live sensor");

    e->error = -ENOENT;
    CHECK(nfr_parse_ack(buf, sizeof(buf)) == false,
          "any negative error is a failure");

    e->error = 0;
    nlh->nlmsg_type = NLMSG_DONE;
    CHECK(nfr_parse_ack(buf, sizeof(buf)) == false,
          "a non-ERROR reply is not read as consent");

    nlh->nlmsg_type = NLMSG_ERROR;
    CHECK(nfr_parse_ack(buf, NLMSG_HDRLEN) == false,
          "a truncated ACK is refused, not trusted");
    CHECK(nfr_parse_ack(buf, 0) == false, "empty is refused");
    CHECK(nfr_parse_ack(NULL, sizeof(buf)) == false, "NULL is refused");

    /* A header claiming more than was delivered must not be read past;
     * NLMSG_OK is what catches this. */
    nlh->nlmsg_len = sizeof(buf) + 64;
    CHECK(nfr_parse_ack(buf, sizeof(buf)) == false,
          "an over-long declared length is refused");
}

int main(void)
{
    test_extracts_payload();
    test_truncation_at_every_offset();
    test_lying_attribute_length();
    test_wrong_subsystem_ignored();
    test_nulls_and_empty();
    test_ack_parsing();
    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
