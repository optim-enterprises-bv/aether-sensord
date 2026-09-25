# Host-side unit tests. No OpenWrt toolchain, no device, no nDPI.
CFLAGS ?= -std=gnu11 -Wall -Wextra -Werror -O1 -g -D_GNU_SOURCE
#
# TWO SUITES, because two platforms.
#
#   BINS       -- portable. Builds and passes on Linux AND FreeBSD, and is what
#                 `make check` runs.
#   LINUX_BINS -- require the Linux kernel's netlink headers. afpush.c and
#                 flowlog.c include <linux/netlink.h>, so they cannot build on
#                 FreeBSD AT ALL -- that is precisely why the FreeBSD port
#                 (bpf_tls.h / ng_sni.c / sni.c / reassembly.c) exists.
#
# They are listed separately rather than being silently dropped: a suite that
# quietly omits the tests it cannot build is worse than one that fails.
BINS = test_sigdb test_policy test_nft test_feed test_apply \
       test_sni test_reassembly test_bpf_tls \
       test_observe test_polcfg test_offload test_canary

# These sources include Linux kernel UAPI headers (linux/netlink.h,
# linux/netfilter/nfnetlink*.h, linux/neighbour.h) and CANNOT build on FreeBSD.
# They are the original Linux transports that the FreeBSD port replaces:
#   afpush.c    netlink  -> bpf_tls.h + ng_sni.c (netgraph)
#   nflog_raw.c nfnetlink -> pf/pflog
#   neigh.c     rtnetlink -> routing socket
# Listed explicitly so the omission is visible, never silent.
LINUX_BINS = test_afpush test_flowlog test_nflog_raw test_neigh
.PHONY: all check clean
all: check
test_sigdb: test_sigdb.c ../src/sigdb.c ../src/match.c ../src/sigdb.h ../src/match.h
	$(CC) $(CFLAGS) -o $@ test_sigdb.c ../src/sigdb.c ../src/match.c
test_policy: test_policy.c ../src/policy.c ../src/sigdb.c ../src/policy.h ../src/sigdb.h
	$(CC) $(CFLAGS) -o $@ test_policy.c ../src/policy.c ../src/sigdb.c
test_nft: test_nft.c ../src/nft.c ../src/nft.h
	$(CC) $(CFLAGS) -o $@ test_nft.c ../src/nft.c

test_feed: test_feed.c ../src/feed.c ../src/nft.c ../src/feed.h
	$(CC) $(CFLAGS) -o $@ test_feed.c ../src/feed.c ../src/nft.c

test_apply: test_apply.c ../src/apply.c ../src/nft.c ../src/apply.h
	$(CC) $(CFLAGS) -o $@ test_apply.c ../src/apply.c ../src/nft.c

test_afpush: test_afpush.c ../src/afpush.c ../src/policy.c ../src/sigdb.c ../src/afpush.h
	$(CC) $(CFLAGS) -o $@ test_afpush.c ../src/afpush.c ../src/policy.c ../src/sigdb.c

test_observe: test_observe.c ../src/observe.c ../src/observe.h
	$(CC) $(CFLAGS) -o $@ test_observe.c ../src/observe.c

test_nflog_raw: test_nflog_raw.c ../src/nflog_raw.c ../src/nflog_raw.h
	$(CC) $(CFLAGS) -o $@ test_nflog_raw.c ../src/nflog_raw.c

test_canary: test_canary.c ../src/canary.c ../src/apply.c ../src/nft.c
	$(CC) $(CFLAGS) -o $@ test_canary.c ../src/canary.c ../src/apply.c ../src/nft.c

test_offload: test_offload.c ../src/offload.c ../src/apply.c ../src/nft.c
	$(CC) $(CFLAGS) -o $@ test_offload.c ../src/offload.c ../src/apply.c ../src/nft.c

test_neigh: test_neigh.c ../src/neigh.c ../src/observe.c ../src/neigh.h
	$(CC) $(CFLAGS) -o $@ test_neigh.c ../src/neigh.c ../src/observe.c

# SNI extraction and TCP reassembly: the FreeBSD/OPNsense port's new parsing
# layer. See the freebsd-payload-filtering skill for why these exist.
test_sni: test_sni.c ../src/sni.c ../src/sni.h
	$(CC) $(CFLAGS) -o $@ test_sni.c ../src/sni.c

test_reassembly: test_reassembly.c ../src/reassembly.c ../src/reassembly.h ../src/sni.c
	$(CC) $(CFLAGS) -o $@ test_reassembly.c ../src/reassembly.c ../src/sni.c

# Links libpcap because bpf_filter()/bpf_validate() are the interpreter this
# program is EXECUTED against. Without that, the test would only be checking
# compilation -- and a BPF program that is never run against real bytes is a
# guess, which is exactly how the fixed-offset version shipped broken.
#
# The header that defines struct bpf_insn and the opcode constants differs by
# platform (FreeBSD: <net/bpf.h> in base; Linux: nothing in base, <pcap/bpf.h>
# from libpcap-devel). PCAP_CFLAGS lets a Linux developer point at it, and
# pkg-config finds libpcap's own prefix when it is not in the default path.
PCAP_CFLAGS ?= $(shell pkg-config --cflags libpcap 2>/dev/null)
PCAP_LDFLAGS ?= $(shell pkg-config --libs libpcap 2>/dev/null)
ifeq ($(PCAP_LDFLAGS),)
PCAP_LDFLAGS := -lpcap
endif

test_bpf_tls: test_bpf_tls.c ../src/bpf_tls.h
	$(CC) $(CFLAGS) $(PCAP_CFLAGS) -o $@ test_bpf_tls.c $(PCAP_LDFLAGS)

test_polcfg: test_polcfg.c ../src/polcfg.c ../src/policy.c ../src/sigdb.c ../src/polcfg.h
	$(CC) $(CFLAGS) -o $@ test_polcfg.c ../src/polcfg.c ../src/policy.c ../src/sigdb.c

# nDPI is optional for the host suite: it is a target dependency, and a
# developer without it should still be able to run the other 529 checks. When
# absent the dpi tests SKIP and say so -- they are never silently omitted.
NDPI_PREFIX ?=
ifneq ($(NDPI_PREFIX),)
NDPI_CFLAGS := -I$(NDPI_PREFIX)/include
NDPI_LDFLAGS := -L$(NDPI_PREFIX)/lib -lndpi -lm -lpthread
else
NDPI_CFLAGS := $(shell pkg-config --cflags libndpi 2>/dev/null)
NDPI_LDFLAGS := $(shell pkg-config --libs libndpi 2>/dev/null)
endif
HAVE_NDPI := $(if $(NDPI_LDFLAGS),yes,no)

test_dpi: test_dpi.c ../src/dpi.c ../src/observe.c ../src/dpi.h
	$(CC) $(CFLAGS) $(NDPI_CFLAGS) -o $@ test_dpi.c ../src/dpi.c \
		../src/observe.c $(NDPI_LDFLAGS)

dpi_replay: dpi_replay.c ../src/dpi.c ../src/observe.c ../src/dpi.h
	$(CC) $(CFLAGS) $(NDPI_CFLAGS) -o $@ dpi_replay.c ../src/dpi.c \
		../src/observe.c $(NDPI_LDFLAGS)

test_appblock: test_appblock.c ../src/appblock.c ../src/dpi.c ../src/observe.c \
		../src/sigdb.c ../src/match.c ../src/policy.c ../src/afpush.c
	$(CC) $(CFLAGS) $(NDPI_CFLAGS) -o $@ test_appblock.c ../src/appblock.c \
		../src/dpi.c ../src/observe.c ../src/sigdb.c ../src/match.c \
		../src/policy.c ../src/afpush.c $(NDPI_LDFLAGS)

check: $(BINS)
	@echo "-- LINUX-ONLY, not built here: $(LINUX_BINS)"
	@echo "   afpush.c/flowlog.c include <linux/netlink.h>; on FreeBSD the"
	@echo "   replacement path is bpf_tls.h + ng_sni.c, covered above."
ifeq ($(HAVE_NDPI),yes)
	@$(MAKE) --no-print-directory test_dpi test_appblock
	@echo "-- test_dpi"; ./test_dpi || exit 1
	@echo "-- test_appblock"; ./test_appblock || exit 1
else
	@echo "-- test_dpi SKIPPED: libndpi not found."
	@echo "   Set NDPI_PREFIX=/path/to/ndpi or install libndpi-dev."
	@echo "   The scope decision (QUIC must never be name-hashed) and the"
	@echo "   enforcement split are NOT covered by this run."
endif
	@for b in $(BINS); do echo "-- $$b"; ./$$b || exit 1; done
clean:
	rm -f $(BINS) $(LINUX_BINS) test_dpi test_appblock dpi_replay

test_flowlog: test_flowlog.c ../src/flowlog.c ../src/appblock.c ../src/match.c ../src/sigdb.c ../src/observe.c ../src/afpush.c ../src/policy.c
	$(CC) $(CFLAGS) -o $@ test_flowlog.c ../src/flowlog.c ../src/appblock.c ../src/match.c ../src/sigdb.c ../src/observe.c ../src/afpush.c ../src/policy.c
