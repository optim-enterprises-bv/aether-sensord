# Host-side unit tests. No OpenWrt toolchain, no device, no nDPI.
CFLAGS ?= -std=gnu11 -Wall -Wextra -Werror -O1 -g -D_GNU_SOURCE
BINS = test_sigdb test_policy test_nft test_feed test_apply test_afpush \
       test_observe test_nflog_raw test_polcfg
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
	rm -f $(BINS) test_dpi test_appblock dpi_replay
