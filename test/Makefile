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

check: $(BINS)
	@for b in $(BINS); do echo "-- $$b"; ./$$b || exit 1; done
clean:
	rm -f $(BINS)
