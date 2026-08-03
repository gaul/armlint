# Bare `make` builds both shipped artifacts. Without this the first
# target below (lib) would be the default, which builds libarmlint.a
# and silently leaves a stale armlint executable behind -- the driver
# in main.c is not part of the library.
.DEFAULT_GOAL := build

CFLAGS = -g -Wall -Wextra -fPIC -std=c11

CAPSTONE_CFLAGS_RAW := $(shell pkg-config --cflags capstone 2>/dev/null)
# Homebrew's capstone.pc sets includedir to .../include/capstone, which
# makes <capstone/capstone.h> unresolvable. Append a stripped form so the
# header resolves under either packaging convention.
CAPSTONE_CFLAGS := $(CAPSTONE_CFLAGS_RAW) $(patsubst %/capstone,%,$(CAPSTONE_CFLAGS_RAW))
CAPSTONE_LIBS := $(shell pkg-config --libs capstone 2>/dev/null)
ifeq ($(strip $(CAPSTONE_LIBS)),)
CAPSTONE_LIBS := -lcapstone
endif

%.o: %.c
	$(CC) $(CFLAGS) $(CAPSTONE_CFLAGS) -c $< -o $@

# The pattern rule above sees only the .c file, so a change to the
# shared header would otherwise not rebuild anything. Every object in
# the project includes armlint.h; the tools/ programs do not.
armlint.o main.o armlint_test.o: armlint.h

# The real file is the target so make can date-stamp it; `lib` stays
# as the phony alias the other targets and the docs refer to.
libarmlint.a: armlint.o
	ar -crs $@ $<

lib: libarmlint.a

armlint: armlint.o main.o
	$(CC) $(CFLAGS) armlint.o main.o $(CAPSTONE_LIBS) -o armlint

test: armlint.o armlint_test.o
	$(CC) $(CFLAGS) armlint.o armlint_test.o $(CAPSTONE_LIBS) -pthread -o armlint_test
	./armlint_test

# Snapshot-based integration suite under fixtures/. Each .s is
# assembled with clang -arch arm64 and diffed against the matching
# .expected. Skips cleanly on hosts without an arm64 toolchain.
integration-test: armlint
	./scripts/run_fixtures.sh

# Regenerate fixtures/*.expected from current armlint output -- use
# after an intentional behavior change, then review the diff before
# committing.
integration-test-regen: armlint
	./scripts/run_fixtures.sh regen

# Corpus-mining research utilities (see "Mining tools" in README.md);
# not part of the default build or test targets.
tools: tools/pairscan tools/defuse

tools/pairscan: tools/pairscan.c
	$(CC) $(CFLAGS) $(CAPSTONE_CFLAGS) $< $(CAPSTONE_LIBS) -o $@

tools/defuse: tools/defuse.c
	$(CC) $(CFLAGS) $(CAPSTONE_CFLAGS) $< $(CAPSTONE_LIBS) -o $@

# The default goal: everything that ships, without running the suites.
build: lib armlint

all: lib armlint test

clean:
	rm -f \
		armlint \
		armlint_test \
		libarmlint.a \
		tools/pairscan \
		tools/defuse \
		*.o

.PHONY: all build clean lib test integration-test integration-test-regen tools
