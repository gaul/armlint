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

lib: armlint.o
	ar -crs libarmlint.a $<

armlint: armlint.o main.o
	$(CC) $(CFLAGS) armlint.o main.o $(CAPSTONE_LIBS) -o armlint

test: armlint.o armlint_test.o
	$(CC) $(CFLAGS) armlint.o armlint_test.o $(CAPSTONE_LIBS) -o armlint_test
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

all: lib armlint test

clean:
	rm -f \
		armlint \
		armlint_test \
		libarmlint.a \
		*.o

.PHONY: all clean lib test integration-test integration-test-regen
