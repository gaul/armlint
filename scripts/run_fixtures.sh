#!/usr/bin/env bash
#
# Integration test harness: assemble each fixtures/*.s with clang
# -arch arm64, run armlint on the resulting Mach-O, and compare the
# output to the corresponding fixtures/*.expected file.
#
# Set MODE=regen as the first argument to write the .expected files
# from current armlint output instead of diffing -- use after an
# intentional behavior change.
#
# Exit status: 0 all fixtures passed, 1 at least one failed, 2 the
# suite could not run (no armlint binary, or no clang able to
# assemble AArch64). It never exits 0 without having run the
# fixtures.

set -eu

MODE="${1:-check}"

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

if [ ! -x "$ROOT/armlint" ]; then
    echo "armlint binary not found at $ROOT/armlint; run 'make armlint' first" >&2
    exit 2
fi

# Pick the right clang invocation for the host. We compile (-c) only:
# the linker step is unnecessary for armlint's analysis (it walks
# SHT_PROGBITS / __text sections in either an object or a linked
# binary) and avoids the macOS/Linux _main-vs-main entry-symbol
# difference.
#
# Output format differs: Mach-O .o on macOS, ELF .o on arm64 Linux.
# armlint accepts both and reports section-relative offsets, so the
# snapshot output is host-format-agnostic.
#
# The suite never skips itself on toolchain grounds. A skip that exits
# 0 is indistinguishable from a pass to make and to CI, so a runner
# missing clang would report success having run no fixture at all --
# the failure mode is a suite that looks green precisely when it
# tested nothing. Anything that stops the fixtures from being built is
# an environment error and exits 2 (as a missing armlint binary
# already does), leaving exit 1 to mean real test failures.
case "$(uname -s)" in
    Darwin)
        CC_FLAGS=(-arch arm64)
        ;;
    Linux)
        if [ "$(uname -m)" = "aarch64" ]; then
            CC_FLAGS=()
        else
            # clang ships every backend, and assembling .s into .o
            # needs no sysroot or cross libc, so naming the target is
            # enough to build the fixtures off an arm64 host.
            CC_FLAGS=(--target=aarch64-linux-gnu)
        fi
        ;;
    *)
        echo "run_fixtures: unsupported OS $(uname -s)" >&2
        exit 2
        ;;
esac

PROBE=$(mktemp -d)
trap 'rm -rf "$PROBE"' EXIT
cat > "$PROBE/probe.s" <<'EOF'
    .text
    .globl  _main
    .p2align 2
_main:
    ret
EOF
if ! probe_err="$(clang "${CC_FLAGS[@]}" -c -o "$PROBE/probe.o" \
        "$PROBE/probe.s" 2>&1)"; then
    echo "run_fixtures: clang ${CC_FLAGS[*]} -c cannot assemble AArch64" >&2
    echo "run_fixtures: the integration suite requires it; install clang" >&2
    printf '%s\n' "$probe_err" | sed 's/^/      /' >&2
    exit 2
fi

PASS=0
FAIL=0
SKIP=0
FAILED_NAMES=()

for s in "$ROOT"/fixtures/*.s; do
    name="$(basename "$s" .s)"
    expected="$ROOT/fixtures/$name.expected"
    obj="$PROBE/$name.o"
    actual="$PROBE/$name.actual"

    # A fixture may pin a Mach-O arch via a sidecar
    # fixtures/<name>.arch (e.g. "arm64e" to exercise the PAC audit's
    # arm64e auto-arm). This marks the fixture Mach-O-only, so it runs
    # on Darwin alone and only when the toolchain can build that arch.
    # Two reasons to reach for it: the fixture depends on a Mach-O
    # concept such as cpusubtype, or -- with a plain "arm64" -- its
    # source uses Mach-O operand syntax (sym@PAGE/@PAGEOFF) that no
    # ELF assembler accepts.
    fixture_cc_flags=("${CC_FLAGS[@]}")
    if [ -f "$ROOT/fixtures/$name.arch" ]; then
        read -r fx_arch < "$ROOT/fixtures/$name.arch"
        if [ "$(uname -s)" != "Darwin" ]; then
            printf "  skip    %s  (arch %s: Mach-O slice test, Darwin only)\n" \
                "$name" "$fx_arch"
            SKIP=$((SKIP + 1))
            continue
        fi
        fixture_cc_flags=(-arch "$fx_arch")
        if ! clang "${fixture_cc_flags[@]}" -c -o "$PROBE/archprobe.o" \
                "$PROBE/probe.s" >/dev/null 2>&1; then
            printf "  skip    %s  (clang -arch %s unavailable)\n" \
                "$name" "$fx_arch"
            SKIP=$((SKIP + 1))
            continue
        fi
    fi

    # A fixture that will not assemble is a bug in that fixture -- a
    # missing .arch marker on Mach-O-only operand syntax, say -- not a
    # reason to abandon the run. Under `set -e` an unguarded failure
    # here killed the script mid-loop, with no FAIL line and no
    # summary, so a single bad fixture silently hid every fixture
    # sorting after it. Report it as a failure and keep going.
    if ! asm_err="$(clang "${fixture_cc_flags[@]}" -c -o "$obj" "$s" 2>&1)"; then
        printf "  FAIL    %s  (assembly failed)\n" "$name"
        printf '%s\n' "$asm_err" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILED_NAMES+=("$name")
        continue
    fi
    # Snapshot the verbose output: it is the superset (the one-line
    # opportunities plus their disassembled instructions plus the
    # by-type summary), so it exercises all of the report formatting.
    # armlint exits with the finding count, so any positive result
    # would trip `set -e`; we want the output, not the exit code.
    #
    # A fixture may carry extra armlint flags in a sidecar
    # fixtures/<name>.flags file (e.g. "-m cssc" for feature-gated
    # checks); its whitespace-separated contents are passed through.
    EXTRA_FLAGS=()
    if [ -f "$ROOT/fixtures/$name.flags" ]; then
        read -r -a EXTRA_FLAGS < "$ROOT/fixtures/$name.flags"
    fi
    "$ROOT/armlint" -v "${EXTRA_FLAGS[@]+"${EXTRA_FLAGS[@]}"}" "$obj" > "$actual" || true

    if [ "$MODE" = "regen" ]; then
        cp "$actual" "$expected"
        printf "  regen   %s\n" "$name"
        PASS=$((PASS + 1))
        continue
    fi

    if [ ! -f "$expected" ]; then
        printf "  missing %s  (no .expected file -- run 'make integration-test-regen')\n" "$name"
        FAIL=$((FAIL + 1))
        FAILED_NAMES+=("$name")
        continue
    fi

    if diff -u "$expected" "$actual" > /dev/null; then
        printf "  ok      %s\n" "$name"
        PASS=$((PASS + 1))
    else
        printf "  FAIL    %s\n" "$name"
        diff -u "$expected" "$actual" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILED_NAMES+=("$name")
    fi
done

echo
SKIP_NOTE=""
if [ "$SKIP" -gt 0 ]; then
    SKIP_NOTE=", $SKIP skipped"
fi
if [ "$FAIL" -eq 0 ]; then
    echo "integration: $PASS passed$SKIP_NOTE"
    exit 0
else
    echo "integration: $PASS passed, $FAIL failed$SKIP_NOTE (${FAILED_NAMES[*]})"
    exit 1
fi
