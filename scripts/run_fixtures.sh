#!/usr/bin/env bash
#
# Integration test harness: assemble each fixtures/*.s with clang
# -arch arm64, run armlint on the resulting Mach-O, and compare the
# output to the corresponding fixtures/*.expected file.
#
# Set MODE=regen as the first argument to write the .expected files
# from current armlint output instead of diffing -- use after an
# intentional behavior change.

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
case "$(uname -s)" in
    Darwin)
        CC_FLAGS=(-arch arm64)
        ;;
    Linux)
        if [ "$(uname -m)" != "aarch64" ]; then
            echo "skip: not an arm64 host (use ubuntu-*-arm runner or a cross-toolchain)" >&2
            exit 0
        fi
        CC_FLAGS=()
        ;;
    *)
        echo "skip: unsupported OS $(uname -s)" >&2
        exit 0
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
if ! clang "${CC_FLAGS[@]}" -c -o "$PROBE/probe.o" "$PROBE/probe.s" \
        >/dev/null 2>&1; then
    echo "skip: clang ${CC_FLAGS[*]} -c failed on this host" >&2
    exit 0
fi

PASS=0
FAIL=0
FAILED_NAMES=()

for s in "$ROOT"/fixtures/*.s; do
    name="$(basename "$s" .s)"
    expected="$ROOT/fixtures/$name.expected"
    obj="$PROBE/$name.o"
    actual="$PROBE/$name.actual"

    clang "${CC_FLAGS[@]}" -c -o "$obj" "$s" 2>/dev/null
    # Snapshot the verbose output: it is the superset (the one-line
    # opportunities plus their disassembled instructions plus the
    # by-type summary), so it exercises all of the report formatting.
    # armlint exits with the finding count, so any positive result
    # would trip `set -e`; we want the output, not the exit code.
    "$ROOT/armlint" -v "$obj" > "$actual" || true

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
if [ "$FAIL" -eq 0 ]; then
    echo "integration: $PASS passed"
    exit 0
else
    echo "integration: $PASS passed, $FAIL failed (${FAILED_NAMES[*]})"
    exit 1
fi
