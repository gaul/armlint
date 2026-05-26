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

# Probe whether the host can assemble + link arm64 Mach-O. On macOS
# clang ships with the arm64 backend; Linux requires a cross-toolchain
# and produces ELF instead. Skip cleanly so the suite still works for
# contributors who can't assemble locally.
PROBE=$(mktemp -d)
trap 'rm -rf "$PROBE"' EXIT
cat > "$PROBE/probe.s" <<'EOF'
    .text
    .globl  _main
    .p2align 2
_main:
    ret
EOF
if ! clang -arch arm64 -o "$PROBE/probe" "$PROBE/probe.s" >/dev/null 2>&1; then
    echo "skip: clang -arch arm64 not available on this host" >&2
    exit 0
fi

PASS=0
FAIL=0
FAILED_NAMES=()

for s in "$ROOT"/fixtures/*.s; do
    name="$(basename "$s" .s)"
    expected="$ROOT/fixtures/$name.expected"
    bin="$PROBE/$name"
    actual="$PROBE/$name.actual"

    clang -arch arm64 -o "$bin" "$s" 2>/dev/null
    # armlint exits with the finding count, so any positive result
    # would trip `set -e`; we want the output, not the exit code.
    "$ROOT/armlint" "$bin" > "$actual" || true

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
