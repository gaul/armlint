#!/usr/bin/env bash
#
# Driver test for the ELF scan scope and reporting: the default
# restriction to the symbol table's function ranges and its -A
# override, the skipped-bytes line, and the exit codes. Fixtures are
# assembled at run time for an explicit ELF triple, which needs no
# sysroot or cross libc and so works on every host (the same argument
# run_fixtures.sh makes), and the checks grep the human report and
# parse the --json document. Exit status: 0 passed, 1 a check failed,
# 2 the test could not run (no armlint binary, no clang able to
# assemble AArch64 ELF).

set -eu

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

if [ ! -x "$ROOT/armlint" ]; then
    echo "armlint binary not found at $ROOT/armlint; run 'make armlint' first" >&2
    exit 2
fi

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

CC_FLAGS=(--target=aarch64-linux-gnu)

FAIL=0
fail() {
    echo "  FAIL    $1"
    FAIL=1
}

# assemble <name>: fixtures/<name>.s from the heredocs below into
# $T/<name>.o, or exit 2 -- an assembler that cannot build the
# fixtures is an environment error, not a test result.
assemble() {
    if ! clang "${CC_FLAGS[@]}" -c -o "$T/$1.o" "$T/$1.s" 2>"$T/cc.err"; then
        echo "driver_test: clang ${CC_FLAGS[*]} -c cannot assemble $1.s" >&2
        sed 's/^/      /' "$T/cc.err" >&2
        exit 2
    fi
}

# run <expected_rc> <args...>: run the driver from $T on a relative
# path, capture stdout and stderr separately, and check the exit code.
run() {
    local expected=$1
    shift
    set +e
    (cd "$T" && "$ROOT/armlint" "$@") >"$T/out" 2>"$T/err"
    local rc=$?
    set -e
    if [ "$rc" -ne "$expected" ]; then
        fail "armlint $* exited $rc, expected $expected"
    fi
}

expect() {   # expect <pattern> [description]: stdout must match
    grep -qE -- "$1" "$T/out" || fail "missing '${2:-$1}' in output of last run"
}

reject() {   # reject <pattern> [description]: stdout must not match
    grep -qE -- "$1" "$T/out" && fail "unexpected '${2:-$1}' in output of last run"
    return 0
}

expect_err() {   # expect_err <pattern>: stderr must match
    grep -qE -- "$1" "$T/err" || fail "missing '$1' on stderr of last run"
}

# One sized function symbol holding a finding (the same-operand CSEL,
# whose rewrite is unconditional), and the same finding again OUTSIDE
# its range: the default symbol-restricted scan masks the trailing
# words (they count as skipped, not as instructions) and -A does not.
cat >"$T/sized.s" <<'EOF'
    .text
    .globl f
    .type f, %function
f:
    csel x1, x2, x2, eq
    ret
    .size f, . - f
    csel x1, x2, x2, eq
    ret
EOF

# The same code under untyped labels: the table places no function,
# so nothing is excluded and the scan is the full sweep.
cat >"$T/untyped.s" <<'EOF'
    .text
    .globl f
f:
    csel x1, x2, x2, eq
    ret
g:
    csel x1, x2, x2, eq
    ret
EOF

assemble sized
assemble untyped

echo "symbol-range restriction:"
run 1 sized.o
expect '^       1  CSEL same-operand identity$' "one finding inside the function"
expect '^8 bytes skipped unlinted' "the excluded words in the skipped line"
expect '^scan restricted to 1 function symbol \(-A scans every byte\)$'
expect '^1 optimization opportunities in 2 instructions$'

run 1 -A sized.o
expect '^       2  CSEL same-operand identity$' "-A reaches the finding outside the function"
reject 'skipped unlinted' "-A skips nothing"
reject 'scan restricted' "-A prints no restriction"
expect '^2 optimization opportunities in 4 instructions$'

run 1 untyped.o
expect '^       2  CSEL same-operand identity$' "untyped labels restrict nothing"
reject 'scan restricted'

# The census is a description of the file and never restricts.
run 0 -i sized.o
expect '^ISA census: 4 instructions, 0 undecodable words skipped$'

# --json carries the restriction and the skipped count.
run 1 --json sized.o
expect '"restriction": \{"symbols": 1\},'
expect '"skipped": 8,'
expect '"opportunities": 1$'
run 1 --json -A sized.o
reject '"restriction"'
expect '"skipped": 0,'

# The verbose finding keeps its annotation under the restriction.
run 1 -v sized.o
expect 'CSEL same-operand identity at offset: 0x0 <f>:'

# -f NAME: two sized functions with one finding each, and a third
# finding in g only; "lint just g" sees g's two and nothing of f.
cat >"$T/two.s" <<'EOF'
    .text
    .globl f
    .type f, %function
f:
    csel x1, x2, x2, eq
    ret
    .size f, . - f
    .globl g
    .type g, %function
g:
    csel x3, x4, x4, eq
    mov x0, x0
    ret
    .size g, . - g
EOF
assemble two

echo "-f single-function scan:"
run 1 -f g two.o
expect '^       1  CSEL same-operand identity$'
expect '^       1  redundant MOV to self$'
expect "^scan restricted to function 'g': 1 site, 12 bytes$"
expect '^2 optimization opportunities in 3 instructions$'
reject 'scan restricted to 2 function symbols' "-f replaces the symbol restriction"
run 1 -f f two.o
expect '^1 optimization opportunities in 2 instructions$'
reject 'redundant MOV to self' "f does not hold g's finding"
run 1 -v -f g two.o
expect 'redundant MOV to self at offset: 0xc <g\+0x4>:'

run 1 --json -f g two.o
expect '"restriction": \{"function": "g", "sites": 1, "bytes": 12\},'
expect '"opportunities": 2$'

# The census under -f scans the function's slice alone, as a slice
# rather than through the mask: nothing reads as undecodable.
run 0 -i -f g two.o
expect '^ISA census: 3 instructions, 0 undecodable words skipped$'
expect "^  scan restricted to function 'g': 1 site, 12 bytes$"

# A name matching nowhere is a tool failure, and --json then leaves
# stdout empty rather than a document restricted to nothing.
run 2 -f nosuch two.o
expect_err "no function symbol named 'nosuch'"
run 2 --json -f nosuch two.o
[ -s "$T/out" ] && fail "--json -f nosuch wrote to stdout"
run 2 -A -f g two.o
expect_err 'mutually exclusive'

# Mach-O carries no symbol sizes, so -f reaches to the next anchor:
# the same functions under plain labels, assembled for arm64 Mach-O.
if [ "$(uname -s)" = "Darwin" ]; then
    grep -v '\.type\|\.size' "$T/two.s" >"$T/two_macho.s"
    if clang -arch arm64 -c -o "$T/two_macho.o" "$T/two_macho.s" 2>/dev/null; then
        run 1 -f g two_macho.o
        expect "^scan restricted to function 'g': 1 site, 12 bytes$"
        expect '^2 optimization opportunities in 3 instructions$'
        run 1 -f f two_macho.o
        expect '^1 optimization opportunities in 2 instructions$'
    fi
fi

if [ "$FAIL" -eq 0 ]; then
    echo "driver: passed"
    exit 0
fi
echo "driver: failed"
exit 1
