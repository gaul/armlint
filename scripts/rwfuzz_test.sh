#!/usr/bin/env bash
#
# Run armlint's advice: tools/rwfuzz applies every finding's rewrite to
# random programs and runs original and rewrite side by side (see its
# header). `all` plants every family and must run findings of at least
# RWFUZZ_MIN_KINDS names; every other mode then runs RWFUZZ_MODE_PROGRAMS,
# for its own plants and special cases. A mode with a control
# arm must also see some rewrite armlint refused change a result: a
# harness that had stopped seeing differences would pass everything
# else. Exit status: 0 passed, 1 a check failed, 2 the test could not
# run (no rwfuzz binary, not an AArch64 host).
#
#   RWFUZZ_PROGRAMS   programs for `all` (default 20000)
#   RWFUZZ_MODE_PROGRAMS  programs for each other mode (default a tenth
#                     of RWFUZZ_PROGRAMS)
#   RWFUZZ_SEED       seed (default 0: the same programs every run)
#   RWFUZZ_JOBS       worker processes (default 1); what rwfuzz prints
#                     does not depend on it
#   RWFUZZ_MIN_KINDS  the floor on the kinds `all` runs (default 150)
#   RWFUZZ_CC         the compiler driver rwfuzz assembles with
#                     (default cc)

set -eu

cd "$(dirname "$0")/.."
RWFUZZ=./tools/rwfuzz

case "$(uname -m)" in
    arm64|aarch64) ;;
    *)
        echo "rwfuzz_test: the programs run natively, and this host is $(uname -m)" >&2
        exit 2
        ;;
esac
if [ ! -x "$RWFUZZ" ]; then
    echo "rwfuzz_test: $RWFUZZ not found; run 'make tools/rwfuzz' first" >&2
    exit 2
fi

PROGRAMS=${RWFUZZ_PROGRAMS:-20000}
SEED=${RWFUZZ_SEED:-0}
JOBS=${RWFUZZ_JOBS:-1}
MIN_KINDS=${RWFUZZ_MIN_KINDS:-150}
SHORT=${RWFUZZ_MODE_PROGRAMS:-$((PROGRAMS / 10 > 0 ? PROGRAMS / 10 : 1))}
MODES=$("$RWFUZZ" 2>&1 | sed -n 's/^modes: //p')
if [ -z "$MODES" ]; then
    echo "rwfuzz_test: $RWFUZZ lists no modes" >&2
    exit 2
fi

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

FAIL=0
run_mode() {
    local mode=$1
    shift
    local cmd=("$RWFUZZ" -s "$SEED" -j "$JOBS" "$@" "$mode")
    echo "== ${cmd[*]}"
    set +e
    "${cmd[@]}" >"$T/out" 2>&1
    local rc=$?
    set -e
    cat "$T/out"
    if [ "$rc" -ne 0 ]; then
        echo "  FAIL    $mode: rwfuzz exited $rc"
        FAIL=1
        return
    fi
    local diffs
    diffs=$(sed -n 's/^  control: .*, \([0-9][0-9]*\) changed the result$/\1/p' "$T/out")
    if [ -n "$diffs" ] && [ "$diffs" -eq 0 ]; then
        echo "  FAIL    $mode: no refused rewrite changed a result"
        FAIL=1
    fi
}

run_mode all -n "$PROGRAMS" -k "$MIN_KINDS"
for mode in $MODES; do
    if [ "$mode" != all ]; then
        run_mode "$mode" -n "$SHORT"
    fi
done

if [ "$FAIL" -ne 0 ]; then
    echo "rwfuzz: FAILED (replay: RWFUZZ_SEED=$SEED RWFUZZ_PROGRAMS=$PROGRAMS RWFUZZ_MODE_PROGRAMS=$SHORT $0)"
    exit 1
fi
echo "rwfuzz: passed"
