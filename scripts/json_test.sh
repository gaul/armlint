#!/usr/bin/env bash
#
# Driver test for --json: assemble one fixture, scan it both ways, and
# check that the JSON document parses, agrees with the human report's
# count, carries the fields the README documents, and that the modes
# whose output would interleave with it are refused. Exit status: 0
# passed, 1 a check failed, 2 the test could not run (no armlint
# binary, no clang able to assemble AArch64).

set -eu

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

if [ ! -x "$ROOT/armlint" ]; then
    echo "armlint binary not found at $ROOT/armlint; run 'make armlint' first" >&2
    exit 2
fi

case "$(uname -s)" in
    Darwin) CC_FLAGS=(-arch arm64) ;;
    Linux)
        if [ "$(uname -m)" = "aarch64" ]; then
            CC_FLAGS=()
        else
            CC_FLAGS=(--target=aarch64-linux-gnu)
        fi
        ;;
    *)
        echo "json_test: unsupported OS $(uname -s)" >&2
        exit 2
        ;;
esac

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

FIXTURE="$ROOT/fixtures/csel_decided.s"
if ! clang "${CC_FLAGS[@]}" -c -o "$T/fixture.o" "$FIXTURE" 2>"$T/cc.err"; then
    echo "json_test: clang ${CC_FLAGS[*]} -c cannot assemble AArch64" >&2
    sed 's/^/      /' "$T/cc.err" >&2
    exit 2
fi

FAIL=0
fail() {
    echo "  FAIL    $1"
    FAIL=1
}

# The human report, for the count and the exit status to agree with.
set +e
(cd "$T" && "$ROOT/armlint" fixture.o) >"$T/human.out" 2>/dev/null
human_rc=$?
(cd "$T" && "$ROOT/armlint" --json fixture.o) >"$T/out.json" 2>"$T/json.err"
json_rc=$?
set -e
human_n=$(sed -n 's/^\([0-9][0-9]*\) optimization opportunities in .*/\1/p' "$T/human.out")
[ -n "$human_n" ] || fail "human report has no total line"
[ "$human_rc" = "$json_rc" ] || fail "exit status differs: human $human_rc, --json $json_rc"
[ "$json_rc" = 1 ] || fail "--json on a fixture with findings exited $json_rc, not 1"
grep -q '^{"file": ' "$T/out.json" || fail "document does not open with the file"
grep -q 'Optimization opportunities by type' "$T/out.json" \
    && fail "by-type table leaked into the document"
grep -q 'optimization opportunities in' "$T/out.json" \
    && fail "summary tail leaked into the document"
grep -q '"check": "conditional select decided by known flags"' "$T/out.json" \
    || fail "the fixture's finding is missing"
grep -q "\"opportunities\": $human_n\$" "$T/out.json" \
    || fail "opportunities does not match the human report ($human_n)"

# Structural check where a JSON parser is at hand: the document
# parses, the array length agrees with the total, and every finding
# carries the documented fields with consistent values.
if command -v python3 >/dev/null 2>&1; then
    python3 - "$T/out.json" "$human_n" <<'PYEOF' || fail "structural check failed"
import json, sys
d = json.load(open(sys.argv[1]))
n = int(sys.argv[2])
assert d["file"] == "fixture.o", d["file"]
assert d["opportunities"] == n, (d["opportunities"], n)
assert len(d["findings"]) == n, "array length disagrees with the total"
assert isinstance(d["instructions"], int) and d["instructions"] > 0
assert d["skipped"] == 0, d["skipped"]
for f in d["findings"]:
    assert isinstance(f["vaddr"], int) and f["vaddr"] >= 0, f
    assert f["check"] and isinstance(f["detail"], str), f
    assert f["section"] in (".text", "__TEXT,__text"), f["section"]
    assert "slice" not in f, "a thin object has no slice"
    assert f["function"] == "_main", f
    assert f["function_offset"] == f["vaddr"], f
    assert f["length"] % 4 == 0 and f["length"] > 0, f
    assert len(f["bytes"]) == 2 * f["length"], f
    int(f["bytes"], 16)
    assert isinstance(f["text"], list) and f["text"], f
PYEOF
else
    echo "json_test: no python3, skipping the structural check" >&2
fi

# --json owns stdout, so the reports that would interleave with it are
# refused rather than silently dropped, and nothing is written.
for flag in -v -i -d -c; do
    set +e
    (cd "$T" && "$ROOT/armlint" --json "$flag" fixture.o) >"$T/combo.out" 2>"$T/combo.err"
    rc=$?
    set -e
    [ "$rc" = 1 ] || fail "--json $flag exited $rc, not 1"
    grep -q 'cannot be combined' "$T/combo.err" || fail "--json $flag: no refusal on stderr"
    [ -s "$T/combo.out" ] && fail "--json $flag wrote to stdout"
done

# A file the driver rejects leaves no half-written document behind.
set +e
"$ROOT/armlint" --json "$FIXTURE" >"$T/reject.out" 2>/dev/null
set -e
[ -s "$T/reject.out" ] && fail "--json wrote a partial document for a non-binary input"

if [ "$FAIL" -eq 0 ]; then
    echo "json: passed"
    exit 0
fi
echo "json: failed"
exit 1
