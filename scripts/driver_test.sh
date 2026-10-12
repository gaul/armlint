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

# The by-function table: g holds two findings, f one, and under -A
# the words past sized.o's one function land in no range.
echo "by-function table:"
run 1 two.o
expect '^Optimization opportunities by function:$'
expect '^       2  g$'
expect '^       1  f$'
reject 'outside every function range'
run 1 -A sized.o
expect '^       1  f$'
expect '^       1  outside every function range$'
# Only the global label anchors: a local untyped ELF label is an
# inner jump target, not a function, so f's unsized reach covers both.
run 1 untyped.o
expect '^       2  f$'
reject '  g$'
run 1 -f g two.o
expect '^       2  g$'
reject '^       1  f$' "-f tallies only the scanned function"
run 1 --json two.o
reject 'by function' "the table stays out of the document"

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

# -b: the BTI landing-pad verification needs a linked binary -- the
# evidence it reads (the entry point, init arrays, dynamic symbols,
# relocations) exists only after the link -- and no host here is
# assumed to link AArch64 ELF, so a minimal shared object is written
# directly. mkelf.py lays out one function per evidence class, each a
# landing pad (or none) followed by RET, and the metadata that
# evidences it: e_entry with a PT_INTERP, an .init_array slot, a
# GLOB_DAT and a JUMP_SLOT relocation against exported symbols, an
# IRELATIVE resolver, a RELATIVE pointer to a sized function and one
# to a bare label (address-taken only, which must not count), a
# packed RELR slot, and a GNU property note when asked for. The pad
# letters are c, j, jc, p (paciasp) and n (none).
cat >"$T/mkelf.py" <<'EOF'
import struct, sys

out, note = sys.argv[1], sys.argv[2]
pads = sys.argv[3].split(",")   # entry,init,export,got,plt,ifunc,rel,label,relr
PAD = {"c": 0xd503245f, "j": 0xd503249f, "jc": 0xd50324df,
       "p": 0xd503233f, "n": 0xd503201f}
RET = 0xd65f03c0
BASE = 0x10000
names = ["f_entry", "f_init", "f_export", "f_got", "f_plt", "f_ifunc",
         "f_rel", "f_label", "f_relr"]
exported = (("f_export", 2), ("f_got", 2), ("f_plt", 2), ("f_ifunc", 10))

# Sections in file order: (name, type, flags, size, link, info, align,
# entsize). Sizes are fixed up front so one layout pass gives every
# address; the payloads are built afterwards from those addresses.
secs = []
def add(name, typ, flags, size, link=0, info=0, align=4, entsize=0):
    secs.append([name, typ, flags, size, link, info, align, entsize])
    return len(secs)   # 1-based: 0 is the null section

def table(strings):
    blob = b"\0"
    offs = {}
    for n in strings:
        offs[n] = len(blob)
        blob += n.encode() + b"\0"
    return blob, offs

interp = b"/lib/ld-linux-aarch64.so.1\0"
dynstr, dyn_off = table([n for n, _ in exported])
strtab, str_off = table(names)
s_interp = add(".interp", 1, 2, len(interp), align=1)
s_text = add(".text", 1, 6, 8 * len(names))
s_dynsym = add(".dynsym", 11, 2, 24 * (1 + len(exported)), info=1, align=8,
               entsize=24)
s_dynstr = add(".dynstr", 3, 2, len(dynstr), align=1)
secs[s_dynsym - 1][4] = s_dynstr
s_data = add(".data.rel.ro", 1, 3, 24, align=8)
s_init = add(".init_array", 14, 3, 8, align=8, entsize=8)
s_rela = add(".rela.dyn", 4, 2, 5 * 24, link=s_dynsym, align=8, entsize=24)
s_relr = add(".relr.dyn", 19, 2, 8, align=8, entsize=8)
notedata = b""
if note != "none":
    desc = struct.pack("<IIII", 0xc0000000, 4, int(note, 0), 0)
    notedata = struct.pack("<III", 4, len(desc), 5) + b"GNU\0" + desc
    add(".note.gnu.property", 7, 2, len(notedata), align=8)
s_symtab = add(".symtab", 2, 0, 24 * (1 + len(names)), info=1, align=8,
               entsize=24)
s_strtab = add(".strtab", 3, 0, len(strtab), align=1)
secs[s_symtab - 1][4] = s_strtab
shstr, sh_off = table([sec[0] for sec in secs] + [".shstrtab"])
s_shstrtab = add(".shstrtab", 3, 0, len(shstr), align=1)

# Layout: ELF header, one program header, the sections in order, each
# aligned; an allocated section's address is BASE + its file offset.
off = 64 + 56
layout = []
for sec in secs:
    off = (off + sec[6] - 1) // sec[6] * sec[6]
    layout.append(off)
    off += sec[3]
shoff = (off + 7) // 8 * 8
def vaddr(i):
    return BASE + layout[i - 1]

text_addr = vaddr(s_text)
addr = {n: text_addr + 8 * i for i, n in enumerate(names)}
data_addr = vaddr(s_data)
got_slot, plt_slot = data_addr + 8, data_addr + 16

def sym(name_off, bind, typ, shndx, value, size):
    return struct.pack("<IBBHQQ", name_off, (bind << 4) | typ, 0, shndx,
                       value, size)
def rela(where, typ, symi, addend):
    return struct.pack("<QQq", where, (symi << 32) | typ, addend)
dindex = {n: i + 1 for i, (n, _) in enumerate(exported)}
payload = {
    s_interp: interp,
    s_text: b"".join(struct.pack("<II", PAD[p], RET) for p in pads),
    s_dynsym: sym(0, 0, 0, 0, 0, 0) + b"".join(
        sym(dyn_off[n], 1, t, s_text, addr[n], 8) for n, t in exported),
    s_dynstr: dynstr,
    s_data: struct.pack("<QQQ", addr["f_relr"], 0, 0),
    s_init: struct.pack("<Q", addr["f_init"]),
    s_rela: (rela(got_slot, 1025, dindex["f_got"], 0)
             + rela(plt_slot, 1026, dindex["f_plt"], 0)
             + rela(got_slot, 1032, 0, addr["f_ifunc"])
             + rela(got_slot, 1027, 0, addr["f_rel"])
             + rela(got_slot, 1027, 0, addr["f_label"])),
    s_relr: struct.pack("<Q", data_addr),
    s_symtab: sym(0, 0, 0, 0, 0, 0) + b"".join(
        sym(str_off[n], 1, 0 if n == "f_label" else 2, s_text, addr[n], 8)
        for n in names),
    s_strtab: strtab,
    s_shstrtab: shstr,
}
if notedata:
    payload[s_symtab - 1] = notedata

body = bytearray(shoff)
for i, sec in enumerate(secs):
    data = payload[i + 1]
    assert len(data) == sec[3], sec[0]
    body[layout[i]:layout[i] + len(data)] = data
shdrs = struct.pack("<IIQQQQIIQQ", *([0] * 10))
for i, sec in enumerate(secs):
    name, typ, flags, size, link, info, align, entsize = sec
    shdrs += struct.pack("<IIQQQQIIQQ", sh_off[name], typ, flags,
                         vaddr(i + 1) if flags & 2 else 0, layout[i], size,
                         link, info, align, entsize)
ehdr = (b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
        + struct.pack("<HHIQQQIHHHHHH", 3, 183, 1, addr["f_entry"], 64, shoff,
                      0, 64, 56, 1, 64, len(secs) + 1, s_shstrtab))
phdr = struct.pack("<IIQQQQQQ", 3, 4, layout[s_interp - 1], vaddr(s_interp),
                   vaddr(s_interp), len(interp), len(interp), 1)
body[0:64 + 56] = ehdr + phdr
open(out, "wb").write(bytes(body) + shdrs)
EOF

if command -v python3 >/dev/null 2>&1; then
    echo "-b BTI landing pads:"
    mkelf() {   # mkelf <name> <note bits|none> <pads>
        python3 "$T/mkelf.py" "$T/$1" "$2" "$3" || fail "mkelf $1 failed"
    }
    # Declared and padded: every evidenced target lands on a BTI c, a
    # BTI jc, or a PACIASP; the bare label's pointer is not evidence.
    mkelf good.so 0x3 c,c,p,jc,c,c,c,n,c
    run 0 -b good.so
    expect '^BTI: BTI property note present; all 8 indirect branch targets land on a BTI c$'
    expect '^PAC: pac-ret declared alongside BTI$'
    reject 'f_label'
    # Declared, two misses: the GOT target has no pad, the PLT target a
    # BTI j, the wrong flavour for a call. Printed without -v.
    mkelf bad.so 0x1 c,c,c,n,j,c,c,n,c
    run 1 -b bad.so
    expect 'indirect branch target missing BTI c: 0x[0-9a-f]+ <f_got> \(GOT relocation\)'
    expect 'indirect branch target has BTI j, which admits no call: 0x[0-9a-f]+ <f_plt> \(PLT relocation\)'
    expect '^BTI: BTI property note present; 2 of 8 indirect branch targets lack a BTI c, some carrying a BTI j'
    expect '^PAC: no pac-ret in the property note despite BTI'
    # Padded but undeclared: the note the link lost.
    mkelf lost.so none c,c,c,c,c,c,c,n,c
    run 1 -b lost.so
    expect '^BTI: no BTI in the property note, but 8 of 8 indirect branch targets begin with a BTI c \(BTI annotation lost at link\?\)$'
    expect '^PAC: no pac-ret in the property note$'
    # Neither: not a BTI binary, nothing to hold it to.
    mkelf none.so none n,n,n,n,n,n,n,n,n
    run 0 -b none.so
    expect '^BTI: no BTI in the property note and no BTI landing pads; not a BTI binary$'
    # pac-ret alone, with GCS: reported, never a finding.
    mkelf pac.so 0x6 n,n,n,n,n,n,n,n,n
    run 0 -b pac.so
    expect '^PAC: pac-ret declared without BTI'
    expect '^GCS: guarded control stack declared$'
    # The block prints after the scan's summary and shares the exit
    # status with it; the census takes -b too.
    run 1 -b -i bad.so
    expect '^ISA census:'
    expect '^BTI: BTI property note present; 2 of 8'
    # Refusals: a relocatable object, and --json.
    run 2 -b two.o
    expect_err 'requires a linked executable or shared object'
    run 2 --json -b good.so
    expect_err 'cannot be combined'
    if [ "$(uname -s)" = "Darwin" ]; then
        run 2 -b two_macho.o
        expect_err 'applies to ELF binaries'
    fi
else
    echo "driver_test: no python3, skipping the -b checks" >&2
fi

if [ "$FAIL" -eq 0 ]; then
    echo "driver: passed"
    exit 0
fi
echo "driver: failed"
exit 1
