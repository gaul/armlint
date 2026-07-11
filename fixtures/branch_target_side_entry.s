// Integration fixture for the branch-target (side-entry) gate shared
// by check_add_ldr_imm_offset and check_add_ldr_str_pre_indexed: a
// direct branch that lands on the memory op of a would-be 2->1 fold
// enters past the ADD, so the merged instruction would apply the
// immediate (or bump the base) on a path that never added it. The
// N-cases must produce no findings; the P-cases keep the same shapes
// without a side entry (or with the branch landing on the ADD, which
// runs the whole pair) and must still be flagged.

    .text
    .globl  _main
    .p2align 2
_main:
    // N1: rotated byte-scan loop -- while (isspace(*p)) p++. The
    // initial branch enters at the LDRB, past the increment, so the
    // pre-indexed rewrite must not fire.
    b       Lentry1
Lstep1:
    add     x8, x8, #1
Lentry1:
    ldrb    w9, [x8]
    cmp     w9, #0x20
    b.eq    Lstep1

    // N2: list-walk re-entry -- p = p->next with next at offset 0.
    // The back edge lands on the LDR (dest == base), so the
    // unsigned-offset rewrite must not fire.
    add     x8, x8, #0x10
Lentry2:
    ldr     x8, [x8]
    cbz     x8, Ldone2
    b       Lentry2
Ldone2:

    // P1: pre-indexed shape with no side entry -- still flagged.
    add     x10, x10, #1
    ldrb    w11, [x10]

    // P2: unsigned-offset shape whose ADD (not the LDR) is the branch
    // target -- entry runs the whole pair, still flagged.
Ladd3:
    add     x12, x12, #0x10
    ldr     x12, [x12]
    b       Ladd3

    ret
