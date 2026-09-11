// Integration fixture for the -a imm audit (via the sidecar .flags
// file): materialized constants whose consumers have an immediate
// form the value cannot use. Nothing here is rewritable in place; the
// audit points at the constants, and the summary tallies them by
// value.

    .text
    .globl  _main
    .p2align 2
_main:
    // add/sub imm12: 16 MiB is one step past 0xfff << 12.
    movz    x16, #0x100, lsl #16
    cmp     x0, x16
    b.ne    9f

    // A two-instruction chain (V8's hole sentinel, 0x2fffd).
    movz    w16, #0xfffd
    movk    w16, #0x2, lsl #16
    cmp     w2, w16
    b.ne    9f

    // bitmask: 0xffffffa0 has a hole at bit 6; an X chain feeding a W
    // consumer is read through its low half; a byte mask such as 0xdf
    // widens to 0xffffffdf when the operand's upper bits are known
    // clear.
    movn    w17, #0x5f
    tst     w16, w17
    b.ne    9f
    movz    x11, #0x12
    tst     w9, w11
    b.ne    9f
    movz    w16, #0xdf
    and     w10, w22, w16

    // ccmp: imm5 stops at 31.
    movz    w16, #0x2d
    ccmp    w7, w16, #4, ne
    b.ne    9f

    // register-offset load: the index is beyond the scaled imm12 range.
    movz    x1, #0x1, lsl #16
    ldr     x0, [x2, x1]

    // Negatives: an encodable constant belongs to the sibling fold and
    // is silent here; an intervening instruction breaks adjacency.
    movz    w6, #0x9
    cmp     w5, w6
    b.ne    9f
    movz    x16, #0x100, lsl #16
    nop
    cmp     x0, x16
    cset    w0, ne
9:
    ret
