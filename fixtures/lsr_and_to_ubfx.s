// Integration fixture for check_lsr_and_to_ubfx.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: LSR + AND low-mask -> UBFX.
    //   x0 = (x1 >> 8) & 0xFF -> ubfx x0, x1, #8, #8.
    lsr     x0, x1, #8
    and     x0, x0, #0xFF           // -> ubfx x0, x1, #8, #8

    // Positive: wider mask, width capped at datasize - shift.
    //   x2 = (x3 >> 32) & 0xFFFFFFFF -> ubfx x2, x3, #32, #32.
    lsr     x2, x3, #32
    and     x2, x2, #0xFFFFFFFF     // -> ubfx x2, x3, #32, #32

    // Positive: W-form.
    lsr     w4, w5, #4
    and     w4, w4, #0xF            // -> ubfx w4, w5, #4, #4

    // Negative: AND mask is not a low-mask (not (1<<w)-1).
    lsr     x6, x7, #8
    and     x6, x6, #0xF0

    // Negative: consumer's Rn != LSR's Rd.
    lsr     x8, x9, #8
    and     x8, x10, #0xFF

    // Negative: intervening instruction.
    lsr     x11, x12, #8
    add     x20, x20, #1
    and     x11, x11, #0xFF

    ret
