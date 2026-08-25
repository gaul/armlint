// Integration fixture for check_and_lo32_mov.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives: both spellings keep only the low 32 bits, which is
    // what a W-form move already does -- every W write zeroes the
    // upper half of its X register.
    and     x0, x1, #0xffffffff         // -> mov w0, w1
    ubfx    x2, x3, #0, #32             // -> mov w2, w3

    // Negatives:
    // N1) Rd == Rn. Sound, but the rewrite would read "mov w4, w4",
    //     whose obvious follow-on is to delete it -- and that is a
    //     miscompile, the W-form move still zeroing bits 63:32. The
    //     in-place cases that really are deletable belong to
    //     check_redundant_zext, which says "delete", not "respell".
    and     x4, x4, #0xffffffff
    ubfx    x5, x5, #0, #32

    // N2) The width must be exactly 32: a narrower mask is a real
    //     extraction.
    and     x6, x7, #0xffff
    ubfx    x6, x7, #0, #16

    // N3) A non-zero lsb extracts from the middle, not the low word.
    ubfx    x8, x9, #4, #32

    // N4) W-form: there is nothing above bit 31 left to clear.
    and     w10, w11, #0xffff

    // N5) AND-immediate reads Rd = 31 as SP, while the rewrite's
    //     ORR Wd, WZR, Wm reads it as WZR. The encodings disagree
    //     about register 31, so an SP destination can never fold.
    and     sp, x12, #0xffffffff

    // N6) UBFM's Rd = 31 really is ZR: the result is discarded, so the
    //     instruction is dead outright rather than respellable.
    ubfx    xzr, x13, #0, #32

    // N7) A ZR source makes either op a zero materialization rather
    //     than a truncation.
    and     x14, xzr, #0xffffffff
    ubfx    x15, xzr, #0, #32

    ret
