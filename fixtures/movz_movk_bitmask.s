// Integration fixture for check_movz_movk_bitmask.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: 0x66666666 is a valid 32-bit bitmask immediate
    // (repeating-4 pattern) -- the two-instruction MOVZ+MOVK could
    // be ORR Wd, WZR, #0x66666666.
    movz    w0, #0x6666
    movk    w0, #0x6666, lsl #16

    // Positive: 0x0F0F0F0F0F0F0F0F is a 64-bit bitmask immediate.
    movz    x1, #0x0F0F
    movk    x1, #0x0F0F, lsl #16
    movk    x1, #0x0F0F, lsl #32
    movk    x1, #0x0F0F, lsl #48

    // Negative: 0x56781234 is not a bitmask immediate (arbitrary).
    movz    w2, #0x1234
    movk    w2, #0x5678, lsl #16

    // Negative: single MOVZ -- nothing to shrink.
    movz    w3, #0x6666

    // Positive: 0xFFFFFFFF is the all-ones-at-width case, excluded
    // from the bitmask-immediate definition -- but a single
    // MOVN w4, #0 builds it, so the two-instruction chain is long.
    movz    w4, #0xFFFF
    movk    w4, #0xFFFF, lsl #16

    // Positive: 0xFFFFFFFF12345678 is not a bitmask immediate, but
    // two of its four halfwords are 0xFFFF -- the MOVN-based chain
    // (movn x5, #0xA987 ; movk x5, #0x1234, lsl #16) reaches it in
    // two instructions instead of four.
    movz    x5, #0x5678
    movk    x5, #0x1234, lsl #16
    movk    x5, #0xFFFF, lsl #32
    movk    x5, #0xFFFF, lsl #48

    // Positive: 0xFFFFEDCB is a single MOVN w6, #0x1234.
    movz    w6, #0xEDCB
    movk    w6, #0xFFFF, lsl #16

    // Negative: 0xFFFFFFFF5678EDCB -- not a bitmask immediate, and
    // the MOVN-based chain is already minimal (two halfwords differ
    // from 0xFFFF).
    movn    x7, #0x1234
    movk    x7, #0x5678, lsl #16

    // The rest are shorter as LLVM builds them (expandMOVImm), by forms
    // beyond the move-wide minimum.

    // Positive: 0xFFF8800000000001, SpiderMonkey's Int32Value(1): a
    // bitmask ORR, then one MOVK.
    movz    x8, #0x1
    movk    x8, #0x8000, lsl #32
    movk    x8, #0xFFF8, lsl #48

    // Positive: 0xFFF8800000000008: two bitmask immediates ANDed.
    movz    x9, #0x8
    movk    x9, #0x8000, lsl #32
    movk    x9, #0xFFF8, lsl #48

    // Positive: 0x0005000500050005: two bitmask immediates ORed.
    movz    x10, #0x5
    movk    x10, #0x5, lsl #16
    movk    x10, #0x5, lsl #32
    movk    x10, #0x5, lsl #48

    // Positive: 0x8000001800000017: two bitmask immediates EORed.
    movz    x11, #0x17
    movk    x11, #0x18, lsl #32
    movk    x11, #0x8000, lsl #48

    // Positive: 0xFFF880000000001D: MOVN, then EON of the register
    // with itself shifted left 46.
    movz    x12, #0x1D
    movk    x12, #0x8000, lsl #32
    movk    x12, #0xFFF8, lsl #48

    // Positive: 0x00000000FF7FFFFF in an X chain: one W MOVN, which
    // zero-extends.
    movz    x13, #0xFFFF
    movk    x13, #0xFF7F, lsl #16

    // Positive: 0x1204110112041101: three for four, the low half ORed
    // into the high.
    movz    x14, #0x1101
    movk    x14, #0x1204, lsl #16
    movk    x14, #0x1101, lsl #32
    movk    x14, #0x1204, lsl #48

    // Positive: 0x12345678EDCBA987: three for four, MOVN + MOVK, then
    // EOR of the register with itself shifted left 32.
    movz    x15, #0xA987
    movk    x15, #0xEDCB, lsl #16
    movk    x15, #0x5678, lsl #32
    movk    x15, #0x1234, lsl #48

    // Negative: 0x0123456789ABCDEF -- four halfwords no form beats.
    movz    x16, #0xCDEF
    movk    x16, #0x89AB, lsl #16
    movk    x16, #0x4567, lsl #32
    movk    x16, #0x0123, lsl #48

    ret
