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

    // Negative: 0xFFFFFFFF is the all-ones-at-width case, excluded
    // from the bitmask-immediate definition.
    movz    w4, #0xFFFF
    movk    w4, #0xFFFF, lsl #16

    ret
