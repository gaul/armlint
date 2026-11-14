// Integration fixture for check_ext_shift_discard.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) Kotlin's packInts as ART compiles it: the high half's SXTW,
    // the low half's SXTW + AND, then the ORR that shifts the first
    // extension out.
    sxtw    x0, w0
    sxtw    x1, w2
    and     x1, x1, #0xffffffff
    orr     x0, x1, x0, lsl #32    // -> orr x0, x1, x0, lsl #32

    // 2) Adjacent EOR.
    sxtw    x3, w4
    eor     x3, x5, x3, lsl #40    // -> eor x3, x5, x4, lsl #40

    // 3) W-form SXTB, W-form AND.
    sxtb    w6, w7
    and     w6, w8, w6, lsl #24    // -> and w6, w8, w7, lsl #24

    // 4) Fresh destination; the MOV proves the extension dead.
    uxth    w9, w10
    orr     x11, x12, x9, lsl #48  // -> orr x11, x12, x10, lsl #48
    mov     x9, #5

    // Negatives:
    // N1) LSL #31 keeps a copy of the sign.
    sxtw    x13, w14
    orr     x13, x15, x13, lsl #31

    // N2) The extension is also the unshifted operand.
    sxtw    x16, w17
    orr     x16, x16, x16, lsl #32

    // N3) The source is overwritten in the gap.
    sxtw    x0, w1
    mov     w1, #3
    orr     x0, x2, x0, lsl #32

    // N4) LSR keeps the high bits.
    sxtw    x3, w4
    orr     x3, x5, x3, lsr #32

    // D1) The extension is read after the ORR: the consumer-only
    // rewrite, the extension stays.
    sxtw    x6, w7
    orr     x8, x9, x6, lsl #32
    add     x10, x6, #1
    mov     x6, #7

    // N5) Data in the gap ends the region.
    sxtw    x20, w21
    .word   0xffffffff
    orr     x20, x22, x20, lsl #32

    ret
