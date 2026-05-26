// Integration fixture for check_redundant_zext.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: W-form ALU + UXTW. The W-form ADD zeros X[63:32].
    add     w0, w1, w2
    uxtw    x0, w0

    // Positive: W-form ALU + AND Xd, Xd, #0xFFFFFFFF.
    add     w3, w4, w5
    and     x3, x3, #0xFFFFFFFF

    // Positive: LDRB Wt + AND wd, wd, #0xFF. LDRB clears bits >= 8.
    ldrb    w6, [x7]
    and     w6, w6, #0xFF

    // Positive: LDRH Wt + AND wd, wd, #0xFFFF.
    ldrh    w8, [x9]
    and     w8, w8, #0xFFFF

    // Positive: LDRB Wt + UXTB Wd, Wd -- C=8 still redundant.
    ldrb    w10, [x11]
    uxtb    w10, w10

    // Positive: W-form ALU + MOV Wd, Wd (the self-MOV that
    // zero-extends X[63:32]).
    add     w12, w13, w14
    mov     w12, w12

    // Negative: producer is X-form -- bits 63..32 are NOT pre-zeroed.
    add     x15, x16, x17
    uxtw    x15, w15

    // Negative: LDRH producer (P=16) with UXTB consumer (C=8) --
    // the consumer is narrower, so it actually clears bits the
    // producer left non-zero.
    ldrh    w18, [x19]
    uxtb    w18, w18

    // Negative: consumer's Rd doesn't match producer's Rd.
    add     w20, w21, w22
    uxtw    x23, w20

    ret
