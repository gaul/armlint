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

    // Positive: LSR pins the threshold sharper than the generic
    // W-form P=32 (P = 32-24 = 8), so masking to a byte is a no-op.
    lsr     w24, w25, #24
    uxtb    w24, w24

    // Positive: the extracted field is 4 bits wide (P = 4 <= C = 8).
    ubfx    w26, w27, #3, #4
    uxtb    w26, w26

    // Positive: X-form AND-imm bounds the value (P = 8): even the
    // 64-bit view is provably zero above bit 7.
    and     x28, x1, #0xff
    uxtb    w28, w28

    // Positive: MOVZ's value is known (0x12 -> P = 5).
    movz    w2, #0x12
    uxtb    w2, w2

    // Positive: CSET yields 0 or 1 (P = 1).
    cset    w4, eq
    and     w4, w4, #0x1

    // Negative: ORR-imm can propagate the source's high bits; only
    // the generic W-form threshold applies (P = 32 > 8).
    orr     w5, w6, #0xf
    uxtb    w5, w5

    ret
