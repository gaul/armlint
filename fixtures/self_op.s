// Integration fixture for check_self_op.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: AND Rd, Rs, Rs (shifted-register, Rn == Rm) -> MOV.
    and     x0, x1, x1

    // Positive: ORR Rd, Rs, Rs -> MOV.
    orr     x2, x3, x3

    // Positive: EOR Rd, Rs, Rs -> MOV Rd, XZR (zero).
    eor     x4, x5, x5

    // Positive: SUB Rd, Rs, Rs -> MOV Rd, XZR.
    sub     x6, x7, x7

    // Positive: BIC Rd, Rs, Rs -> MOV Rd, XZR.
    bic     x8, x9, x9

    // Positive: ORN Rd, Rs, Rs -> MOV Rd, #-1.
    orn     x10, x11, x11

    // Positive: EON Rd, Rs, Rs -> MOV Rd, #-1.
    eon     x12, x13, x13

    // Positive: W-form ANDs.
    and     w14, w15, w15

    // Negative: flag-setting variant -- the flag-set is the user's
    // intent.
    ands    x16, x17, x17

    // Negative: SUBS likewise excluded.
    subs    x18, x19, x19

    // Negative: Rn != Rm -- genuine operation.
    and     x20, x21, x22

    ret
