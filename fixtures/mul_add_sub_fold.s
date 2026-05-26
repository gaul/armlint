// Integration fixture for check_mul_add_sub_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) Canonical: mul ; add Rd=Rt, Rn=Rt, Rm=Rc.
    mul     x3, x1, x2
    add     x3, x3, x4              // -> madd x3, x1, x2, x4

    // 2) Commutativity: add Rd=Rt, Rn=Rc, Rm=Rt.
    mul     x3, x1, x2
    add     x3, x4, x3              // -> madd x3, x1, x2, x4

    // 3) W form.
    mul     w3, w1, w2
    add     w3, w3, w4              // -> madd w3, w1, w2, w4

    // 4) SUB with Rm=Rt (foldable to MSUB).
    mul     x3, x1, x2
    sub     x3, x4, x3              // -> msub x3, x1, x2, x4

    // 5) MUL with Rn=Rd: mul x3, x3, x2; add x3, x3, x4.
    mul     x3, x3, x2
    add     x3, x3, x4              // -> madd x3, x3, x2, x4

    // 6) Square: mul x3, x1, x1.
    mul     x3, x1, x1
    add     x3, x3, x4              // -> madd x3, x1, x1, x4

    // Negatives:
    // N1) SUB with Rn=Rt (xt - xc, NOT MSUB).
    mul     x3, x1, x2
    sub     x3, x3, x4

    // N2) S-variant (no MADD/MSUB flag form).
    mul     x3, x1, x2
    adds    x3, x3, x4

    // N3) Rd != Rt (MUL result alive after).
    mul     x3, x1, x2
    add     x5, x3, x4

    // N4) Accumulator = Rt aliasing: add x3, x3, x3.
    mul     x3, x1, x2
    add     x3, x3, x3

    // N5) ADD with shift on Rm.
    mul     x3, x1, x2
    add     x3, x3, x4, lsl #1

    // N6) Intervening instruction.
    mul     x3, x1, x2
    add     x5, x5, x6              // unrelated
    add     x3, x3, x4

    ret
