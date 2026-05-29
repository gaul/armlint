// Integration fixture for check_widening_mul_add_sub_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) Canonical: smull ; add Rd=Xt, Rn=Xt, Rm=Xc.
    smull   x8, w0, w1
    add     x8, x8, x2             // -> smaddl x8, w0, w1, x2

    // 2) Commutativity: add Rd=Xt, Rn=Xc, Rm=Xt.
    smull   x8, w0, w1
    add     x8, x2, x8             // -> smaddl x8, w0, w1, x2

    // 3) SUB with Rm=Xt (foldable to SMSUBL).
    smull   x8, w0, w1
    sub     x8, x2, x8             // -> smsubl x8, w0, w1, x2

    // 4) UMULL + ADD.
    umull   x8, w0, w1
    add     x8, x8, x2             // -> umaddl x8, w0, w1, x2

    // 5) UMULL + SUB with Rm=Xt (foldable to UMSUBL).
    umull   x8, w0, w1
    sub     x8, x2, x8             // -> umsubl x8, w0, w1, x2

    // 6) Accumulator shares its number with a multiply operand: the
    //    accumulator reads the full x0, the multiply reads w0 (low half
    //    of the same unmodified register).
    smull   x8, w0, w1
    add     x8, x8, x0             // -> smaddl x8, w0, w1, x0

    // 7) NEG consumer -> SMNEGL / UMNEGL.
    smull   x8, w0, w1
    neg     x8, x8                 // -> smnegl x8, w0, w1
    umull   x8, w0, w1
    neg     x8, x8                 // -> umnegl x8, w0, w1

    // Negatives:
    // N1) W-form consumer: the 64-bit product can't fold into a 32-bit ADD.
    smull   x8, w0, w1
    add     w8, w8, w2

    // N2) SUB with Rn=Xt (Xt - Xc, not SMSUBL's Xc - Xt).
    smull   x8, w0, w1
    sub     x8, x8, x2

    // N3) S-variant (no flag-setting long MAC).
    smull   x8, w0, w1
    adds    x8, x8, x2

    // N4) Rd != Xt (product alive after the ADD).
    smull   x8, w0, w1
    add     x9, x8, x2

    // N5) Accumulator = Xt aliasing: add x8, x8, x8.
    smull   x8, w0, w1
    add     x8, x8, x8

    // N6) Intervening instruction.
    smull   x8, w0, w1
    add     x5, x5, x6             // unrelated
    add     x8, x8, x2

    // N7) Real SMADDL (Ra != XZR) is not the SMULL alias.
    smaddl  x8, w0, w1, x3
    add     x8, x8, x2

    ret
