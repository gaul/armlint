// Integration fixture for check_zero_cmp_to_s_variant. Every
// positive also fires the CMP/TST + B.cond -> CBZ/CBNZ fold -- the
// two findings offer alternative rewrites, like the sibling
// redundant-CMP check's overlap.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) Shifted-register ADD: the CMP recomputes N/Z that ADDS
    //    would set for free.
    add     x0, x1, x2
    cmp     x0, #0
    b.eq    1f                      // -> adds x0, x1, x2 (drop cmp)

    // 2) SUB + B.NE.
    sub     x0, x1, x2
    cmp     x0, #0
    b.ne    1f                      // -> subs x0, x1, x2

    // 3) Immediate form, W.
    add     w0, w1, #16
    cmp     w0, #0
    b.eq    1f                      // -> adds w0, w1, #16

    // 4) Extended-register form.
    add     x0, x1, w2, uxtw
    cmp     x0, #0
    b.eq    1f                      // -> adds x0, x1, w2, uxtw

    // 5) AND + TST: flag-exact (TST and ANDS both pin C = V = 0).
    and     w0, w1, w2
    tst     w0, w0
    b.eq    1f                      // -> ands w0, w1, w2

    // 6) AND immediate.
    and     x0, x1, #0xff
    cmp     x0, #0
    b.ne    1f                      // -> ands x0, x1, #0xff

    // 7) BIC.
    bic     w0, w1, w2
    cmp     w0, #0
    b.eq    1f                      // -> bics w0, w1, w2

    // 8) NEG alias (SUB from ZR): the flag-setting twin is NEGS.
    neg     x0, x1
    cmp     x0, #0
    b.eq    1f                      // -> negs x0, x1

    // Negatives (only the CBZ fold, or nothing, fires):
    // N1) CMP of a different register.
    add     x0, x1, x2
    cmp     x5, #0
    b.eq    1f

    // N2) Width mismatch (W ALU, X CMP).
    add     w0, w1, w2
    cmp     x0, #0
    b.eq    1f

    // N3) ORR has no S-variant twin; the CMP must stay.
    orr     x0, x1, x2
    cmp     x0, #0
    b.eq    1f

    // N4) Downstream NZCV reader: the CSEL after the branch reads
    //     C/V territory, so the deferred finding is discarded (the
    //     CBZ fold's scan suppresses too).
    add     x0, x1, x2
    cmp     x0, #0
    b.eq    1f
    csel    x5, x6, x7, hs

1:  ret
