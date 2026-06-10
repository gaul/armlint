// Integration fixture for check_cmp_zero_branch.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: CMP Rn, #0 ; B.EQ -> CBZ. The deferred-finding
    // mechanism requires a forward stopper (here, the function-end
    // RET clobbers nothing further so the fold is sound).
    cmp     x0, #0
    b.eq    1f

    // Positive: CMP Rn, XZR ; B.NE -> CBNZ.
    cmp     x1, xzr
    b.ne    1f

    // Positive: TST Rn, Rn ; B.EQ -> CBZ.
    tst     x2, x2
    b.eq    1f

    // Positive: CMP Rn, #0 ; B.MI -> TBNZ Rn, #63 (sign-bit branch
    // fold, V == 0 after CMP-zero).
    cmp     x3, #0
    b.mi    1f

    // Negative: CMP with non-zero immediate is not the zero-test form.
    cmp     x4, #1
    b.eq    1f

    // Negative: B.LO/B.HS after CMP-zero are constant-valued (C is
    // always 1, so LO is never taken, HS always) -- dead-branch
    // territory, not a register-test rewrite.
    cmp     x5, #0
    b.lo    1f

    // Positive: CMP Rn, #0 ; B.HI -> CBNZ. Subtracting zero never
    // borrows, so C == 1 and HI (C && !Z) reduces to NE.
    cmp     x6, #0
    b.hi    1f

    // Positive: CMP Rn, #0 ; B.LS -> CBZ (LS = !C || Z reduces to EQ).
    cmp     x7, #0
    b.ls    1f

    // Negative: TST Rn, Rn ; B.HI -- ANDS clears C, so HI after it is
    // never taken; not the CBNZ rewrite.
    tst     x8, x8
    b.hi    1f

1:  ret
