// Integration fixture for FJCVTZS (FEAT_JSCVT) as an NZCV writer: Z set
// when the conversion was exact, all four flags clear otherwise.
// Capstone 5 models no flag write for it, so armlint classifies it
// itself.

    .arch   armv8.3-a
    .text
    .globl  _main
    .p2align 2
_main:
    // Negatives:
    // 1) V8's Float64ToInt32 deoptimization test. The FJCVTZS rewrites
    //    the flags the first B.NE decided, so the second is live.
    cmp     w1, #3
    b.ne    9f
    fjcvtzs w0, d0
    b.ne    9f
    ret

    // 2) A join of a path that knows the flags pass EQ with one that
    //    ran an FJCVTZS: at the join NE may still pass.
    cmp     w1, #3
    b.eq    2f
    fjcvtzs w0, d0
2:
    b.ne    9f
    ret

    // Positives:
    // 3) N is never set after an FJCVTZS.
    fjcvtzs w0, d0
    b.mi    9f
    ret

    // 4) A repeated B.NE reads what the first decided.
    fjcvtzs w0, d0
    b.ne    9f
    b.ne    9f
    ret

    // 5) A compare whose flags an FJCVTZS overwrites unread: the
    //    CMP+B.NE folds into CBNZ, since nothing reads its flags past
    //    the FJCVTZS.
    cmp     w1, #0
    b.ne    9f
    fjcvtzs w0, d0
    b.ne    9f
    ret
9:
    ret
