// Integration fixture for check_csel_decided.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) LLVM's shape: the compare repeated after the branch that read
    //    it, then a CSET of it. The second compare's flags were never
    //    branched on, and the first branch's fall-through settles them.
    cmp     x0, #7
    b.ne    1f
    cmp     x0, #7
    cset    w1, eq
1:
    ret

    // 2) A compare of a known value: EQ holds, so the select is a MOV.
    mov     x0, #7
    cmp     x0, #7
    csel    x1, x2, x3, eq
    ret

    // 3) A register a CBZ proved nonzero, then a fresh compare: NE
    //    holds.
    cbz     x0, 9f
    cmp     x0, #0
    csel    x1, x2, x3, ne
    ret

    // 4) TST never sets C, so HI never holds: the else operand.
    tst     w0, #1
    csel    w1, w2, w3, hi
    ret

    // 5) The else operations: CSINC adds one, CSINV inverts, CSNEG
    //    negates; a ZR else operand is the constant.
    mov     x0, #7
    cmp     x0, #8
    csinc   x1, x2, x3, eq
    csinv   x4, x5, x6, eq
    csneg   x7, x8, x9, eq
    cinc    x10, x11, eq
    cset    w12, eq
    ret

    // Negatives:
    // 6) Open flags.
    cmp     x0, x1
    csel    x2, x3, x4, eq
    ret

    // 7) A select on flags a branch already tested: the Spectre shape.
    cmp     x0, x1
    b.ne    9f
    csel    x2, x3, xzr, eq
    ret

    // 8) check_csel_self's identity, and a discarded result.
    mov     x0, #7
    cmp     x0, #7
    csel    x1, x2, x2, eq
    csel    xzr, x2, x3, eq
    ret

    // 9) A side entry onto the select.
    mov     x0, #7
    cmp     x0, #7
2:
    csel    x1, x2, x3, eq
    cbz     x5, 2b
9:
    ret
