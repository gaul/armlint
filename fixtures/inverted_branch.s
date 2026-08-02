// Integration fixture for check_inverted_branch: a one-instruction
// conditional skip over an unconditional B folds to the single
// inverted branch. Neither instruction writes a register or a flag,
// so findings report immediately -- no committing instruction after
// each pair.

    .text
    .globl  _main
    .p2align 2
_main:
    // 1) b.eq over a forward b -> b.ne.
    b.eq    1f
    b       90f
1:  nop

    // 2) b.lt over a backward b -> b.ge.
2:  nop
    b.lt    3f
    b       2b
3:  nop

    // 3) cbz w3 -> cbnz w3.
    cbz     w3, 4f
    b       90f
4:  nop

    // 4) cbnz x5 -> cbz x5.
    cbnz    x5, 5f
    b       90f
5:  nop

    // 5) tbnz x4, #63 -> tbz x4, #63.
    tbnz    x4, #63, 6f
    b       90f
6:  nop

    // 6) tbz w1, #5 -> tbnz w1, #5.
    tbz     w1, #5, 7f
    b       90f
7:  nop

    // Negatives:
    // N1) AL has no inverse.
    .inst   0x5400004e              // b.al .+8
    b       90f
    nop

    // N2) BC.cond would lose its Armv8.8 hint under the fold.
    .inst   0x54000050              // bc.eq .+8
    b       90f
    nop

    // N3) A skip of more than one instruction is real control flow.
    b.eq    8f
    nop
    b       90f
8:  nop

    // N4) BL writes x30: a conditional skip of a call stays.
    b.eq    9f
    bl      90f
9:  nop

    // N5) A register-31 compare skip is a constant condition.
    cbz     wzr, 10f
    b       90f
10: nop

    // N6) A side entry onto the B: that path expects an
    //     unconditional transfer, which the merged branch is not.
    b.eq    11f
12: b       90f
11: nop
    b       12b

90: ret
