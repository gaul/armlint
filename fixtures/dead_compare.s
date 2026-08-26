// Integration fixture for check_dead_compare.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) Two compares back to back. The first writes flags the second
    //    throws away before anything reads them.
    cmp     x1, #8
    cmp     x1, #6
    b.eq    1f

    // 2) Flag-neutral instructions in the gap do not matter -- the
    //    scan walks past them.
    cmp     w2, #3
    nop
    nop
    cmp     w2, #5
    b.lo    1f

    // 3) TST is a compare too (ANDS into the zero register), and the
    //    killer only has to write all four flags -- an S-variant
    //    keeping its result does.
    tst     w3, #0x10
    subs    x11, x12, x13
    b.ne    1f

    // 4) CCMP has no destination field at all, so a CCMP whose flags
    //    are discarded is equally dead. The CMP in front of it is
    //    NOT: a CCMP reads the flags it conditionally rewrites.
    cmp     x4, #1
    ccmp    x5, #2, #0, eq
    cmp     x4, #7
    b.gt    1f

    // Negatives:
    // N1) A reader before the overwrite.
    cmp     x6, #1
    b.eq    1f
    cmp     x6, #2
    b.ne    1f

    // N2) A call. The PCS leaves NZCV undefined across it, which is
    //     enough for the folds that keep the compare but not for
    //     deleting it outright, so the scan refuses.
    cmp     x7, #1
    bl      2f
2:
    cmp     x7, #2
    b.ne    1f

    // N3) A return, refused for the same reason.
    cmp     x8, #1
    ret

    // N4) An unsafe terminator: the flags may be live at a target the
    //     scan does not follow.
    cmp     x9, #1
    b       1f
    cmp     x9, #2
    b.ne    1f

    // N5) An S-variant keeping its result is not a compare. Dropping
    //     its S bit is size- and cycle-neutral, so this half of the
    //     dead-flag family is left alone.
    subs    x14, x15, #1
    cmp     x16, #7
    b.ne    1f

    // N6) FCMP is destination-free but excluded: deleting it would
    //     also drop the FPSR cumulative exception bits it sets.
    fcmp    d0, d1
    cmp     x17, #3

1:
    ret
