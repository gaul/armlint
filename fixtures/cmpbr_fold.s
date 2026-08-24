// Integration fixture for check_cmpbr_fold (run with -m cmpbr via the
// sidecar .flags file). Each pair is committed by the next block's
// compare, whose NZCV overwrite proves the deleted flags dead.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: signed register compare, GT -> CBGT.
    cmp     x1, x2
    b.gt    1f                      // -> cbgt x1, x2, 1f

    // Positive: W form, unsigned LS -> CBLS. The reversed conditions
    // are assembler pseudo-instructions over the same encodings, so
    // they fold like the direct ones.
    cmp     w3, w4
    b.ls    1f                      // -> cbls w3, w4, 1f

    // Positive: an immediate comparand inside CB's 6-bit window.
    cmp     x5, #63
    b.eq    1f                      // -> cbeq x5, #0x3f, 1f

    // Positive: CBGE stores imm-1, so its window runs 1..64.
    cmp     w6, #64
    b.ge    1f                      // -> cbge w6, #0x40, 1f

    // Positive: CBLE stores imm+1, so its window stops at 62.
    cmp     x7, #62
    b.le    1f                      // -> cble x7, #0x3e, 1f

    // Positive: GT survives a zero comparand -- no baseline
    // instruction tests "> 0" in one word.
    cmp     x8, #0
    b.gt    1f                      // -> cbgt x8, #0, 1f

    // Positive: `cmp Rn, xzr` is the register spelling of `cmp Rn, #0`
    // and reports as the immediate form, so no zero register is named.
    cmp     x9, xzr
    b.le    1f                      // -> cble x9, #0, 1f

    // Negative here, positive there: EQ after a zero compare is
    // check_cmp_zero_branch's CBZ, which needs no extension. The pair
    // is reported once, by that check.
    cmp     x10, #0
    b.eq    1f

    // Negative: MI reads a sign bit that no comparison of two values
    // reproduces; CB has no form for it (nor for PL/VS/VC).
    cmp     x11, x12
    b.mi    1f

    // Negative: the comparand is one past CB's 6-bit window.
    cmp     x13, #64
    b.eq    1f

    // Negative: CBLE stores imm+1, so #63 is one past its window --
    // the same comparand folds under EQ three blocks up.
    cmp     x14, #63
    b.le    1f

    // Negative: a shifted compare has no CB form (nor does an
    // extended-register one).
    cmp     x15, x16, lsl #3
    b.gt    1f

    // Negative: CMN compares against a negated operand, which CB's
    // unsigned comparand cannot express.
    cmn     x17, #4
    b.gt    1f

    // Negative: the compare's flags are read after the branch, so it
    // cannot be deleted.
    cmp     x18, x19
    b.gt    1f
    cset    w20, lt

1:  ret

    // Negative: the flags are read at the branch TARGET -- clang's
    // three-way comparator, which branches twice off one compare.
    // The fall-through half proves out (the RET below kills NZCV),
    // so only the target-side scan rejects this.
    cmp     x21, x22
    b.le    2f
    mov     w0, #1
    ret
2:  b.ge    3f
    mov     w0, #-1
3:  ret
