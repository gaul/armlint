// Integration fixture for check_mov_shift_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives (the constant register dies at the trailing mov, so
    // the deferred finding emits):
    // 1) LSL.
    mov     x8, #5
    lsl     x0, x1, x8              // -> lsl x0, x1, #5
    mov     x8, #9

    // 2) LSR.
    mov     x8, #5
    lsr     x0, x1, x8              // -> lsr x0, x1, #5
    mov     x8, #9

    // 3) ASR, W-form.
    mov     w8, #7
    asr     w0, w1, w8              // -> asr w0, w1, #7
    mov     w8, #9

    // 4) ROR.
    mov     x8, #13
    ror     x0, x1, x8              // -> ror x0, x1, #13
    mov     x8, #9

    // 5) The register form shifts modulo the datasize: #67 on a
    //    64-bit shift folds to #3.
    mov     x8, #67
    lsl     x0, x1, x8              // -> lsl x0, x1, #3
    mov     x8, #9

    // 6) Structural kill: the shift overwrites the constant register.
    mov     x8, #5
    lsl     x8, x1, x8              // -> lsl x8, x1, #5

    // Negatives:
    // N1) Residue 0 (#64 mod 64) shifts by nothing -- a register
    //     copy, not a shift; degenerate.
    mov     x8, #64
    lsl     x0, x1, x8
    mov     x8, #9

    // N2) The shifted operand is the constant register: the rewrite
    //     would still read it.
    mov     x8, #5
    lsl     x0, x8, x8
    mov     x8, #9

    // N3) Fresh destination with no later kill: the constant is
    //     never proven dead, so nothing is emitted.
    mov     x9, #5
    lsl     x0, x1, x9

    ret
