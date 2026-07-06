// Integration fixture for check_fp_zero_to_movi.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: scalar zeroing through the zero register -- a
    // cross-file transfer that MOVI performs on the FP side.
    fmov    s0, wzr
    fmov    d1, xzr

    // Positive: converting integer zero always yields +0.0, the
    // all-zeros pattern.
    scvtf   d2, wzr
    ucvtf   s3, wzr

    // Positive: vector zeroing via a GPR broadcast keeps its
    // arrangement.
    dup     v4.4s, wzr
    dup     v5.2d, xzr
    dup     v6.8b, wzr

    // Positive: the zero built in a scratch register first -- the MOV
    // also dies, once the overwrite proves the register dead.
    mov     w8, #0
    fmov    s7, w8
    mov     w8, #1

    mov     w9, #0
    dup     v8.4s, w9
    mov     w9, #1

    // Negative: a nonzero broadcast is not a zeroing (MOVI's expanded
    // immediate could encode it, but constant DUPs are out of scope).
    mov     w10, #5
    dup     v9.4s, w10
    mov     w10, #0

    // Negative: the scratch register is read again before dying --
    // the MOV must stay.
    mov     w11, #0
    fmov    s10, w11
    add     w1, w11, w2

    ret
