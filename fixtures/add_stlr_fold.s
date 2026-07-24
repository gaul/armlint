// Integration fixture for check_add_stlr_fold (gated on -m lrcpc2).

    .text
    .globl  _main
    .p2align 2
_main:
    // Canonical volatile-store shape: the address temp is overwritten
    // before any read, so the ADD folds into STLUR's unscaled slot.
    add     x16, x0, #8
    stlr    w1, [x16]
    mov     x16, #0

    // X-form data, larger offset, still inside 0..255.
    add     x16, x2, #248
    stlr    x3, [x16]
    mov     x16, #0

    // Byte and half-word forms; the unscaled slot is alignment-free.
    add     x16, x0, #3
    stlrb   w1, [x16]
    mov     x16, #0
    add     x16, x0, #3
    stlrh   w1, [x16]
    mov     x16, #0

    // Zero store through WZR.
    add     x16, x0, #12
    stlr    wzr, [x16]
    mov     x16, #0

    // SP base.
    add     x16, sp, #16
    stlr    w1, [x16]
    mov     x16, #0

    // Negative: out of the positive unscaled range.
    add     x16, x0, #256
    stlr    w1, [x16]
    mov     x16, #0

    // Negative: the stored data register is the address temp -- the
    // folded store would read the deleted sum.
    add     x16, x0, #8
    stlr    x16, [x16]
    mov     x16, #0

    // Negative: LDAR is deliberately not rewritten -- LDAPUR's
    // acquire-RCpc is weaker than LDAR's RCsc, which the STLR/LDAR
    // sequentially-consistent mappings rely on.
    add     x16, x0, #8
    ldar    w1, [x16]
    mov     x16, #0

    // Negative: the address temp is read again -- the ADD stays.
    add     x16, x0, #8
    stlr    w1, [x16]
    add     x4, x16, #1
    mov     x16, #0

    // Negative: side entry -- the store is a branch target, so the
    // folded form would skip the ADD on the branched path.
    cbz     w5, 1f
    add     x16, x0, #8
1:
    stlr    w1, [x16]
    mov     x16, #0

    ret
