// Integration fixture for check_cset_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: CSET + CBNZ branches exactly when the condition held
    // -- b.eq -- and the branch target is the instruction that
    // overwrites the flag temp, so both edges provably kill it.
    cmp     w0, w1
    cset    w8, eq
    cbnz    w8, 1f
    add     x1, x2, x3
1:  mov     w8, #0

    // Positive: CBZ inverts the condition -- b.ge.
    cmp     w0, w1
    cset    w9, lt
    cbz     w9, 2f
    add     x1, x2, x3
2:  mov     w9, #0

    // Positive: X-form.
    cmp     x0, x1
    cset    x10, hi
    cbnz    x10, 3f
    add     x1, x2, x3
3:  mov     x10, #0

    // Positive: EOR #1 inverts the stored condition; overwriting the
    // temp itself, the pair collapses in place.
    cmp     w0, w1
    cset    w11, eq
    eor     w11, w11, #1

    // Positive: EOR #1 into a different register defers until the
    // temp dies.
    cmp     w0, w1
    cset    w12, hs
    eor     w13, w12, #1
    mov     w12, #0

    // Positive: NEG of the temp is CSETM.
    cmp     w0, w1
    cset    w14, mi
    neg     w14, w14

    // Negative: the temp is read on the fall-through -- the CSET
    // cannot be deleted.
    cmp     w0, w1
    cset    w15, eq
    cbnz    w15, 4f
    add     w1, w15, w2
4:  mov     w15, #0

    // Negative: the branch target lies beyond the overwrite, so the
    // taken path's liveness is unproven.
    cmp     w0, w1
    cset    w16, eq
    cbz     w16, 5f
    mov     w16, #0
    add     x1, x2, x3
5:  ret
