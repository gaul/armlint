// Integration fixture for check_neg_cbz.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: libcrypto's in-place shape. On the taken edge x = 0
    // and the NEG changed nothing; the fall-through overwrites w8.
    ldrb    w8, [x24, #6]
    neg     w8, w8
    cbz     w8, 1f
    mov     w8, #1
1:
    ret

    // Positive: in place with CBNZ -- only the target needs w8 dead;
    // the fall-through may read it.
    neg     w9, w9
    cbnz    w9, 2f
    str     w9, [x0]
    ret
2:
    ldr     w9, [x0]
    ret

    // Positive: out of place, both edges overwrite the result.
    neg     x10, x1
    cbz     x10, 3f
    mov     x10, #1
    ret
3:
    mov     x10, #2
    ret

    // Negative: the fall-through reads the negated value.
    neg     w11, w11
    cbz     w11, 4f
    add     w0, w11, #1
4:
    ret

    // Negative: out of place, the target reads it.
    neg     w12, w2
    cbz     w12, 5f
    mov     w12, #1
    ret
5:
    add     w0, w12, #1
    ret

    // Negative: NEGS writes the flags; a width mismatch; a shifted
    // source changes which values are zero.
    negs    w13, w13
    cbz     w13, 6f
    mov     w13, #1
6:
    neg     w14, w14
    cbz     x14, 7f
    mov     w14, #1
7:
    neg     w15, w3, lsl #1
    cbz     w15, 8f
    mov     w15, #1
8:
    ret
