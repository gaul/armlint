// Integration fixture for check_cmp_cmn_w.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) librustc_driver's shape: the high word compared with
    //    UINT32_MAX. x8 and the flags die on both edges.
    lsr     x1, x0, #32
    mov     w8, #-1
    cmp     x1, x8
    b.ne    1f
    mov     x8, #0
    cmp     x2, #3
1:
    mov     x8, #1
    cmn     x2, #3
    ret

    // 2) A W copy zero-extends; HS reads C, which the fold keeps.
    mov     w1, w0
    mov     w9, #-2
    cmp     x1, x9
    cset    w0, hs
    mov     x9, #0
    cmp     x2, #3
    ret

    // 3) k = 0x10000 encodes shifted: cmn w1, #0x10, lsl #12.
    ldr     w1, [x0]
    mov     w8, #0xffff0000
    cmp     x1, x8
    csel    x0, x2, x3, lo
    ldr     x8, [x5]
    cmp     x2, #4
    ret

    // 4) An X-form ORR constant, an EQ select, a CCMP on NE.
    and     x1, x0, #0xffffffff
    mov     x8, #0xffffffff
    cmp     x1, x8
    csel    x0, x2, x3, eq
    ldr     x8, [x5]
    ccmp    x2, #3, #0, ne
    ret

    // Negatives:
    // 5) A reader of N or V.
    lsr     x1, x0, #32
    mov     w8, #-1
    cmp     x1, x8
    b.lt    9f
    mov     x8, #0
    cmp     x2, #3
    ret

    // 6) The constant feeds a second compare, so its MOV stays.
    lsr     x8, x6, #32
    mov     w10, #-1
    cmp     x8, x10
    cset    w11, ne
    lsr     x9, x7, #32
    cmp     x9, x10
    cset    w10, ne
    ret

    // 7) The compared register's top half is unknown.
    mov     w8, #-1
    cmp     x1, x8
    b.ne    9f
    mov     x8, #0
    cmp     x2, #3
    ret

    // 8) k = 4097 does not encode.
    lsr     x1, x0, #32
    mov     w8, #-4097
    cmp     x1, x8
    b.ne    9f
    mov     x8, #0
    cmp     x2, #3
9:
    ret
