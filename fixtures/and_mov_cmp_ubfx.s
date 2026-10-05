// Integration fixture for check_and_mov_cmp_ubfx.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) The UTF-16 high-surrogate test, the mask first.
    and     w9, w22, #0xfc00
    mov     w11, #0xd800
    cmp     w9, w11
    b.eq    1f                  // -> ubfx w9, w22, #10, #6 ; cmp w9, #0x36
    mov     w9, #0              // the masked register dead
    mov     w11, #0             // the constant register dead
    adds    w3, w4, w5          // NZCV dead
1:
    // 2) The constant first, the registers swapped in the CMP, one
    //    instruction between, and the RET proving NZCV dead last.
    mov     w8, #0xd800
    and     w9, w0, #0xfc00
    add     x1, x1, #1
    cmp     w8, w9
    b.ne    2f                  // -> ubfx w9, w0, #10, #6 ; cmp w9, #0x36
    mov     w8, #0
    mov     w9, #0
    ret
2:
    // 3) X form, a two-link chain, the shifted immediate form.
    and     x8, x0, #0xfffffffff000000
    mov     x9, #0x40000000000
    cmp     x8, x9
    b.hi    3f                  // -> ubfx x8, x0, #24, #36 ; cmp x8, #0x40, lsl #12
    adds    x8, x1, x2
    mov     x9, #0
3:
    // 4) A mask reaching the sign bit: an unsigned condition is fine.
    and     w8, w0, #0xffffc000
    mov     w9, #0x80000000
    cmp     w8, w9
    b.lo    4f                  // -> ubfx w8, w0, #14, #18 ; cmp w8, #0x20, lsl #12
    adds    w8, w1, w2
    mov     w9, #0
4:
    // 5) In place: the masked register is its own source.
    and     w9, w9, #0xfc00
    mov     w11, #0xd800
    cmp     w9, w11
    b.ne    5f                  // -> ubfx w9, w9, #10, #6 ; cmp w9, #0x36
    adds    w9, w1, w2
    mov     w11, #0
5:
    ret

    // Negatives:
    // 6) The constant fits the compare already (the sibling fold's).
    and     w9, w22, #0xf0
    mov     w11, #0x30
    cmp     w9, w11
    b.eq    9f
    adds    w9, w1, w2
    mov     w11, #0

    // 7) The shifted constant still does not fit.
    and     x8, x0, #0x7fffffffffffffff
    mov     x9, #0x7ff0000000000000
    cmp     x8, x9
    b.eq    9f
    adds    x8, x1, x2
    mov     x9, #0

    // 8) A signed condition over a mask that reaches the sign bit.
    and     w8, w0, #0xffffc000
    mov     w9, #0x80000000
    cmp     w8, w9
    b.lt    9f
    adds    w8, w1, w2
    mov     w9, #0

    // 9) The masked register read after the branch.
    and     w9, w22, #0xfc00
    mov     w11, #0xd800
    cmp     w9, w11
    b.eq    9f
    str     w9, [x0]
    adds    w9, w1, w2
    mov     w11, #0

    // 10) The masked register read between the AND and the CMP.
    and     w9, w22, #0xfc00
    str     w9, [x0]
    mov     w11, #0xd800
    cmp     w9, w11
    b.eq    9f
    adds    w9, w1, w2
    mov     w11, #0

    // 11) The mask is not one run of bits.
    and     w9, w22, #0xff00ff00
    mov     w11, #0x3400
    cmp     w9, w11
    b.eq    9f
    adds    w9, w1, w2
    mov     w11, #0

    // 12) The constant has bits outside the mask.
    and     w9, w22, #0xfc00
    mov     w11, #0xd801
    cmp     w9, w11
    b.eq    9f
    adds    w9, w1, w2
    mov     w11, #0

    // 13) A side entry between the producers and the CMP.
    and     w9, w22, #0xfc00
8:
    mov     w11, #0xd800
    cmp     w9, w11
    b.eq    9f
    adds    w9, w1, w2
    mov     w11, #0
    cbz     x0, 8b
9:
    ret
