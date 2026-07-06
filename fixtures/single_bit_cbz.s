// Integration fixture for check_single_bit_cbz.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: the canonical skip-one shape -- the branch target is
    // the instruction that overwrites the masked temp, so both edges
    // provably kill it.
    and     w8, w9, #0x10
    cbz     w8, 1f
    add     x1, x2, x3
1:  mov     w8, #0

    // Positive: bool test of bit 0 with CBNZ.
    and     w10, w11, #0x1
    cbnz    w10, 2f
    add     x1, x2, x3
2:  mov     w10, #0

    // Positive: UBFX single-bit extract.
    ubfx    w12, w13, #4, #1
    cbz     w12, 3f
    add     x1, x2, x3
3:  mov     w12, #0

    // Positive: sign bit via LSR #31.
    lsr     w14, w15, #31
    cbnz    w14, 4f
    add     x1, x2, x3
4:  mov     w14, #0

    // Positive: X-form high bit.
    and     x16, x17, #0x10000000000
    cbz     x16, 5f
    add     x1, x2, x3
5:  mov     x16, #0

    // Negative: the masked temp is read on the fall-through -- the
    // producer cannot be deleted.
    and     w19, w20, #0x10
    cbz     w19, 6f
    add     w1, w19, w2
6:  mov     w19, #0

    // Negative: the branch target lies beyond the overwrite, so the
    // taken path's liveness is unproven.
    and     w21, w22, #0x10
    cbz     w21, 7f
    mov     w21, #0
    add     x1, x2, x3
7:  ret
