// Integration fixture for check_const_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) A bool's zero-extension of a constant tail duplication put in
    //    front of it.
    mov     w8, #0
    and     w0, w8, #1
    ret

    // 2) Arithmetic on two constants.
    mov     x9, #3
    mov     x8, #5
    add     x10, x9, x8
    ret

    // 3) A shift of a constant, and a negation.
    mov     w1, #6
    lsl     w4, w1, #3
    neg     w5, w1
    ret

    // 4) A value a branch pinned: CBNZ fell through, so x0 is zero.
    cbnz    x0, 9f
    add     x1, x0, #5
    ret

    // 5) A value a compare pinned: x0 is 7 past the B.NE.
    cmp     x0, #7
    b.ne    9f
    add     x1, x0, #1
    ret

    // 6) A multiply and a bitfield extract of constants.
    mov     x1, #3
    mov     x2, #4
    mul     x3, x1, x2
    mov     w6, #0xff
    ubfx    w7, w6, #4, #4
    ret

    // 6b) Results the known bits fix although no input is exact: w4 is
    //     confined to bits 7:4, so a shift by 8 empties it; the TBZ
    //     fell through, so bit 3 of w8 is set; AND with a zero is zero
    //     whatever the other operand holds.
    and     w4, w5, #0xf0
    lsr     w9, w4, #8
    tbz     w8, #3, 9f
    and     w0, w8, #8
    mov     x11, #0
    and     x12, x13, x11
    ret

    // 7) A result its register already holds: x9 stays 0.
    mov     x9, #0
    mov     x20, #0
    sub     x9, x9, x20
    ret

    // Negatives:
    // 8) A result no one instruction materializes.
    mov     x9, #0x1234
    lsl     x10, x9, #20
    ret

    // 9) An input a MOVK built (a JIT patch site's shape).
    mov     x9, #1
    movk    x9, #1, lsl #16
    add     x10, x9, #1
    ret

    // 10) Shapes other checks own: Rs, Rs; Rm = ZR; a copy; ADD #0; an
    //     in-place zero-extension.
    mov     x9, #5
    eor     x10, x9, x9
    orr     x11, x9, xzr
    mov     x12, x9
    add     x13, x9, #0
    mov     w14, #5
    and     w14, w14, #0xff
    ret

    // 11) A flag setter, and an unknown input.
    mov     x9, #5
    adds    x10, x9, #1
    add     x11, x15, #1
    ret

    // 11b) Bits the operation leaves unknown: bits 3:0 of the result
    //      are w10's bits 7:4.
    and     w10, w5, #0xf0
    add     x1, x2, x3
    lsr     w11, w10, #4
    ret

    // 12) A side entry onto the operation.
    mov     x9, #5
1:
    add     x10, x9, #1
    cbz     x0, 1b
9:
    ret
