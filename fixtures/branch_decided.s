// Integration fixture for check_branch_decided.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) A constant: x8 is 1, so the CBZ never branches.
    mov     w8, #1
    cbz     x8, 9f
    ret

    // 2) llvm::Expected's flag tested twice: the TBZ always branches.
    ldr     w8, [sp, #8]
    tbnz    w8, #0, 9f
    str     w8, [x19]
    tbz     w8, #0, 9f
    ret

    // 3) A switch's compare tree ending in a compare its earlier
    //    branches decided: x1 is 5.
    cmp     x1, #6
    b.hs    9f
    cmp     x1, #4
    b.le    9f
    cmp     x1, #5
    b.eq    9f
    ret

    // 4) A compare repeated past the branch that read it.
    cmp     x0, #5
    b.eq    9f
    add     x2, x2, #1
    cmp     x0, #5
    b.eq    9f
    ret

    // 5) A second null check of an unchanged register.
    cbz     x23, 9f
    ldrb    w8, [x23, #8]
    cbz     x23, 9f
    ret

    // 6) The bit a TST found clear.
    tst     x0, #4
    b.ne    9f
    tbnz    w0, #2, 9f
    ret

    // 7) The sign bit of a zero-extended load.
    ldrh    w7, [x2]
    tbnz    w7, #31, 9f
    ret

    // 8) The range a byte load leaves.
    ldrb    w3, [x0]
    cmp     x3, #0xff
    b.hi    9f
    ret

    // 9) What TST alone decides: ANDS clears C.
    tst     w0, #1
    b.hs    9f
    ret

    // 10) A bound from a compare with a register holding a constant.
    mov     w9, #0x7fff
    cmp     w27, w9
    b.hs    9f
    cmp     w27, #8, lsl #12
    b.hs    9f
    ret

    // Negatives:
    // 11) A write between.
    cbz     x0, 9f
    mov     x0, x1
    cbz     x0, 9f
    ret

    // 12) A side entry: the second CBZ is a branch target.
    cbz     x0, 9f
1:
    cbz     x0, 9f
    b       1b

    // 13) A call between.
    cbz     x0, 9f
    bl      _main
    cbz     x0, 9f
    ret

    // 14) A MOVK sequence may be a JIT's patch site.
    mov     x2, #5
    movk    x2, #0xfffe, lsl #48
    cbz     w2, 9f
    ret

    // 15) A W zero test says nothing of the top half.
    cbnz    w0, 9f
    cbz     x0, 9f
    ret

    // 16) Another compare changed the flags.
    cmp     x0, #5
    b.eq    9f
    cmp     x1, #5
    b.eq    9f
    ret
9:
    ret
