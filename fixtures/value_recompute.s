// Integration fixture for check_value_recompute.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) The irregexp lookahead shape: input+pos re-formed while x16,
    //    x0 and x2 are all untouched -- the checks in between only
    //    read the tracked registers (including the register-offset
    //    load through the pair) and the conditional branches leave
    //    the fall-through path's registers alone.
    add     x16, x0, x2
    ldrb    w1, [x16, #1]
    cmp     w1, #0x78
    b.ne    9f
    ldrb    w1, [x0, x2]
    cmp     w1, #0x30
    b.ne    9f
    add     x16, x0, x2
    ldrb    w1, [x16, #2]
    ret

    // 2) A JIT scratch constant rematerialized after its use.
    mov     x16, #0x8ca0
    add     x4, x25, x16
    ldur    x2, [x29, #-0x40]
    mov     x16, #0x8ca0
    ret

    // 3) One value, two spellings: x8 = 0xffffffff either way.
    mov     w8, #-1
    str     w8, [x1]
    mov     x8, #0xffffffff
    ret

    // 4) A compare repeated past the branch that read it.
    cmp     x26, #5
    b.lo    9f
    strb    w19, [x8, #4]
    cmp     x26, #5
    b.hi    9f
    ret

    // 5) A copy restored across a branch: x0 still equals x19.
    mov     x19, x0
    ldr     x1, [x1, #0x18]
    cbz     x1, 9f
    mov     x0, x19
    ret

    // 6) Equal through a copy: x3 already holds x1 + 8.
    mov     x2, x1
    add     x3, x2, #8
    str     x3, [x5]
    add     x3, x1, #8
    ret

    // 7) The stack pointer resynchronized from an unchanged x20.
    mov     sp, x20
    str     x5, [x20]
    mov     x0, x5
    mov     sp, x20
    ret

    // 8) A flag setter repeated with both of its results unchanged.
    adds    x10, x11, x12
    b.eq    9f
    adds    x10, x11, x12
    ret

    // 9) ADRP of the page x8 holds, reported apart as a relink fix.
    //    Emit ADRP via .long to avoid Mach-O/ELF relocation-syntax
    //    differences (`@PAGE` is Mach-O-only); both words are
    //    `adrp x8` of this instruction's own page.
    .long   0x90000008              // adrp x8, page0
    ldr     x9, [x8]
    .long   0x90000008              // adrp x8, page0
    ret

    // Negatives:
    // 10) A write to a source register kills the tracked sum.
    add     x17, x1, x4
    movz    x1, #1
    add     x17, x1, x4
    ret

    // 11) A label on the recompute is a side entry: the entering path
    //     never executed the first ADD.
    add     x21, x22, x23
1:
    add     x21, x22, x23
    cbz     x9, 1b
    ret

    // 12) A destination that is also an input changes per execution.
    add     x3, x3, x4
    add     x3, x3, x4
    ret

    // 13) Another compare changed the flags in between.
    cmp     x0, #5
    b.eq    9f
    cmp     x1, #2
    cmp     x0, #5
    b.ne    9f
    ret

    // 14) A W copy zero-extends: x0 changes whenever its top half
    //     was set.
    mov     w1, w0
    mov     w0, w1
    ret

    // 15) A JIT patch site: the MOVZ its MOVKs continue, and the
    //     MOVKs, match only until patched.
    movz    x16, #0
    str     x16, [x0]
    movz    x16, #0
    movk    x16, #0, lsl #16
    movk    x16, #0, lsl #32
    ret

    // 16) A call ends the region, whatever the callee preserves.
    mov     x19, #7
    bl      _main
    mov     x19, #7
9:
    ret
