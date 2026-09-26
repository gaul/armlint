// Integration fixture for check_dead_write.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) JavaScriptCore Baseline: the metadata pointer formed, then
    //    formed again from a new offset before anything read it.
    add     x4, x25, x16
    ldur    x2, [x29, #-0xa8]
    mov     x16, #0x3898
    add     x4, x25, x16
    str     x4, [x0]
    ret

    // 2) SpiderMonkey Ion: an adjusted length overwritten by a load.
    sub     w4, w4, #8
    ldr     w4, [x10, #4]
    str     w4, [x0]
    ret

    // 3) V8: a register zeroed, then loaded.
    mov     x4, #0
    ldrb    w4, [x3, #0xc]
    str     w4, [x0]
    ret

    // 4) One load pair kills two writes.
    mov     x1, #1
    mov     x2, #2
    ldp     x1, x2, [x0]
    stp     x1, x2, [x5]
    ret

    // 5) A label between the two does not matter: only the first
    //    instruction goes, and the entering path never ran it.
    mov     x3, #7
1:
    add     x5, x6, x7
    mov     x3, #8
    cbz     x9, 1b
    str     x3, [x0]
    ret

    // Negatives:
    // 6) The value is read before the overwrite.
    mov     x3, #7
    add     x4, x3, #1
    mov     x3, #8
    stp     x3, x4, [x0]
    ret

    // 7) A branch leaves straight-line code before the overwrite.
    mov     x3, #7
    cbz     x0, 9f
    mov     x3, #8
    str     x3, [x0]
    ret

    // 8) A system call reads its number register.
    mov     x16, #1
    svc     #0x80
    mov     x16, #2
    str     x16, [x0]
    ret

    // 9) The overwrite recomputes the same value: check_value_recompute
    //    deletes the second instead.
    add     x4, x25, #0xc8
    ldur    x2, [x29, #-0x30]
    add     x4, x25, #0xc8
    str     x4, [x0]
    ret

    // 10) A flag setter, and a JIT patch site's MOVZ + MOVK.
    adds    x3, x1, x2
    mov     x3, #1
    movz    x16, #1
    movk    x16, #2, lsl #16
    mov     x16, #3
    stp     x3, x16, [x0]
9:
    ret
