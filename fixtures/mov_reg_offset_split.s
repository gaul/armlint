// Integration fixture for check_mov_reg_offset_split.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) rustc: a global-context field at 0x7a3e8, two links and a
    //    register-offset load.
    movz    w9, #0xa3e8
    movk    w9, #7, lsl #16
    ldr     x8, [x8, x9]        // -> add x9, x8, #0x7a, lsl #12 ; ldr x8, [x9, #0x3e8]
    mov     x9, #0
    ret

    // 2) The load writes the constant register itself.
    movz    x9, #0xa3e8
    movk    x9, #7, lsl #16
    ldr     x9, [x8, x9]        // -> add x9, x8, #0x7a, lsl #12 ; ldr x9, [x9, #0x3e8]
    ret

    // 3) A store, an SP base.
    movz    w9, #0xa3e8
    movk    w9, #7, lsl #16
    str     x1, [sp, x9]        // -> add x9, sp, #0x7a, lsl #12 ; str x1, [x9, #0x3e8]
    mov     x9, #0
    ret

    // 4) A scaled index, and a low part the access size does not
    //    divide (the unscaled form).
    movz    w9, #0x100
    movk    w9, #1, lsl #16
    ldr     x8, [x0, x9, lsl #3]  // -> add x9, x0, #0x80, lsl #12 ; ldr x8, [x9, #0x800]
    mov     x9, #0
    movz    w9, #3
    movk    w9, #1, lsl #16
    ldr     x8, [x0, x9]        // -> add x9, x0, #0x10, lsl #12 ; ldur x8, [x9, #0x3]
    mov     x9, #0
    ret

    // Negatives:
    // 5) One immediate reaches it (the sibling fold's).
    mov     x9, #0x1000
    ldr     x8, [x0, x9]
    mov     x9, #0
    // 6) Beyond one shifted ADD.
    movz    w9, #1
    movk    w9, #0x100, lsl #16
    ldr     x8, [x0, x9]
    mov     x9, #0
    // 7) Misaligned and beyond the unscaled range.
    movz    w9, #0x801
    movk    w9, #1, lsl #16
    ldr     x8, [x0, x9]
    mov     x9, #0
    // 8) The constant register read afterwards.
    movz    w9, #0xa3e8
    movk    w9, #7, lsl #16
    ldr     x8, [x0, x9]
    str     x9, [x0]
    ret
