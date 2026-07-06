// Integration fixture for check_mov_reg_offset_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: the constant index folds into the scaled immediate
    // form; the load overwrites the constant register, so the MOV is
    // immediately dead.
    mov     x8, #256
    ldr     x8, [x1, x8]

    // Positive: scaled index (lsl #3) -> byte offset 32.
    mov     x9, #4
    ldr     x9, [x2, x9, lsl #3]

    // Positive: misaligned byte offset -> the unscaled LDUR form.
    mov     x10, #3
    ldr     x10, [x3, x10]

    // Positive: negative constant (MOVN) -> LDUR with #-8.
    mov     x11, #-8
    ldr     x11, [x4, x11]

    // Positive: store consumer; the constant dies at the following
    // overwrite, so the deferred finding emits.
    mov     x12, #16
    str     x0, [x5, x12]
    mov     x12, #0

    // Positive: a zero store -- the data register is WZR and must
    // render as wzr in the rewrite.
    mov     x17, #4
    str     wzr, [x1, x17]
    mov     x17, #0

    // Negative: the base is the constant register -- the immediate
    // rewrite would still read it, so the MOV cannot be deleted.
    mov     x13, #8
    ldr     x0, [x13, x13]

    // Negative: the store's data register is the constant.
    mov     x14, #8
    str     x14, [x6, x14]

    // Negative: the offset exceeds every encodable form.
    mov     x15, #0x9000
    ldr     x15, [x7, x15]

    // Negative: the constant register is read again before dying --
    // the MOV must stay, so the deferred finding is discarded.
    mov     x16, #16
    ldr     x0, [x1, x16]
    add     x2, x16, #1

    ret
