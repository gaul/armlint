// Integration fixture for check_add_ldr_str_pre_indexed.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) Canonical X-form load + pre-index.
    add     x1, x1, #16
    ldr     x3, [x1]                // -> ldr x3, [x1, #16]!

    // 2) W-form load.
    add     x1, x1, #16
    ldr     w3, [x1]                // -> ldr w3, [x1, #16]!

    // 3) Byte/halfword loads.
    add     x1, x1, #5
    ldrb    w3, [x1]                // -> ldrb w3, [x1, #5]!

    add     x1, x1, #6
    ldrh    w3, [x1]                // -> ldrh w3, [x1, #6]!

    // 4) X-form store.
    add     x1, x1, #16
    str     x3, [x1]                // -> str x3, [x1, #16]!

    // 5) W-form store, plus byte and halfword.
    add     x1, x1, #16
    str     w3, [x1]                // -> str w3, [x1, #16]!

    add     x1, x1, #5
    strb    w3, [x1]                // -> strb w3, [x1, #5]!

    add     x1, x1, #6
    strh    w3, [x1]                // -> strh w3, [x1, #6]!

    // 6) SP base: add sp, sp, #16 ; ldr x3, [sp]
    //    -> ldr x3, [sp, #16]!.
    add     sp, sp, #16
    ldr     x3, [sp]

    // 7) SP base + XZR store: add sp, sp, #8 ; str xzr, [sp]
    //    -> str xzr, [sp, #8]!.
    add     sp, sp, #8
    str     xzr, [sp]

    // Boundary positives: imm = 255 and imm = 1.
    add     x1, x1, #255
    ldr     x3, [x1]                // -> ldr x3, [x1, #255]!

    add     x1, x1, #1
    ldr     x3, [x1]                // -> ldr x3, [x1, #1]!

    // Negatives:
    // N1) imm = 256: just over the 9-bit signed positive range.
    add     x1, x1, #256
    ldr     x3, [x1]

    // N2) sh=1 ADD: 4096 way out of range.
    add     x1, x1, #4096
    ldr     x3, [x1]

    // N3) Rt == Rn (Rn != 31): falls through to
    //     check_add_ldr_imm_offset, which folds it as immediate-
    //     offset (no writeback). Pre-index rejects (UNPREDICTABLE).
    //     Net: 1 finding here, not from us.
    add     x4, x4, #16
    ldr     x4, [x4]

    // N4) ADD not a self-update.
    add     x1, x2, #16
    ldr     x3, [x1]

    // N5) ADD updates an unrelated register.
    add     x5, x5, #16
    ldr     x3, [x1]

    // Positive: SUB-imm self-update -> negative pre-index writeback.
    // (The preceding ldr also pairs with this sub as a post-index fold,
    // so this block yields both a post- and a pre-index finding -- the
    // same overlap the ADD positives above exhibit.)
    sub     x1, x1, #16
    ldr     x3, [x1]                // -> ldr x3, [x1, #-16]!

    // N7) ADDS (flag-setting; pre-index has no flag form).
    adds    x1, x1, #16
    ldr     x3, [x1]

    // N8) LDR has non-zero offset.
    add     x1, x1, #16
    ldr     x3, [x1, #8]

    // N9) Intervening instruction expires pending state.
    add     x1, x1, #16
    mov     x9, #5
    ldr     x3, [x1]

    // P) SIMD&FP load: every FP size has a pre-indexed form, and the
    // FP Rt can never alias the integer base.
    add     x9, x9, #16
    ldr     q0, [x9]                // -> ldr q0, [x9, #16]!

    // P) D store after a negative bump. (A different base register
    // than the case above, so the ldr q0 / sub pair straddling the
    // two cases does not itself form a post-index pattern.)
    sub     x10, x10, #8
    str     d3, [x10]               // -> str d3, [x10, #-8]!

    ret
