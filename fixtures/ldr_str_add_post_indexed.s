// Integration fixture for check_ldr_str_add_post_indexed.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) Canonical X-form load + base bump.
    ldr     x3, [x1]
    add     x1, x1, #16             // -> ldr x3, [x1], #16

    // 2) W-form load.
    ldr     w3, [x1]
    add     x1, x1, #16             // -> ldr w3, [x1], #16

    // 3) Byte load: any byte offset works.
    ldrb    w3, [x1]
    add     x1, x1, #5              // -> ldrb w3, [x1], #5

    // 4) Halfword load.
    ldrh    w3, [x1]
    add     x1, x1, #6              // -> ldrh w3, [x1], #6

    // 5) X-form store.
    str     x3, [x1]
    add     x1, x1, #16             // -> str x3, [x1], #16

    // 6) W-form store.
    str     w3, [x1]
    add     x1, x1, #16             // -> str w3, [x1], #16

    // 7) STRB / STRH.
    strb    w3, [x1]
    add     x1, x1, #5              // -> strb w3, [x1], #5

    strh    w3, [x1]
    add     x1, x1, #6              // -> strh w3, [x1], #6

    // 8) Canonical stack pop: ldr x3, [sp] ; add sp, sp, #16.
    ldr     x3, [sp]
    add     sp, sp, #16             // -> ldr x3, [sp], #16

    // 9) Store zero to stack with bump: str xzr, [sp] ; add sp, sp, #8.
    //    Rt = 31 (XZR) and Rn = 31 (SP) encode distinct registers,
    //    so the writeback is well-defined.
    str     xzr, [sp]
    add     sp, sp, #8              // -> str xzr, [sp], #8

    // Boundary positive: max accepted imm = 255.
    ldr     x3, [x1]
    add     x1, x1, #255            // -> ldr x3, [x1], #255

    // Boundary positive: min accepted imm = 1.
    ldr     x3, [x1]
    add     x1, x1, #1              // -> ldr x3, [x1], #1

    // Negatives:
    // N1) imm = 256: just over the 9-bit signed positive range.
    ldr     x3, [x1]
    add     x1, x1, #256

    // N2) sh=1 ADD: 4096 way out of range.
    ldr     x3, [x1]
    add     x1, x1, #4096

    // N3) Rt == Rn writeback (UNPREDICTABLE), Rn != 31. Use x4 so the
    //     LDR doesn't also fold with N2's preceding ADD via the
    //     immediate-offset check.
    ldr     x4, [x4]
    add     x4, x4, #16

    // N4) ADD not a self-update (Rd != Rn).
    ldr     x3, [x1]
    add     x1, x2, #16

    // N5) ADD updates an unrelated register.
    ldr     x3, [x1]
    add     x5, x5, #16

    // Positive: SUB-imm self-update -> negative post-index writeback.
    ldr     x3, [x1]
    sub     x1, x1, #16             // -> ldr x3, [x1], #-16

    // Positive (boundary): SUB imm = 256 -> writeback -256 (signed-9-bit
    // minimum). imm = 257 would be out of range (covered in unit tests).
    ldr     x3, [x1]
    sub     x1, x1, #256            // -> ldr x3, [x1], #-256

    // N7) ADDS (flag-setting; post-index has no flag form).
    ldr     x3, [x1]
    adds    x1, x1, #16

    // N8) LDR with non-zero offset: post-index can't combine.
    ldr     x3, [x1, #8]
    add     x1, x1, #16

    // N9) Intervening instruction expires the pending state.
    ldr     x3, [x1]
    mov     x9, #5
    add     x1, x1, #16

    ret
