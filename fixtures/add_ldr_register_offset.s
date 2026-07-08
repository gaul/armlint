// Integration fixture for check_add_ldr_register_offset.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) Canonical X-form, LSL #0.
    add     x3, x1, x2
    ldr     x3, [x3]                // -> ldr x3, [x1, x2]

    // 2) X-form LSL #3 matches X access scale.
    add     x3, x1, x2, lsl #3
    ldr     x3, [x3]                // -> ldr x3, [x1, x2, lsl #3]

    // 3) W-form load, LSL #0.
    add     x3, x1, x2
    ldr     w3, [x3]                // -> ldr w3, [x1, x2]

    // 4) W-form load with LSL #2 matches W access scale.
    add     x3, x1, x2, lsl #2
    ldr     w3, [x3]                // -> ldr w3, [x1, x2, lsl #2]

    // 5) LDRB, LSL #0.
    add     x3, x1, x2
    ldrb    w3, [x3]                // -> ldrb w3, [x1, x2]

    // 6) LDRH with LSL #1.
    add     x3, x1, x2, lsl #1
    ldrh    w3, [x3]                // -> ldrh w3, [x1, x2, lsl #1]

    // 7) Aliasing OK: add x3, x3, x2 ; ldr x3, [x3].
    add     x3, x3, x2
    ldr     x3, [x3]                // -> ldr x3, [x3, x2]

    // Negatives:
    // N1) LSL #2 with X load (scale 3 required).
    add     x3, x1, x2, lsl #2
    ldr     x3, [x3]

    // N2) LSL #1 with W load (scale 2 required).
    add     x3, x1, x2, lsl #1
    ldr     w3, [x3]

    // N3) LDR base != ADD's Rd.
    add     x3, x1, x2
    ldr     x3, [x5]

    // P) Fresh-destination load: ldr x7 leaves x3 live at the
    // consumer, so emission defers through the forward register-
    // liveness scan -- and the next line's add overwrites x3,
    // proving it dead, so the deferred finding emits.
    add     x3, x1, x2
    ldr     x7, [x3]                // -> ldr x7, [x1, x2]

    // N5) LDR with non-zero immediate.
    add     x3, x1, x2
    ldr     x3, [x3, #8]

    // N6) SUB instead of ADD.
    sub     x3, x1, x2
    ldr     x3, [x3]

    // N7) Intervening instruction.
    add     x3, x1, x2
    add     x5, x5, x6              // unrelated
    ldr     x3, [x3]

    // P) Sign-extending consumer: LDRSW overwrites x3 just like a
    // plain load, so the fold carries over to its register-offset
    // form.
    add     x3, x1, x2, lsl #2
    ldrsw   x3, [x3]                // -> ldrsw x3, [x1, x2, lsl #2]

    // N8) PRFM shares the encoding family but its Rt is a prefetch
    // operation, not a destination; the address register stays live.
    add     x3, x1, x2
    prfm    pldl1keep, [x3]

    // Store consumers (deferred): a store never overwrites the
    // address register, so emission waits until the forward scan
    // sees it die.

    // P) X store; x3 dies at the trailing mov.
    add     x3, x1, x2
    str     x0, [x3]                // -> str x0, [x1, x2]
    mov     x3, #1

    // P) Scaled store.
    add     x3, x1, x2, lsl #3
    str     x0, [x3]                // -> str x0, [x1, x2, lsl #3]
    mov     x3, #2

    // P) Zero store renders wzr/xzr.
    add     x3, x1, x2
    str     xzr, [x3]               // -> str xzr, [x1, x2]
    mov     x3, #3

    // N9) Store data == address register: the rewrite would read the
    // deleted sum; never folds.
    add     x3, x1, x2
    str     x3, [x3]
    mov     x3, #4

    ret
