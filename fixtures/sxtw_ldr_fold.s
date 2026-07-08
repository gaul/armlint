// Integration fixture for check_sxtw_ldr_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) SXTW + register-offset LDR (LSL #0).
    sxtw    x0, w1
    ldr     x0, [x3, x0]           // -> ldr x0, [x3, w1, sxtw]

    // 2) Scaled X load.
    sxtw    x0, w1
    ldr     x0, [x3, x0, lsl #3]   // -> ldr x0, [x3, w1, sxtw #3]

    // 3) Scaled W load.
    sxtw    x0, w1
    ldr     w0, [x3, x0, lsl #2]   // -> ldr w0, [x3, w1, sxtw #2]

    // 4) LDRB.
    sxtw    x0, w1
    ldrb    w0, [x3, x0]           // -> ldrb w0, [x3, w1, sxtw]

    // 5) SP base.
    sxtw    x0, w1
    ldr     x0, [sp, x0]           // -> ldr x0, [sp, w1, sxtw]

    // P) Fresh-destination load: ldr x2 leaves the index live at the
    // consumer, so emission defers through the forward register-
    // liveness scan -- and the next line's sxtw overwrites x0,
    // proving it dead, so the deferred finding emits.
    sxtw    x0, w1
    ldr     x2, [x3, x0]           // -> ldr x2, [x3, w1, sxtw]

    // Negatives:
    // N1) Store whose data register IS the index: the rewrite would
    // read the deleted extend's result; never folds.
    sxtw    x0, w1
    str     x0, [x3, x0]

    // N2) Base == index: folding would read the base's pre-SXTW value.
    sxtw    x0, w1
    ldr     x0, [x0, x0]

    // P) Sign-extending consumer: LDRSW still overwrites the index,
    // and its register-offset form takes the same SXTW option.
    sxtw    x0, w1
    ldrsw   x0, [x3, x0, lsl #2]    // -> ldrsw x0, [x3, w1, sxtw #2]

    // N3) PRFM's Rt is a prefetch operation, not a destination; the
    // index stays live (and can never be proven dead through it).
    sxtw    x0, w1
    prfm    pldl1keep, [x3, x0]

    // Store consumers (deferred): a store never overwrites the index,
    // so emission waits until the forward scan sees the index die.

    // P) X store; x0 dies at the trailing mov.
    sxtw    x0, w1
    str     x5, [x3, x0]            // -> str x5, [x3, w1, sxtw]
    mov     x0, #1

    // P) Scaled W store.
    sxtw    x0, w1
    str     w5, [x3, x0, lsl #2]    // -> str w5, [x3, w1, sxtw #2]
    mov     x0, #2

    // N4) The index is read again before dying: the deferred finding
    // is discarded (the SXTW must stay).
    sxtw    x0, w1
    str     x5, [x3, x0]
    add     x6, x0, #1
    mov     x0, #3

    ret
