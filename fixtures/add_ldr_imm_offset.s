// Integration fixture for check_add_ldr_imm_offset.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) Canonical: add x3, x1, #16 ; ldr x3, [x3] -> ldr x3, [x1, #16].
    add     x3, x1, #16
    ldr     x3, [x3]

    // 2) W-form LDR.
    add     x3, x1, #16
    ldr     w3, [x3]

    // 3) LDRB (any byte offset works).
    add     x3, x1, #5
    ldrb    w3, [x3]

    // 4) LDRH with aligned offset.
    add     x3, x1, #6
    ldrh    w3, [x3]

    // 5) Stack-relative: ADD Rn=SP folds to LDR with SP base.
    add     x3, sp, #32
    ldr     x3, [x3]

    // 6) sh=1 form: large 4096-byte offset.
    add     x3, x1, #4096
    ldr     x3, [x3]

    // 7) Aliasing OK: add x3, x3, #16 ; ldr x3, [x3].
    add     x3, x3, #16
    ldr     x3, [x3]

    // 8) Combined offset: 16 + 8 = 24.
    add     x3, x1, #16
    ldr     x3, [x3, #8]

    // Negatives:
    // N1) Misaligned for X access (#4 not a multiple of 8).
    add     x3, x1, #4
    ldr     x3, [x3]

    // N2) Misaligned for W access (#2 not a multiple of 4).
    add     x3, x1, #2
    ldr     w3, [x3]

    // N3) Too large for X-form encoding: 0x8000 / 8 = 4096 > 4095.
    add     x3, x1, #32768
    ldr     x3, [x3]

    // N4) LDR base != ADD's Rd.
    add     x3, x1, #16
    ldr     x3, [x5]

    // P) Fresh-destination load: ldr x7 leaves x3 live at the
    // consumer, so emission defers through the forward register-
    // liveness scan -- and the next line's add overwrites x3,
    // proving it dead, so the deferred finding emits.
    add     x3, x1, #16
    ldr     x7, [x3]                // -> ldr x7, [x1, #16]

    // N6) Combined offset out of X-form range: 0x7000 + 0x1000 = 0x8000,
    //     0x8000/8 = 4096 > 4095.
    add     x3, x1, #0x7000
    ldr     x3, [x3, #0x1000]

    // N7) SUB-imm: no negative encoding in LDR-uimm.
    sub     x3, x1, #16
    ldr     x3, [x3]

    // N8) Intervening instruction.
    add     x3, x1, #16
    add     x5, x5, x6
    ldr     x3, [x3]

    // P) Sign-extending consumer: the offsets combine into LDRSW's
    // own unsigned-offset form.
    add     x3, x1, #8
    ldrsw   x3, [x3, #4]            // -> ldrsw x3, [x1, #0xc]

    // P) MOV-from-SP alias (add x8, sp, #0): the base copy folds the
    // same way.
    mov     x8, sp
    ldr     x8, [x8]                // -> ldr x8, [sp]

    // P) MOV-from-SP with an offset on the load.
    mov     x8, sp
    ldr     x8, [x8, #16]           // -> ldr x8, [sp, #16]

    // P) MOV-from-SP feeding a load of another register: defers on
    //    x8, and the next block's add overwrites it, so the deferred
    //    finding emits.
    mov     x8, sp
    ldr     x0, [x8]                // -> ldr x0, [sp]

    // Store consumers (deferred): a store never overwrites the
    // address register, so emission waits until the forward scan
    // sees it die.

    // P) Field store through a temp; x8 dies at the trailing mov.
    add     x8, x1, #16
    str     x0, [x8]                // -> str x0, [x1, #16]
    mov     x8, #1

    // P) Stack spill through a temp.
    add     x8, sp, #32
    str     x0, [x8]                // -> str x0, [sp, #32]
    mov     x8, #2

    // P) MOV-from-SP + zero store, with the store's own offset.
    mov     x8, sp
    str     xzr, [x8, #8]           // -> str xzr, [sp, #8]
    mov     x8, #3

    // N10) Store data == address register: the rewrite would read
    //      the deleted sum; never folds.
    add     x8, x1, #16
    str     x8, [x8]
    mov     x8, #4

    // N11) The address register is read again before dying: the
    //      deferred finding is discarded (the ADD must stay).
    add     x8, x1, #16
    str     x0, [x8]
    add     x5, x8, #1
    mov     x8, #5

    // N12) A deferral cut short by an unsafe terminator: the RET ends
    //      the scan before x9 is ever proven dead, so nothing is
    //      emitted.
    add     x9, x1, #16
    str     x0, [x9]

    ret
