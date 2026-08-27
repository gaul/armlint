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

    // 9) A sum off the access-size grid has no unsigned-offset
    // spelling; the unscaled form takes it unchanged.
    add     x3, x1, #4
    ldr     x3, [x3]                // -> ldur x3, [x1, #4]

    // 10) Same for a W access.
    add     x3, x1, #2
    ldr     w3, [x3]                // -> ldur w3, [x1, #2]

    // Unscaled inputs. Which spelling the assembler chose for the
    // access says nothing about whether the sum folds; the output
    // spelling is chosen from the sum alone.

    // 11) Unscaled in, scaled out.
    add     x3, x1, #16
    ldur    x3, [x3, #-8]           // -> ldr x3, [x1, #8]

    // 12) Unscaled in, unscaled out: the sum goes negative, which the
    // unsigned-offset form cannot express at all.
    add     x3, x1, #16
    ldur    x3, [x3, #-32]          // -> ldur x3, [x1, #-16]

    // 13) The unscaled offset cancels the ADD exactly.
    add     x3, x1, #24
    ldur    x3, [x3, #-24]          // -> ldr x3, [x1]

    // Negatives:
    // N1) Misaligned AND past the unscaled +255 ceiling: 260 is not a
    //     multiple of 8, so neither spelling encodes it.
    add     x3, x1, #260
    ldr     x3, [x3]

    // N2) Pre-indexed load. Same encoding group as LDUR, but it writes
    //     the sum back to the base, so deleting the ADD would drop an
    //     observable update.
    add     x3, x1, #16
    ldr     x5, [x3, #8]!

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

    // N7) SUB-imm: the pending slot opens only on ADD-immediate. The
    //     sum would encode now that the unscaled form is understood,
    //     but the check does not look for a SUB producer.
    sub     x3, x1, #16
    ldr     x3, [x3]

    // N8) Intervening instruction. Negative for this check only:
    //     check_add_ldr_str_multi_fold reaches the use across the gap
    //     and reports the same rewrite, which is why a finding under
    //     that name appears below.
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

    // P) Unscaled store, folding to the scaled spelling.
    add     x8, x1, #16
    stur    x0, [x8, #-8]           // -> str x0, [x1, #8]
    mov     x8, #6

    // P) A misaligned sum under a scaled store folds to STUR.
    add     x8, x1, #4
    str     x0, [x8]                // -> stur x0, [x1, #4]
    mov     x8, #7

    // SIMD&FP consumers. The address arithmetic does not care which
    // register file the data lands in; only the deadness proof does,
    // and a V-register destination can never supply it.

    // P) Scaled FP load. Rt is a V register, so it cannot overwrite
    //    the address register -- this defers like a store, and the
    //    trailing mov proves x8 dead.
    add     x8, x1, #16
    ldr     q0, [x8]                // -> ldr q0, [x1, #0x10]
    mov     x8, #8

    // P) A D-register store: the grid the sum must land on is 8, not
    //    16, because the transfer size comes from the encoding.
    add     x8, x1, #8
    str     d3, [x8, #16]           // -> str d3, [x1, #0x18]
    mov     x8, #9

    // P) Unscaled FP in, scaled out. The ADD's immediate is off the
    //    16-byte grid, which is why the store was spelled STUR; the
    //    sum lands back on it. This is the dominant real shape.
    add     x8, sp, #0x2a8
    stur    q0, [x8, #0x68]         // -> str q0, [sp, #0x310]
    mov     x8, #10

    // P) An FP load whose Rt NUMBER equals the address register still
    //    defers: q8 is in the other file and leaves x8 untouched, so
    //    nothing here proves the sum dead on the spot.
    add     x8, x1, #16
    ldr     q8, [x8]                // -> ldr q8, [x1, #0x10]
    mov     x8, #11

    // N9) Out of range for a Q access: 0xfff0 + 16 scaled by 16 is
    //     4096, one past imm12, and far past imm9.
    add     x8, x1, #16
    str     q0, [x8, #0xfff0]
    mov     x8, #12

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
