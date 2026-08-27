// Integration fixture for the pair arm of check_add_ldr_imm_offset:
// an ADD-immediate feeding a signed-offset LDP/STP.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives, structural tier: the pair load's destination list
    // covers the ADD's Rd, so the sum is dead at the consumer and the
    // finding needs no liveness scan.

    // 1) The shape that dominates real code: an ADD forward and a
    //    negative imm7 back, cancelling to a bare base.
    add     x19, x26, #0xb8
    ldp     x21, x19, [x19, #-0xb8] // -> ldp x21, x19, [x26]

    // 2) Either destination slot proves the kill.
    add     x8, x26, #0xb8
    ldp     x8, x20, [x8, #-0xb8]   // -> ldp x8, x20, [x26]

    // 3) A combined offset that stays positive.
    add     x8, x26, #16
    ldp     x8, x20, [x8, #16]      // -> ldp x8, x20, [x26, #32]

    // 4) ...and one that crosses to negative, which the single-access
    //    fold cannot express at all (LDR-uimm has no negative offset).
    add     x8, x26, #16
    ldp     x8, x20, [x8, #-48]     // -> ldp x8, x20, [x26, #-32]

    // 5) W pair: the 4-byte scale accepts #4.
    add     x8, x1, #4
    ldp     w8, w20, [x8]           // -> ldp w8, w20, [x1, #4]

    // 6) LDPSW scales by 4 despite its X destinations.
    add     x8, x1, #4
    ldpsw   x8, x20, [x8]           // -> ldpsw x8, x20, [x1, #4]

    // 7) Read-modify-write ADD: the rewrite names the pre-ADD value
    //    as base, which is the address the original computed.
    add     x8, x8, #8
    ldp     x8, x12, [x8, #-8]      // -> ldp x8, x12, [x8]

    // 8) Boundary: 63 * 8 = 504 is the last X-pair slot.
    add     x8, x1, #504
    ldp     x8, x20, [x8]           // -> ldp x8, x20, [x1, #504]

    // Negatives:
    // N1) 512 / 8 = 64, one past the signed-7-bit slot.
    add     x8, x1, #512
    ldp     x8, x20, [x8]

    // N2) Alignment is decided by the ADD alone (imm7 is pre-scaled),
    //     and #4 is not a multiple of the X pair's 8-byte transfer.
    add     x8, x1, #4
    ldp     x8, x20, [x8]

    // N3) The pair's base is not the ADD's destination.
    add     x8, x1, #16
    ldp     x8, x20, [x9]

    // N4) ADD writes SP: folding would discard an observable SP
    //     update, so the opener never fires.
    add     sp, x1, #16
    ldp     x8, x20, [sp]

    // N5) Intervening instruction breaks adjacency -- for THIS check.
    //     The fold is sound at a distance, and
    //     check_add_ldr_str_multi_fold scans a window and reports the
    //     site; adjacency is where the two checks divide, not a
    //     condition on the rewrite. Hence a finding below under that
    //     name and none under this one.
    add     x8, x1, #16
    mov     x9, #5
    ldp     x8, x20, [x8]

    // Deferred tier: nothing in the window overwrites the address
    // register, so each of these commits only once a later write
    // proves the sum dead. The movz supplies that write.

    // 9) Pair store.
    add     x8, x1, #16
    stp     x3, x4, [x8]            // -> stp x3, x4, [x1, #16]
    movz    x8, #1

    // 10) The canonical stack shape.
    add     x8, sp, #0x30
    stp     x1, x2, [x8, #-0x10]    // -> stp x1, x2, [sp, #0x20]
    movz    x8, #1

    // 11) Fresh-destination pair load.
    add     x8, x1, #16
    ldp     x3, x4, [x8]            // -> ldp x3, x4, [x1, #16]
    movz    x8, #1

    // 12) A SIMD&FP pair carrying the same register NUMBER as the
    //     base is not an alias -- q8 and x8 are different files.
    add     x8, x1, #32
    stp     q8, q9, [x8]            // -> stp q8, q9, [x1, #32]
    movz    x8, #1

    // N6) A pair store whose data register IS the ADD's Rd never
    //     folds: the rewritten store would read the deleted sum.
    add     x8, x1, #16
    stp     x8, x4, [x8]
    movz    x8, #1

    // N7) ...in either slot.
    add     x8, x1, #16
    stp     x3, x8, [x8]
    movz    x8, #1

    // N8) A read of the address register before the kill keeps it
    //     live, so the deferral is discarded.
    add     x8, x1, #16
    ldp     x3, x4, [x8]
    add     x5, x8, x6
    movz    x8, #1

    ret
