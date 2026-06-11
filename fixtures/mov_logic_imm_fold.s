// Integration fixture for check_mov_logic_imm_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) AND with small bitmask immediate.
    mov     x0, #0xFF
    and     x3, x2, x0          // -> and x3, x2, #0xff

    // 2) AND, commutativity (Rn from MOV).
    mov     x0, #0xFF
    and     x3, x0, x2          // -> and x3, x2, #0xff

    // 3) W form.
    mov     w0, #0xFF
    and     w3, w2, w0          // -> and w3, w2, #0xff

    // 4) ORR.
    mov     x0, #0xFF
    orr     x3, x2, x0          // -> orr x3, x2, #0xff

    // 5) EOR.
    mov     x0, #0xFF
    eor     x3, x2, x0          // -> eor x3, x2, #0xff

    // 6) ANDS.
    mov     x0, #0xFF
    ands    x3, x2, x0          // -> ands x3, x2, #0xff

    // 7) TST (ANDS with Rd=XZR).
    mov     x0, #0xFF
    tst     x2, x0              // -> tst x2, #0xff

    // 8) Wider bitmask immediate.
    mov     x0, #0xFFFF
    and     x3, x2, x0          // -> and x3, x2, #0xffff

    // 9) Shifted MOVZ producing high bitmask.
    movz    x0, #0xFFFF, lsl #16
    and     x3, x2, x0          // -> and x3, x2, #0xffff0000

    // 10) BIC: the Rm-inverting family folds with the complemented
    //     constant when ~C is a bitmask immediate.
    mov     x0, #0xFF
    bic     x3, x2, x0          // -> and x3, x2, #0xffffffffffffff00

    // 11) ORN (W form).
    mov     w0, #1
    orn     w3, w2, w0          // -> orr w3, w2, #0xfffffffe

    // 12) EON.
    mov     x0, #1
    eon     x3, x2, x0          // -> eor x3, x2, #0xfffffffffffffffe

    // 13) BICS, NZCV-identical to ANDS-immediate, and its TST alias.
    mov     w0, #1
    bics    w3, w2, w0          // -> ands w3, w2, #0xfffffffe

    mov     w0, #1
    bics    wzr, w2, w0         // -> tst w2, #0xfffffffe

    // Negatives:
    // N1) C = 5 is not a bitmask immediate.
    mov     x0, #5
    and     x3, x2, x0

    // N2) ~C is not a bitmask immediate (C = 0xfffffffa, ~C = 5).
    mov     w0, #-6
    bic     w3, w2, w0

    // N3) Shifted AND.
    mov     x0, #0xFF
    and     x3, x2, x0, lsl #2

    // N4) Constant in BIC's non-inverted slot: C & ~x2 has no
    //     immediate form.
    mov     x0, #0xFF
    bic     x3, x0, x2

    // N5) Surviving operand is the constant register itself: the
    //     immediate rewrite would still read x0, so the MOV could
    //     never be deleted. Silent here; the self-op identity check
    //     flags the AND on its own.
    mov     x0, #0xFF
    and     x3, x0, x0

    ret
