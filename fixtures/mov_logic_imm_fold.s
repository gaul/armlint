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

    // Negatives:
    // N1) C = 5 is not a bitmask immediate.
    mov     x0, #5
    and     x3, x2, x0

    // N2) BIC has no immediate form (N = 1).
    mov     x0, #0xFF
    bic     x3, x2, x0

    // N3) Shifted AND.
    mov     x0, #0xFF
    and     x3, x2, x0, lsl #2

    ret
