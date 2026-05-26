// Integration fixture for check_mov_zero_to_xzr.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) STR X.
    mov     x0, #0
    str     x0, [x1]                // -> str xzr, [x1]

    // 2) STR W.
    mov     w0, #0
    str     w0, [x1]                // -> str wzr, [x1]

    // 3) STRB.
    mov     w0, #0
    strb    w0, [x1]                // -> strb wzr, [x1]

    // 4) STRH.
    mov     w0, #0
    strh    w0, [x1]                // -> strh wzr, [x1]

    // 5) STR with offset.
    mov     x0, #0
    str     x0, [x1, #16]           // -> str xzr, [x1, #16]

    // 6) STR with SP.
    mov     x0, #0
    str     x0, [sp, #8]            // -> str xzr, [sp, #8]

    // 7) ADD with Rm = mov.
    mov     x0, #0
    add     x3, x2, x0              // -> add x3, x2, xzr

    // 8) SUB-from-zero (Rn = mov).
    mov     x0, #0
    sub     x3, x0, x2              // -> sub x3, xzr, x2 (= neg x3, x2)

    // 9) CMP (Rm = mov).
    mov     x0, #0
    cmp     x2, x0                  // -> cmp x2, xzr (= cmp x2, #0)

    // 10) CMN.
    mov     x0, #0
    cmn     x2, x0                  // -> cmn x2, xzr

    // 11) AND.
    mov     x0, #0
    and     x3, x2, x0              // -> and x3, x2, xzr (= MOV X3, XZR)

    // 12) ORR -> MOV alias.
    mov     x0, #0
    orr     x3, x2, x0              // -> orr x3, x2, xzr (= MOV X3, X2)

    // 13) EOR.
    mov     x0, #0
    eor     x3, x2, x0              // -> eor x3, x2, xzr (= MOV X3, X2)

    // 14) TST.
    mov     x0, #0
    tst     x2, x0                  // -> tst x2, xzr

    // Negatives:
    // N1) Non-zero MOV value.
    mov     x0, #1
    str     x0, [x1]

    // N2) STR Rt != mov_rd.
    mov     x0, #0
    str     x2, [x1]

    // N3) STR base = mov_rd (Rn=X0 means SP if replaced).
    mov     x0, #0
    str     x2, [x0]                // not a fold candidate

    // N4) ALU op not reading mov_rd.
    mov     x0, #0
    add     x3, x1, x2

    ret
