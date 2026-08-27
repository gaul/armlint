// Integration fixture for check_zr_operand_alu.
//
// An ALU instruction whose Rm operand is the zero register collapses to
// a copy, a constant, or a NOT. Rm is the deliberate side: every
// canonical degenerate spelling puts ZR in Rn instead, and those are
// the assembler's own output for mov / neg / mvn.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives, collapsing to a copy of Rn:
    orr     w0, w1, wzr             // -> mov w0, w1
    orr     x0, x1, xzr             // -> mov x0, x1
    eor     w0, w1, wzr             // -> mov w0, w1
    bic     w0, w1, wzr             // -> mov w0, w1
    add     w0, w1, wzr             // -> mov w0, w1
    sub     w0, w1, wzr             // -> mov w0, w1

    // Positives, collapsing to zero:
    and     w0, w1, wzr             // -> mov w0, wzr
    mul     w0, w1, wzr             // -> mov w0, wzr

    // Positives, the two remaining shapes:
    orn     w0, w1, wzr             // -> mov w0, #-1
    eon     w0, w1, wzr             // -> mvn w0, w1

    // Negatives:
    // N1) The canonical spellings, which all put ZR in Rn. Flagging
    //     any of these would report the assembler's own rendering of
    //     mov, neg and mvn -- the trap that makes Rm the side to key
    //     on.
    mov     w0, w1                  // orr w0, wzr, w1
    neg     w0, w1                  // sub w0, wzr, w1
    mvn     w0, w1                  // orn w0, wzr, w1

    // N2) The S-variants. Their flag write is a second result the
    //     rewrite would drop, so they belong to the dead-flag
    //     candidate rather than here.
    adds    w0, w1, wzr
    subs    w0, w1, wzr
    ands    w0, w1, wzr

    // N3) A ZR destination writes nothing at all -- the
    //     dead-ZR-write candidate, which the corpus measures at zero.
    orr     wzr, w1, wzr

    // N4) A real Rm is not this shape.
    orr     w0, w1, w2

    ret
