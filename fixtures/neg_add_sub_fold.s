// Integration fixture for check_neg_add_sub_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) Canonical X-form, nt in Rm slot.
    neg     x3, x1
    add     x3, x2, x3              // -> sub x3, x2, x1

    // 2) Commuted X-form, nt in Rn slot.
    neg     x3, x1
    add     x3, x3, x2              // -> sub x3, x2, x1

    // 3) W-form.
    neg     w3, w1
    add     w3, w2, w3              // -> sub w3, w2, w1

    // 4) SUB consumer, nt in Rm slot.
    neg     x3, x1
    sub     x3, x2, x3              // -> add x3, x2, x1

    // Negatives:
    // N1) SUB with nt in Rn slot (no single-insn fold).
    neg     x3, x1
    sub     x3, x3, x4

    // N2) Width mismatch (NEG W, ADD X).
    neg     w3, w1
    add     x3, x2, x3

    // P) Fresh destination: the ADD leaves -x1 in x3 alive at the
    // consumer, so emission defers through the forward register-
    // liveness scan -- and the next case's neg overwrites x3, proving
    // it dead, so the deferred finding emits.
    neg     x3, x1
    add     x5, x2, x3              // -> sub x5, x2, x1

    // N4) Accumulator aliasing: both ADD operands are nt.
    neg     x3, x1
    add     x3, x3, x3

    // N5) ADD does not consume nt.
    neg     x3, x1
    add     x6, x4, x5

    // N6) Intervening instruction breaks adjacency.
    neg     x3, x1
    add     x5, x5, x6
    add     x3, x2, x3

    // N7) Real SUB (not the NEG alias): Rn != XZR.
    sub     x3, x4, x1
    add     x3, x2, x3

    // N8) Fresh destination, but the negation is read again before
    // dying: the deferred finding is discarded.
    neg     x3, x1
    add     x5, x2, x3
    add     x6, x3, x7
    mov     x3, #1

    // CSEL consumers: CSNEG's else-branch is a negation
    // (Rd = cond ? Rn : -Rm), so the NEG folds into the select.

    // P) Negation in the else slot: the condition carries over.
    neg     x3, x1
    csel    x3, x2, x3, lt          // -> csneg x3, x2, x1, lt

    // P) Negation in the then slot: the rewrite swaps the operands
    //    and inverts the condition.
    neg     x3, x1
    csel    x3, x3, x2, lt          // -> csneg x3, x2, x1, ge

    // P) W-form.
    neg     w3, w1
    csel    w3, w2, w3, hi          // -> csneg w3, w2, w1, hi

    // P) Fresh destination, deferred: x3 dies at the trailing mov.
    neg     x3, x1
    csel    x5, x2, x3, ne          // -> csneg x5, x2, x1, ne
    mov     x3, #1

    // N9) AL condition: the select is unconditional (a plain MOV of
    //     Rn), and the then-slot inversion (AL <-> NV) would still be
    //     always-taken.
    neg     x3, x1
    csel    x5, x2, x3, al
    mov     x3, #1

    // N10) Both CSEL operands are the negation: the same-operand
    //      identity belongs to the CSEL identity check (whose finding
    //      is the one reported here), not this fold.
    neg     x3, x1
    csel    x5, x3, x3, lt
    mov     x3, #1

    ret
