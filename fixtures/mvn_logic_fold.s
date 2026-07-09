// Integration fixture for check_mvn_logic_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) MVN result in the consumer's Rm slot.
    mvn     w0, w1
    and     w0, w3, w0             // -> bic w0, w3, w1

    // 2) MVN result in the consumer's Rn slot (AND commutes).
    mvn     w0, w1
    and     w0, w0, w3             // -> bic w0, w3, w1

    // 3) ORR -> ORN.
    mvn     w0, w1
    orr     w0, w3, w0             // -> orn w0, w3, w1

    // 4) EOR -> EON.
    mvn     w0, w1
    eor     w0, w3, w0             // -> eon w0, w3, w1

    // 5) ANDS -> BICS (flag-setting).
    mvn     w0, w1
    ands    w0, w3, w0             // -> bics w0, w3, w1

    // 6) X-form.
    mvn     x0, x1
    and     x0, x3, x0             // -> bic x0, x3, x1

    // P) Fresh destination: the AND leaves ~w1 in w0 alive at the
    // consumer, so emission defers through the forward register-
    // liveness scan -- and the next case's mvn overwrites w0, proving
    // it dead, so the deferred finding emits.
    mvn     w0, w1
    and     w5, w3, w0             // -> bic w5, w3, w1

    // Negatives:
    // N1) Consumer is already a negated form (BIC, N=1): not matched.
    mvn     w0, w1
    bic     w0, w3, w0

    // N2) Consumer does not read the MVN dest.
    mvn     w0, w1
    and     w2, w3, w4

    // N3) Fresh destination, but the complement is read again before
    // dying: the deferred finding is discarded.
    mvn     w0, w1
    and     w5, w3, w0
    orr     w6, w7, w0
    mov     w0, #1

    // P) CSEL consumer, else slot: CSINV's else-branch is a
    //    complement, so the condition carries over.
    mvn     x3, x1
    csel    x3, x2, x3, lt          // -> csinv x3, x2, x1, lt

    // P) CSEL consumer, then slot: operands swap and the condition
    //    inverts.
    mvn     x3, x1
    csel    x3, x3, x2, lt          // -> csinv x3, x2, x1, ge

    // N4) AL select is unconditional; excluded.
    mvn     x3, x1
    csel    x3, x2, x3, al

    ret
