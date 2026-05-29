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

    // Negatives:
    // N1) Consumer's Rd != MVN dest (the ~Rs value would stay live).
    mvn     w0, w1
    and     w5, w3, w0

    // N2) Consumer is already a negated form (BIC, N=1): not matched.
    mvn     w0, w1
    bic     w0, w3, w0

    // N3) Consumer does not read the MVN dest.
    mvn     w0, w1
    and     w2, w3, w4

    ret
