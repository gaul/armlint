// Integration fixture for check_br_x30.

    .text
    .globl  _main
    .p2align 2
_main:
    // 1) The spelled-out return: the identical transfer, but only
    //    RET engages the return-address predictor.
    add     x0, x1, x2
    br      x30

    // Negatives:
    // N1) An ordinary indirect branch.
    br      x17

    // N2) A call through x30 is not a return.
    blr     x30

    // N3) The real thing.
    ret
