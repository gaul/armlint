// Integration fixture for check_lse_rmw (-m lse via the .flags
// sidecar: LSE atomics are undefined before Armv8.1). Each positive
// loop is followed by an instruction that overwrites the loop's
// scratches -- the computed value and the status register -- which
// commits the deferred finding.

    .text
    .globl  _main
    .p2align 2
_main:
    // 1) The canonical fetch-add.
1:  ldxr    x8, [x0]
    add     x9, x8, x1
    stxr    w10, x9, [x0]
    cbnz    w10, 1b
    ldp     x9, x10, [sp]

    // 2) Acquire + release exclusives carry over as the AL suffix.
2:  ldaxr   x8, [x0]
    add     x9, x8, x1
    stlxr   w10, x9, [x0]
    cbnz    w10, 2b
    ldp     x9, x10, [sp]

    // 3) W-form ORR becomes LDSET.
3:  ldxr    w8, [x0]
    orr     w9, w8, w1
    stxr    w10, w9, [x0]
    cbnz    w10, 3b
    ldp     w9, w10, [sp]

    // 4) Byte-sized AND routes through the complemented operand.
4:  ldxrb   w8, [x0]
    and     w9, w8, w1
    stxrb   w10, w9, [x0]
    cbnz    w10, 4b
    ldp     w9, w10, [sp]

    // 5) The immediate spelling routes through a scratch MOV.
5:  ldxr    x8, [x0]
    add     x9, x8, #1
    stxr    w10, x9, [x0]
    cbnz    w10, 5b
    ldp     x9, x10, [sp]

    // 6) The swap shape: no middle op, a loop-invariant value.
6:  ldaxr   x8, [x0]
    stlxr   w10, x2, [x0]
    cbnz    w10, 6b
    mov     w10, w19

    // Negatives:
    // N1) The computed value is read after the loop; the single
    //     atomic does not produce it.
7:  ldxr    x8, [x0]
    add     x9, x8, x1
    stxr    w10, x9, [x0]
    cbnz    w10, 7b
    add     x2, x9, x9

    // N2) A side entry into the loop interior: some path reaches
    //     the store-exclusive without the load.
    b       8f
9:  ldxr    x8, [x0]
    add     x9, x8, x1
8:  stxr    w10, x9, [x0]
    cbnz    w10, 9b
    ldp     x9, x10, [sp]

    // N3) CBZ retries on success: the wrong sense.
10: ldxr    x8, [x0]
    add     x9, x8, x1
    stxr    w10, x9, [x0]
    cbz     w10, 10b
    ldp     x9, x10, [sp]
    ret
