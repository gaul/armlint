// Integration fixture for check_cheap_const_copy.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) The move-resolver argument-homing shape: a one-instruction
    //    constant copied into another register.
    mov     w1, #1
    orr     x2, xzr, x1

    // 2) MOVN producer.
    movn    x3, #0
    orr     x4, xzr, x3

    // 3) W MOVN + X copy: reads 0xffffffff zero-extended, still a
    //    one-instruction (logical-immediate) constant at 64 bits.
    movn    w5, #0
    orr     x6, xzr, x5

    // Negatives:
    // 4) Multi-instruction chain: rematerializing would cost more.
    mov     x7, #0x6789
    movk    x7, #0x2345, lsl #16
    orr     x8, xzr, x7

    // 5) Zero chain: MOV #0 -> ZR territory (that finding, not this one;
    //    x10 overwritten below so the deferred MOV #0 finding emits).
    mov     w9, #0
    orr     x10, xzr, x9
    mov     x9, #1

    // 6) W MOVN #0x1234 + X copy: zero-extends to a two-instruction
    //    64-bit constant; the copy is the cheapest form.
    movn    w14, #0x1234
    orr     x15, xzr, x14
    ret
