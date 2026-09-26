// Integration fixture for check_redundant_zext across a gap: the
// producer's fact lasts until something writes the register, a branch
// lands in between, or control leaves by a call or an unconditional
// transfer.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: JavaScriptCore's WasmBBQ shape -- an i32 loaded, a tier-up
    // counter bumped, then the value zero-extended for a call.
    ldr     w2, [x17, w2, uxtw]
    ldr     w16, [x26, #0x38]
    add     w16, w16, #1
    str     w16, [x26, #0x38]
    mov     w2, w2                      // a no-op: bits >= 32 are zero

    // Positive: LLVM's cross-block shape -- the mask sits past a compare
    // and a conditional branch, whose fall-through keeps the register.
    ldrh    w10, [x9]
    ldr     x9, [x9, #8]
    cmp     x10, #0xc
    b.eq    L_out
    and     w10, w10, #0xffff           // a no-op: bits >= 16 are zero

    // Positive, twice: a consumer that changes nothing leaves the LDRB's
    // fact (P = 8) in place for the next one.
    ldrb    w0, [x1]
    mov     w0, w0
    add     x20, x20, #1
    uxtb    w0, w0

    // Negative: an X-form write to the register in the gap.
    ldrb    w3, [x4]
    add     x3, x3, #1
    uxtb    w3, w3

    // Negative: a writeback base is written, though Capstone 5 flags
    // the operand read-only.
    ldrb    w5, [x6]
    ldr     x7, [x5], #8
    uxtb    w5, w5

    // Negative: a call may write any register.
    add     w8, w11, w12
    bl      _main
    mov     w8, w8

    // Negative: a branch lands in the gap, reaching the consumer
    // without the producer.
    add     w13, w14, w15
L_join:
    movz    w18, #1
    mov     w13, w13
    cbnz    x19, L_join

L_out:
    ret
