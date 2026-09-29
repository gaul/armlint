// Constant chains (-c): the constants MOVZ/MOVN + MOVK chains build,
// and those a function builds more than once.
//
// _hash builds FxHasher's multiplier twice, as an inlined hash that
// does not keep it in a register does: the second build is a rebuild.
// _field builds a field offset three times, each after the load that
// overwrote it: two rebuilds. _offset builds the same offset once, a
// build of _field's value but in another function, so not a rebuild;
// _offset_x builds it at X width, which is another value. _lone's
// single MOVZ is no chain. No finding fires: every rebuild follows a
// write that clobbered the register, which is what keeps them out of
// reach of the local value numbering check.

    .text
    .globl  _hash
    .p2align 2
_hash:
    movz    x8, #0xa9c5
    movk    x8, #0x2e62, lsl #16
    movk    x8, #0x7aea, lsl #32
    movk    x8, #0xf135, lsl #48
    mul     x0, x0, x8
    ldr     x8, [x1]
    eor     x0, x0, x8
    movz    x8, #0xa9c5
    movk    x8, #0x2e62, lsl #16
    movk    x8, #0x7aea, lsl #32
    movk    x8, #0xf135, lsl #48
    mul     x0, x0, x8
    ret

    .globl  _field
    .p2align 2
_field:
    movz    w9, #0xdeb8
    movk    w9, #0x1, lsl #16
    ldr     w9, [x0, x9]
    add     w2, w2, w9
    movz    w9, #0xdeb8
    movk    w9, #0x1, lsl #16
    ldr     w9, [x1, x9]
    add     w2, w2, w9
    movz    w9, #0xdeb8
    movk    w9, #0x1, lsl #16
    ldr     w9, [x3, x9]
    add     w0, w2, w9
    ret

    .globl  _offset
    .p2align 2
_offset:
    movz    w9, #0xdeb8
    movk    w9, #0x1, lsl #16
    add     x0, x0, x9
    ret

    .globl  _offset_x
    .p2align 2
_offset_x:
    movz    x9, #0xdeb8
    movk    x9, #0x1, lsl #16
    add     x0, x0, x9
    ret

    .globl  _lone
    .p2align 2
_lone:
    movz    w0, #0x1234
    ret
