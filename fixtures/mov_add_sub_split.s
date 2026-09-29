// MOV + ADD/SUB foldable to two immediate ADD/SUBs: a constant below
// 2^24 that no single ADD/SUB immediate encodes, built by a MOV chain
// of two instructions, is two immediates -- the high 12 bits with LSL
// #12, then the low 12 bits -- once the constant's register dies.
//
// _field is issue #10's rustc shape: a W chain zero-extended into an X
// ADD, its register overwritten later. _in_place overwrites it with
// the ADD itself. _negative adds a negative X constant, which splits
// into SUBs, and _md5 adds MD5's round constant 0xfffa3942 at W width,
// -0x5c6be there.
//
// No finding: _live reads the constant again, _adds sets the flags of
// the whole sum, _one_imm's 0x12000 is a single immediate (0x12, lsl
// #12), _far's 0x1235678 is past 2^24, and _call's register is dead
// after the call only by the calling convention, which armlint does
// not assume.

    .text
    .globl  _field
    .p2align 2
_field:
    mov     w9, #0xdeb8
    movk    w9, #0x1, lsl #16
    add     x21, x0, x9
    ldrh    w8, [x21, #8]
    mov     x9, #0
    ret

    .globl  _in_place
    .p2align 2
_in_place:
    mov     w8, #0xb1f0
    movk    w8, #0x1, lsl #16
    add     x8, x0, x8
    ldr     x0, [x8, #8]
    ret

    .globl  _negative
    .p2align 2
_negative:
    mov     x8, #-3
    movk    x8, #0xfffd, lsl #16
    add     x19, x22, x8
    mov     x8, #1
    ret

    .globl  _md5
    .p2align 2
_md5:
    mov     w9, #0x3942
    movk    w9, #0xfffa, lsl #16
    add     w0, w0, w9
    eor     w9, w1, w2
    ret

    .globl  _live
    .p2align 2
_live:
    mov     w9, #0xdeb8
    movk    w9, #0x1, lsl #16
    add     x21, x0, x9
    add     x22, x1, x9
    ret

    .globl  _adds
    .p2align 2
_adds:
    mov     w9, #0xdeb8
    movk    w9, #0x1, lsl #16
    adds    x21, x0, x9
    mov     x9, #0
    ret

    .globl  _one_imm
    .p2align 2
_one_imm:
    mov     w9, #0x2000
    movk    w9, #0x1, lsl #16
    add     x21, x0, x9
    mov     x9, #0
    ret

    .globl  _far
    .p2align 2
_far:
    mov     w9, #0x5678
    movk    w9, #0x123, lsl #16
    add     x21, x0, x9
    mov     x9, #0
    ret

    .globl  _call
    .p2align 2
_call:
    mov     w9, #0xdeb8
    movk    w9, #0x1, lsl #16
    add     x0, x0, x9
    bl      _field
    mov     x9, #0
    ret
