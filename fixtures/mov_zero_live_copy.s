// Integration fixture for the live-zero copy fallback of
// check_mov_zero_to_xzr.

    .text
    .globl  _main
    .p2align 2
_main:
    // 1) ART's argument homing: the zero is itself an argument, so it
    // stays live into the call and only the copy changes.
    mov     w1, #0
    mov     x22, x1                // -> mov x22, xzr
    bl      _main

    // 2) The zero read again by a second copy.
    mov     w3, #0
    mov     x4, x3                 // -> mov x4, xzr
    mov     x5, x3

    // 3) The zero dead after the copy: the MOV #0 fold deletes it.
    mov     w6, #0
    mov     x7, x6
    mov     x6, #5

    // 4) The zero live to the end of the region.
    mov     w8, #0
    mov     w9, w8                 // -> mov w9, wzr
