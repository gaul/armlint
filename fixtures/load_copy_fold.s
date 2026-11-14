// Integration fixture for check_load_copy_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives (each loaded register is overwritten afterwards):
    // 1) A spill reload copied to a callee-saved home (ART's shape).
    ldr     w0, [sp, #0x2c]
    mov     x22, x0               // -> ldr w22, [sp, #0x2c]
    mov     w0, #1

    // 2) A field load copied into an argument register, X form.
    ldr     x2, [x25, #0xd0]
    mov     x1, x2                // -> ldr x1, [x25, #0xd0]
    mov     w2, #2

    // 3) A store between that leaves both registers alone.
    ldr     w3, [x19, #0x98]
    str     wzr, [x19, #0x98]
    mov     x23, x3               // -> ldr w23, [x19, #0x98]
    mov     w3, #3

    // 4) The destination is the load's base.
    ldrsh   w4, [x24, #6]
    mov     w24, w4               // -> ldrsh w24, [x24, #6]
    mov     w4, #4

    // Negatives:
    // N1) The loaded register is read after the copy.
    ldr     w5, [x1]
    mov     x26, x5
    add     w6, w5, #1

    // N2) A W copy of an X load.
    ldr     x7, [x1]
    mov     w27, w7
    mov     w7, #7

    // N3) A gap that writes the destination.
    ldr     w8, [x1]
    mov     w28, #8
    mov     x28, x8
    mov     w8, #9

    // N4) Data in the gap ends the region.
    ldr     x10, [x11]
    .word   0xffffffff
    mov     x12, x10

    ret
