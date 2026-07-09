// Integration fixture for check_ldr_cvtf_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives (the loaded GPR dies at the trailing mov, so the
    // deferred finding emits):
    // 1) int32 -> single.
    ldr     w8, [x1]
    scvtf   s0, w8              // -> ldr s0, [x1] ; scvtf s0, s0
    mov     w8, #1

    // 2) Unsigned conversion.
    ldr     w8, [x1, #4]
    ucvtf   s0, w8              // -> ldr s0, [x1, #4] ; ucvtf s0, s0
    mov     w8, #1

    // 3) int64 -> double, with an offset.
    ldr     x8, [x1, #8]
    scvtf   d0, x8              // -> ldr d0, [x1, #8] ; scvtf d0, d0
    mov     x8, #1

    // 4) SP base.
    ldr     w8, [sp]
    scvtf   s0, w8              // -> ldr s0, [sp] ; scvtf s0, s0
    mov     w8, #1

    // Negatives:
    // N1) Mixed widths (int32 -> double) have no in-SIMD twin.
    ldr     w8, [x1]
    scvtf   d0, w8
    mov     w8, #1

    // N2) A halfword load has no conversion width.
    ldrh    w8, [x1]
    scvtf   s0, w8
    mov     w8, #1

    // N3) Fresh use with no later kill: the loaded register is never
    //     proven dead, so nothing is emitted.
    ldr     w9, [x1]
    scvtf   s0, w9

    ret
