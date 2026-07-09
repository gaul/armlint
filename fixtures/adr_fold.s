// Integration fixture for check_adr_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) The load overwrites the address register: structural kill.
    adr     x8, L_pool
    ldr     x8, [x8]                // -> ldr x8, L_pool

    // 2) Different destination: defers until the address dies at the
    //    trailing mov.
    adr     x9, L_pool
    ldr     w10, [x9]               // -> ldr w10, L_pool
    mov     x9, #1

    // 3) FP destination always defers.
    adr     x11, L_pool
    ldr     d0, [x11]               // -> ldr d0, L_pool
    mov     x11, #1

    // 4) BR through IP0: the ABI reserves x16/x17 as veneer scratch.
    adr     x16, L_target
    br      x16                     // -> b L_target

L_target:
    // Negatives:
    // N1) A general register may carry the address to the target.
    adr     x8, L_target
    br      x8

    // N2) A non-zero load offset is not the plain address use.
    adr     x8, L_pool
    ldr     x8, [x8, #8]

    ret

    .p2align 3
L_pool: .quad 0x0123456789abcdef
        .quad 0
