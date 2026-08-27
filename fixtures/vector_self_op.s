// Integration fixture for check_vector_self_op.
//
// An ASIMD three-same operation whose two sources are the same
// register collapses to a constant or to the operand. Every case here
// is 1-for-1 with no liveness argument, so nothing needs a trailing
// kill the way the deletion folds do.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives, collapsing to zero:
    // 1) The corpus shape. All 351 of its sites are in place, inside
    //    OpenSSL's stitched AES + SHA1 assembly.
    eor     v26.16b, v26.16b, v26.16b   // -> movi v26.2d, #0

    // 2) The same with a fresh destination.
    eor     v4.16b, v0.16b, v0.16b      // -> movi v4.2d, #0

    // 3) A D-form source. MOVI with a 2D arrangement is still the
    //    right rewrite: every 64-bit-arrangement SIMD instruction
    //    zeroes the upper half of its destination anyway.
    eor     v4.8b, v0.8b, v0.8b         // -> movi v4.2d, #0

    // 4) BIC of a register with itself is zero too.
    bic     v4.16b, v0.16b, v0.16b      // -> movi v4.2d, #0

    // 5) SUB, at two of its four element sizes.
    sub     v4.16b, v0.16b, v0.16b      // -> movi v4.2d, #0
    sub     v4.2d, v0.2d, v0.2d         // -> movi v4.2d, #0

    // Positives, collapsing to the operand:
    // 6) AND with a fresh destination is a register copy.
    and     v4.16b, v0.16b, v0.16b      // -> mov v4.16b, v0.16b

    // 7) In place, AND and ORR write a register its own value.
    and     v0.16b, v0.16b, v0.16b      // -> delete
    orr     v7.16b, v7.16b, v7.16b      // -> delete

    // Negatives:
    // N1) The member that must never be flagged: `orr Vd, Vn, Vn` with
    //     Rd != Rn IS the canonical vector MOV, which the assembler
    //     emits for every `mov vd.16b, vn.16b`. Counting these
    //     inflated a first pass over this shape from 353 to 2,158.
    orr     v4.16b, v0.16b, v0.16b
    orr     v4.8b, v0.8b, v0.8b

    // N2) Sources differ: not a self-op.
    eor     v4.16b, v0.16b, v1.16b
    and     v4.16b, v0.16b, v1.16b

    // N3) ORN of a register with itself is all-ones -- neither zero
    //     nor the operand, a different rewrite, and absent from the
    //     corpus.
    orn     v4.16b, v0.16b, v0.16b

    // N4) BSL shares EOR's U bit but reads the destination as a third
    //     source, so it is a different shape even with Vn == Vm.
    bsl     v4.16b, v0.16b, v0.16b

    ret
