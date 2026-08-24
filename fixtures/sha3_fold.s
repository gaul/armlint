// Integration fixture for check_sha3_fold (run with -m sha3 via the
// sidecar .flags file).

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: EOR + EOR -> EOR3. The consumer overwrites the temp,
    // so the deleted producer's destination dies structurally.
    eor     v0.16b, v1.16b, v2.16b
    eor     v0.16b, v0.16b, v3.16b      // -> eor3 v0, v1, v2, v3

    // Positive: the temp in the consumer's other source slot -- EOR3
    // is symmetric in its three sources.
    eor     v4.16b, v5.16b, v6.16b
    eor     v4.16b, v7.16b, v4.16b      // -> eor3 v4, v5, v6, v7

    // Positive: the in-place spelling compilers actually emit.
    // Deleting the producer leaves v8 holding the value it read.
    eor     v8.16b, v8.16b, v9.16b
    eor     v8.16b, v8.16b, v10.16b     // -> eor3 v8, v8, v9, v10

    // Positive: BIC + EOR -> BCAX, which is Vn EOR (Vm AND NOT Va).
    bic     v11.16b, v12.16b, v13.16b
    eor     v11.16b, v14.16b, v11.16b   // -> bcax v11, v14, v12, v13

    // Negative: the 8B forms have no EOR3/BCAX counterpart -- the
    // fused instruction would write the upper half the pair zeroes.
    eor     v16.8b, v17.8b, v18.8b
    eor     v16.8b, v16.8b, v19.8b

    // Negative: both consumer sources are the temp, so the EOR cancels
    // to zero -- a vector self-op, not a three-way XOR.
    eor     v20.16b, v21.16b, v22.16b
    eor     v23.16b, v20.16b, v20.16b

    // Negative: AND is a different op in the same encoding class and
    // never opens (nor do ORR/ORN/BSL/BIT/BIF).
    and     v24.16b, v25.16b, v26.16b
    eor     v24.16b, v24.16b, v27.16b

    // Negative: the consumer must be an EOR; a BIC consumer is not a
    // three-operand shape.
    eor     v28.16b, v29.16b, v30.16b
    bic     v28.16b, v28.16b, v31.16b

    // Positive: a fresh destination defers to the vector-register
    // liveness scan, which the FP load of v1 commits.
    eor     v1.16b, v2.16b, v3.16b
    eor     v5.16b, v1.16b, v4.16b      // -> eor3 v5, v2, v3, v4
    ldr     q1, [x0]

    // Negative: the same shape with nothing to kill the temp -- the
    // scan stops at the branch and never commits.
    eor     v1.16b, v2.16b, v3.16b
    eor     v5.16b, v1.16b, v4.16b
    ret

    // Negative: side entry -- the branch lands on the consumer, so the
    // path entering there never ran the producer and the fused EOR3
    // would mix in an operand it must not. Not hypothetical: 19 of
    // libcrypto's 71 otherwise-foldable pairs are exactly this shape,
    // inside the AES loops.
    cbz     x0, 2f
    eor     v0.16b, v1.16b, v2.16b
2:
    eor     v0.16b, v0.16b, v3.16b
    ret
