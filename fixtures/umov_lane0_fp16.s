// Integration fixture for the halfword arm of check_umov_lane0_fmov
// (run with -m fp16 via the sidecar .flags file). FMOV Wd, Hn is
// FEAT_FP16, so this arm is gated; the S and D arms need no extension
// and are covered by umov_lane0_fmov.

    .text
    .arch armv8.4-a+fp16
    .globl  _main
    .p2align 2
_main:
    // Positive: Hn is the low 16 bits of Vn, and both instructions
    // zero-extend it into Wd.
    umov    w0, v1.h[0]                 // -> fmov w0, h1

    // The always-live arms keep working with the feature enabled.
    umov    w2, v3.s[0]                 // -> fmov w2, s3
    umov    x4, v5.d[0]                 // -> fmov x4, d5

    // Negatives:
    // N1) Halfword lanes above 0 stay unreachable -- the feature adds
    //     a low-element transfer, not an indexed one.
    umov    w6, v7.h[1]
    umov    w6, v7.h[7]

    // N2) Byte elements have no FMOV form even under FP16.
    umov    w8, v9.b[0]

    // N3) Discarded transfer.
    umov    wzr, v10.h[0]

    ret
