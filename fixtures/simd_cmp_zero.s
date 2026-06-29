// Integration fixture for check_simd_cmp_zero: a zeroing MOVI feeding a
// vector compare folds into the compare-with-#0 form.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives: the compare overwrites the zero register (Vd == Vz).
    // 1) CMEQ is symmetric.
    movi    v16.4s, #0
    cmeq    v16.4s, v16.4s, v0.4s        // -> cmeq v16.4s, v0.4s, #0

    // 2) CMGE, zero in Vm -> cmge ...,#0.
    movi    v16.4s, #0
    cmge    v16.4s, v0.4s, v16.4s        // -> cmge v16.4s, v0.4s, #0

    // 3) CMGE, zero in Vn -> the sense flips to cmle.
    movi    v16.4s, #0
    cmge    v16.4s, v16.4s, v0.4s        // -> cmle v16.4s, v0.4s, #0

    // 4) CMGT, zero in Vn -> flips to cmlt.
    movi    v16.4s, #0
    cmgt    v16.4s, v16.4s, v0.4s        // -> cmlt v16.4s, v0.4s, #0

    // 5) FP FCMGT, zero in Vm -> fcmgt ...,#0.0.
    movi    v16.4s, #0
    fcmgt   v16.4s, v0.4s, v16.4s        // -> fcmgt v16.4s, v0.4s, #0.0

    // 6) FP FCMGE, zero in Vn -> flips to fcmle.
    movi    v16.2d, #0
    fcmge   v16.2d, v16.2d, v0.2d        // -> fcmle v16.2d, v0.2d, #0.0

    // 7) The producer arrangement need not match: an 8B zero feeds a 16B
    //    compare (a 64-bit MOVI still clears all 128 bits).
    movi    v3.8b, #0
    cmeq    v3.16b, v3.16b, v7.16b       // -> cmeq v3.16b, v7.16b, #0

    // Negatives (no finding):
    // N1) MVNI materializes all-ones, not zero.
    mvni    v16.4s, #0
    cmeq    v16.4s, v16.4s, v0.4s

    // N2) The compare does not overwrite the zero register (Vd != Vz), so
    //     the zero is not proven dead.
    movi    v16.4s, #0
    cmeq    v5.4s, v16.4s, v0.4s

    // N3) Unsigned CMHI has no compare-with-#0 equivalent.
    movi    v16.4s, #0
    cmhi    v16.4s, v0.4s, v16.4s

    ret
