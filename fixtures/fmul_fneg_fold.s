// Integration fixture for check_fmul_fneg_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives (the in-place FNEG overwrites the product, and
    // FNMUL's negation applies to the already-rounded product, so the
    // fold is bit-exact in every FPCR rounding mode):
    // 1) Double precision.
    fmul    d0, d1, d2
    fneg    d0, d0                  // -> fnmul d0, d1, d2

    // 2) Single precision.
    fmul    s0, s1, s2
    fneg    s0, s0                  // -> fnmul s0, s1, s2

    // 3) In-place multiply source: both spellings read d0 before
    //    writing it.
    fmul    d0, d0, d2
    fneg    d0, d0                  // -> fnmul d0, d0, d2

    // 4) FNEG into a fresh register defers on the product register;
    //    the trailing fmov overwrites v0 and commits the finding.
    fmul    d0, d1, d2
    fneg    d5, d0                  // -> fnmul d5, d1, d2
    fmov    d0, d3

    // Negatives:
    // N2) Precision mismatch.
    fmul    d0, d1, d2
    fneg    s0, s0

    // N3) The unsound sibling: negating an OPERAND before the
    //     multiply computes round(-(a*b)), which differs from FNMUL's
    //     -(round(a*b)) under the directed rounding modes.
    fneg    d1, d1
    fmul    d0, d1, d2

    // N1) Fresh destination with no later kill (the ret stops the
    //     scan): the product is never proven dead.
    fmul    d0, d1, d2
    fneg    d5, d0

    ret
