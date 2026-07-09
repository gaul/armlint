// Integration fixture for the CSSC synthesis checks (run with
// -m cssc via the sidecar .flags file).

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives (each pair is followed by a fresh compare, whose
    // NZCV overwrite commits the deferred finding):
    // 1) Signed max.
    cmp     x1, x2
    csel    x0, x1, x2, gt          // -> smax x0, x1, x2
    cmp     x9, #0

    // 2) Unsigned min via swapped operands, W form.
    cmp     w1, w2
    csel    w0, w2, w1, hi          // -> umin w0, w1, w2
    cmp     w9, #0

    // 3) Absolute value.
    cmp     x1, #0
    cneg    x0, x1, mi              // -> abs x0, x1
    cmp     x9, #0

    // 4) Count trailing zeros (no flags involved; the CLZ overwrites
    //    the reversed value).
    rbit    x0, x1
    clz     x0, x0                  // -> ctz x0, x1

    // 5) NEON popcount round trip; v0 dies at the trailing fmov, so
    //    the vector-register scan commits the finding.
    fmov    d0, x1
    cnt     v0.8b, v0.8b
    addv    b0, v0.8b
    fmov    w0, s0                  // -> cnt x0, x1
    fmov    d0, x9

    // Negatives:
    // N1) A later flag reader keeps the compare alive: no fold.
    cmp     x1, x2
    csel    x0, x1, x2, gt
    b.eq    1f
1:
    // N2) EQ selects neither extreme.
    cmp     x1, x2
    csel    x0, x1, x2, eq
    cmp     x9, #0

    ret
