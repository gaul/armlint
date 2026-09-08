// Integration fixture for the -m v8 mode (via the sidecar .flags
// file). The one CLI spelling for a V8 JIT dump arms both halves of
// the mode: the cage-base ORR -> ADD fold, which asserts that x28 is
// V8's 4GB-aligned pointer-compression cage base, and the constant-
// pool skip, which reads LDR XZR, (literal) as V8's self-describing
// pool marker (imm19 = the count of data words that follow).

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: the V8 undefined-root load. The scratch dies at the
    // next MOVZ, which is what commits the deferred liveness proof.
    movz    x16, #0x11
    orr     x0, x28, x16            // -> add x0, x28, #0x11

    // Positive: the commuted spelling, with an LSL #12-form immediate.
    movz    x16, #0x5000
    orr     x1, x16, x28            // -> add x1, x28, #0x5000

    // Negative: the base is not the cage register, so the alignment
    // argument does not apply and this stays a plain ORR (0x11 is not
    // a bitmask immediate, so the sound MOV + ORR fold is silent too).
    movz    x16, #0x11
    orr     x2, x27, x16

    // Positive: a literal load whose pooled value is mov-encodable.
    // The value sits inside the skipped pool below; the check reads
    // through the skip, since the bytes stay in the buffer.
    ldr     x3, L_lit               // -> mov x3, #0x2a

    // V8 places a mid-function pool behind a branch over it: the
    // marker, then the data words. The first data word encodes
    // "mov x1, x1", a guaranteed self-MOV finding if the scan ever
    // decoded the pool as code; under -m v8 it is data, and the
    // instruction count in the summary excludes all four words.
    b       1f
    .long   0x5800007f              // ldr xzr, (literal): 3 data words
    .long   0xaa0103e1              // pool data ("mov x1, x1")
L_lit:  .long   0x2a                // pool data: the literal's low word
    .long   0                       //             ... and its high word
1:
    ret
