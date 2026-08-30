// Integration fixture for check_copy_add_sub_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) The SpiderMonkey Baseline frame-pointer shape:
    //    mov x19, x29 ; sub x19, x19, #0x48 -> sub x19, x29, #0x48.
    mov     x19, x29
    sub     x19, x19, #0x48

    // 2) ADD consumer, W form.
    mov     w1, w0
    add     w1, w1, #4

    // 3) A W consumer of an X copy reads the low half of the same
    //    value.
    mov     x2, x3
    add     w2, w2, #8

    // 4) The shifted immediate folds unchanged.
    mov     x4, x5
    add     x4, x4, #1, lsl #12

    // 5) The SP-read alias as the producer.
    mov     x20, sp
    add     x20, x20, #16

    // Negatives:
    // 6) An X consumer of a W copy observes the zeroed upper half.
    mov     w6, w7
    add     x6, x6, #4

    // 7) An SP-writing MOV never opens: the transient SP value is
    //    architecturally observable.
    mov     sp, x8
    add     sp, sp, #16

    // 8) Not in-place: x11 may stay live, so both instructions
    //    remain.
    mov     x11, x12
    add     x13, x11, #4

    // 9) Adjacency broken by an unrelated instruction.
    mov     x15, x16
    movz    x17, #1
    add     x15, x15, #4

    // 10) Side entry onto the consumer: the branch target suppresses
    //     the finding.
    mov     x21, x22
1:
    add     x21, x21, #8
    cbz     x23, 1b
    ret
