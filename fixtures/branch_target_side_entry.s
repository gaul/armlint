// Integration fixture for the branch-target (side-entry) gate: a
// direct branch that lands inside a finding's window, past its first
// instruction, invalidates the rewrite -- the entering path would
// execute a suffix that no longer exists. N1/N2 exercise the
// close-side gates in check_add_ldr_imm_offset and
// check_add_ldr_str_pre_indexed; N3-N5 exercise the central emission
// gate (armlint_finding_has_side_entry) on checks with no gate of
// their own. The N-cases must produce no findings; the P-cases keep
// the same shapes without a side entry (or with the branch landing on
// the window's first instruction, which runs the whole pattern) and
// must still be flagged.

    .text
    .globl  _main
    .p2align 2
_main:
    // N1: rotated byte-scan loop -- while (isspace(*p)) p++. The
    // initial branch enters at the LDRB, past the increment, so the
    // pre-indexed rewrite must not fire.
    b       Lentry1
Lstep1:
    add     x8, x8, #1
Lentry1:
    ldrb    w9, [x8]
    cmp     w9, #0x20
    b.eq    Lstep1

    // N2: list-walk re-entry -- p = p->next with next at offset 0.
    // The back edge lands on the LDR (dest == base), so the
    // unsigned-offset rewrite must not fire.
    add     x8, x8, #0x10
Lentry2:
    ldr     x8, [x8]
    cbz     x8, Ldone2
    b       Lentry2
Ldone2:

    // P1: pre-indexed shape with no side entry -- still flagged.
    add     x10, x10, #1
    ldrb    w11, [x10]

    // P2: unsigned-offset shape whose ADD (not the LDR) is the branch
    // target -- entry runs the whole pair, still flagged.
Ladd3:
    add     x12, x12, #0x10
    ldr     x12, [x12]
    b       Ladd3

    // N3: shared return tail -- the MOV #0's use is entered from a
    // path whose register is live and non-zero, so the ZR rewrite
    // must not fire (central gate; the fold defers through the
    // liveness scan and emits at the kill).
    cbz     x0, Lzero3
    add     x8, x0, #1
    b       Luse3
Lzero3:
    mov     x8, #0
Luse3:
    mov     x0, x8
    mov     x8, #1

    // N4: adjacent loads whose second is a loop entry -- coalescing
    // to LDP would drop the re-entered load (central gate).
    ldr     x20, [x19, #0x18]
Lentry4:
    ldr     x0, [x19, #0x20]
    cbz     x0, Lentry4

    // N5: post-index shape whose self-update is the loop-continue
    // target -- merging removes the increment's entry point
    // (central gate).
    ldrb    w9, [x8]
Lstep5:
    add     x8, x8, #1
    cbnz    w9, Lstep5

    // P3: straight-line MOV #0 + use with no side entry -- still
    // flagged (deferred, emitted at the kill).
    mov     x8, #0
    mov     x0, x8
    mov     x8, #2

    ret
