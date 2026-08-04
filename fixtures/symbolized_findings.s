// Integration fixture for symbolized findings: two global functions
// with one finding inside each, so the finding headers carry
// "<_first+0x4>"-style annotations naming the containing symbol. Both
// host object formats surface the .globl labels (Mach-O nlist N_SECT
// externals; ELF .symtab global NOTYPE), and the numeric local labels
// surface in neither, so the snapshot stays host-format-agnostic just
// like the section-relative offsets. The findings themselves are the
// trivial branch-to-next no-op.

    .text
    .globl  _first
    .p2align 2
_first:
    nop
    b       1f              // finding at 0x4: <_first+0x4>
1:
    ret

    .globl  _second
    .p2align 2
_second:
    nop
    nop
    b       2f              // finding at 0x14: <_second+0x8>
2:
    ret
