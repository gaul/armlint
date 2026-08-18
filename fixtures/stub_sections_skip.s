// Linker-synthesized Mach-O import glue must not be scanned: ld's
// classic lazy-binding __stub_helper entries each LDR their
// lazy-bind-info offset into w16 from an inline literal -- exactly
// the shape check_ldr_literal_const flags -- and __stubs (type
// S_SYMBOL_STUBS) holds the indirect jumps out to dyld. Findings
// there restate the dyld ABI, not a codegen miss, so both sections
// stay silent; only the __text copy of the same pattern may surface
// a finding. The stub bodies below are shaped to trip the
// LDR-literal check if either section were ever scanned.
//
// Mach-O section syntax, so the .arch sidecar pins this fixture to
// -arch arm64.

    .text
    .globl  _main
    .p2align 2
_main:
    ldr     w0, L_const             // -> mov w0, #0x2a: a real finding
    ret
L_const:
    .long   42

    .section __TEXT,__stub_helper,regular,pure_instructions
    .p2align 2
L_helper:
    ldr     w16, L_lazy             // silent: lazy-binding glue
    b       L_helper
L_lazy:
    .long   0x1d

    .section __TEXT,__stubs,symbol_stubs,pure_instructions,12
    .p2align 2
    .indirect_symbol _printf
    ldr     w16, L_stub             // silent: import stub
    br      x16
L_stub:
    .long   0x2a
