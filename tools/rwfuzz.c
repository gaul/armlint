// rwfuzz: check that the rewrites armlint suggests compute what the code
// they replace computed, by running both.
//
// A check's decision can be right and its advice still wrong -- a proof
// that misses a write, a rendering that inverts a condition -- and the
// unit tests and fixtures cover only the cases someone thought to write
// down. rwfuzz generates random AArch64 programs, runs armlint's check
// registry over each, applies every finding's rewrite to a copy of the
// program, and runs original and rewrite natively from the same random
// registers, flags and memory. Any difference in x0..x7, NZCV, v0..v7 or
// the scratch memory at the end -- or a rewrite that faults or runs on
// where the original did not -- is a soundness bug in the check, or in
// the harness.
//
// Any check's rewrite applies the same way. A finding carries its
// rewrite as edits (armlint_edit in armlint.h): which words of its
// window become which instruction, spelled as the advice spells it, and
// which go. rwfuzz turns each instruction into its word with the host's
// own assembler -- once per batch of programs, over every text the batch
// needs that no batch before it did -- and a deleted word becomes a NOP,
// so that every branch keeps its target. A PC-relative operand, which a
// finding gives as an absolute offset, is re-spelled from the word it
// lands in. So what runs is the advice a reader sees, and a check whose
// advice the assembler refuses is caught too ("not applied").
//
// Each program is a fixed prologue that loads x0..x7, v0..v7, NZCV and
// a scratch-buffer pointer (x28) from a state block, a literal pool the
// prologue branches over, a random body, and an epilogue that stores the
// registers and NZCV back; after it sits a stub the body can call, which
// clobbers x0..x7, v0..v7 and NZCV as a callee may. The body writes only
// x0..x7 and v0..v7 and stores only into the scratch buffer: W and X
// arithmetic, logic, shifts and bitfields, moves, conditional selects,
// loads off x28 (atomics included), compares, forward CBZ/CBNZ/B.cond,
// calls to the stub, and the shapes the mode plants for checks to find.
// Register values lean on the edges -- zero, all ones, the 32-bit
// boundaries, small constants and their negatives, and for vectors the
// floats an FP fold must keep exact -- so compares and masks meet the
// values that tell a rewrite from the original.
//
// Modes plant shapes. The first thirteen plant one check's shape each,
// test its findings alone, count a special case of them, and run a
// control arm for it:
//   zext   check_redundant_zext (special: across a gap)
//   ubfx   check_lsr_and_to_ubfx (out of place)
//   ccmp   check_ccmp_chain (with a branch reader)
//   lvn    check_value_recompute (not adjacent)
//   dead   check_dead_write (across a gap)
//   cmn    check_cmp_cmn_w (with a branch reader)
//   branch check_branch_decided (always taken)
//   fold   check_const_fold (deleted)
//   and    check_and_known_noop (deleted)
//   cbz    check_cmp_zero_branch (through a branch at the target)
//   split  check_mov_add_sub_split (sign-crossed)
//   cbc    check_bcond_cmp_bcond (sharing a target)
//   hammock check_bcond_over_one (through an alias)
// The next four plant a family of shapes, written as assembly text, and
// test every finding with a rewrite in their programs:
//   mem    address arithmetic and the accesses it feeds: immediate,
//          unscaled and register offsets, pre- and post-indexing,
//          pairs, zero stores, extends after loads, store-releases,
//          literal loads from the pool
//   arith  multiplies, divides and shifts by constants, NEG/MVN and
//          their consumers, CSET/CSETM and theirs, bitfield pairs,
//          funnels, BFI/BFXIL synthesis, MOV chains feeding logic and
//          compares, identities, copy chains
//   fp     FMUL + FNEG, constants through general registers, FCSEL,
//          UMOV of lane 0, vector self-ops, compares with zero, EOR3 and
//          BCAX, extends and loads before a conversion
//   lse    exclusive-access loops: fetch-and-op, swap, compare-and-swap
// and all plants any of them and tests every finding with a rewrite,
// reporting by finding name. A finding whose edits touch the harness's
// own code is left alone and counted apart.
//
// A control arm applies the same kind of rewrite where armlint REFUSED
// to -- an unflagged consumer deleted, an unflagged shift + AND folded,
// an unflagged chain cut to its last compare -- and counts how often
// that changes the result: a harness that never saw a difference there
// could not see one anywhere. To check the harness itself after changing
// it, break the proof a mode exercises in armlint.c (drop the write
// invalidation in check_redundant_zext, say), rebuild libarmlint.a and
// rwfuzz, and expect mismatches within a few thousand programs.
//
// Usage: rwfuzz [-n PROGRAMS] [-s SEED] [-f NAME] [-k KINDS] [-j JOBS] MODE
//   -n  programs to generate (default 100000)
//   -s  seed, mixed into the fixed default one (default 0)
//   -f  test only the findings whose name contains NAME; the programs
//       are drawn from a stream of their own, so they stay the same
//   -k  fail unless findings of at least KINDS names were run, so that a
//       plant that stops producing its finding does not pass unseen
//   -j  run the programs in JOBS worker processes (default 1), which
//       take batches of them as they finish the last; each program is
//       drawn from its own seed, so the programs and all that is printed
//       are the same for any JOBS
// Exit status: 0 when every finding was applied and matched; 1 on a
// mismatch, on a finding the harness could not apply (an edit the
// assembler refuses would otherwise drop out of the test silently), or
// on fewer kinds run than -k asks for; 2 on a usage or environment
// error, a run that tested no finding included.
//
// The programs run on the host, so rwfuzz needs an AArch64 one: MAP_JIT
// memory on macOS, and on Linux memory mapped twice, written through one
// view and run from the other, which is not writable. It turns
// on the armlint features whose instructions the host runs (LSE, SHA3,
// LRCPC2, FP16, CSSC, CMPBR) and assembles with RWFUZZ_CC (default cc)
// under a matching -march. Built by `make tools`; it links libarmlint.a.

#define _GNU_SOURCE
#define _DARWIN_C_SOURCE

#include <stdio.h>

#if !defined(__aarch64__) && !defined(__arm64__)

int main(void)
{
    fprintf(stderr, "rwfuzz: the programs it generates run natively, so "
            "it needs an AArch64 host\n");
    return 2;
}

#else

#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

#include "armlint.h"

// === Randomness ===

// Two streams for each program: one draws the program, the other the
// states it runs from and the control arm's choices, so that which
// findings a run tests (-f) does not change the programs it draws. Both
// start from the program's index and the seed (-s), so that a program
// is the same whichever worker runs it, however many run (-j).
#define STREAM_GEN 0x9E3779B97F4A7C15ull
#define STREAM_RUN 0xD1B54A32D192ED03ull
static uint64_t seed;
static uint64_t gen_rng, run_rng;
static uint64_t *rng = &gen_rng;

// splitmix64's finalizer.
static uint64_t mix64(uint64_t z)
{
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

// Where program INDEX's STREAM starts: never zero, where xorshift would
// stay.
static uint64_t stream_start(long index, uint64_t stream)
{
    uint64_t z = mix64(mix64(seed ^ stream) + (uint64_t)index);
    return z != 0 ? z : stream;
}

// xorshift64*: fast, and reproducible from the seed.
static uint64_t rnd(void)
{
    *rng ^= *rng >> 12;
    *rng ^= *rng << 25;
    *rng ^= *rng >> 27;
    return *rng * 0x2545F4914F6CDD1Dull;
}

static unsigned rr(unsigned n)
{
    return (unsigned)(rnd() % n);
}

// The body reads and writes x0..x7 only.
static unsigned body_reg(void)
{
    return rr(8);
}

// === Encoders ===
//
// d/n/m/t are register numbers, x selects the 64-bit form. Loads and
// atomics address the scratch buffer through x28, which nothing in the
// body writes.

#define REG_BUF 28u
#define NOP 0xD503201Fu
#define RET 0xD65F03C0u

static uint32_t add_w(unsigned d, unsigned n, unsigned m) { return 0x0B000000u | m << 16 | n << 5 | d; }
static uint32_t add_x(unsigned d, unsigned n, unsigned m) { return 0x8B000000u | m << 16 | n << 5 | d; }
static uint32_t adds_x(unsigned d, unsigned n, unsigned m) { return 0xAB000000u | m << 16 | n << 5 | d; }
static uint32_t addi_w(unsigned d, unsigned n, unsigned i) { return 0x11000000u | (i & 0xFFFu) << 10 | n << 5 | d; }
static uint32_t addi_x(unsigned d, unsigned n, unsigned i) { return 0x91000000u | (i & 0xFFFu) << 10 | n << 5 | d; }
static uint32_t subi_w(unsigned d, unsigned n, unsigned i) { return 0x51000000u | (i & 0xFFFu) << 10 | n << 5 | d; }
static uint32_t eor_w(unsigned d, unsigned n, unsigned m) { return 0x4A000000u | m << 16 | n << 5 | d; }
static uint32_t eor_x(unsigned d, unsigned n, unsigned m) { return 0xCA000000u | m << 16 | n << 5 | d; }
static uint32_t orr_x(unsigned d, unsigned n, unsigned m) { return 0xAA000000u | m << 16 | n << 5 | d; }
static uint32_t mov_w(unsigned d, unsigned m) { return 0x2A0003E0u | m << 16 | d; }
static uint32_t mov_x(unsigned d, unsigned m) { return 0xAA0003E0u | m << 16 | d; }
static uint32_t neg_w(unsigned d, unsigned m) { return 0x4B0003E0u | m << 16 | d; }
static uint32_t neg_x(unsigned d, unsigned m) { return 0xCB0003E0u | m << 16 | d; }
static uint32_t ubfm_w(unsigned d, unsigned n, unsigned r, unsigned s) { return 0x53000000u | r << 16 | s << 10 | n << 5 | d; }
static uint32_t ubfm_x(unsigned d, unsigned n, unsigned r, unsigned s) { return 0xD3400000u | r << 16 | s << 10 | n << 5 | d; }
static uint32_t sbfm_w(unsigned d, unsigned n, unsigned r, unsigned s) { return 0x13000000u | r << 16 | s << 10 | n << 5 | d; }
static uint32_t sbfm_x(unsigned d, unsigned n, unsigned r, unsigned s) { return 0x93400000u | r << 16 | s << 10 | n << 5 | d; }
// AND/ORR with the low-mask immediate (1 << w) - 1.
static uint32_t and_w_low(unsigned d, unsigned n, unsigned w) { return 0x12000000u | (w - 1u) << 10 | n << 5 | d; }
static uint32_t and_x_low(unsigned d, unsigned n, unsigned w) { return 0x92400000u | (w - 1u) << 10 | n << 5 | d; }
static uint32_t orr_w_low(unsigned d, unsigned n, unsigned w) { return 0x32000000u | (w - 1u) << 10 | n << 5 | d; }
static uint32_t movz_w(unsigned d, unsigned i, unsigned hw) { return 0x52800000u | hw << 21 | (i & 0xFFFFu) << 5 | d; }
static uint32_t movz_x(unsigned d, unsigned i, unsigned hw) { return 0xD2800000u | hw << 21 | (i & 0xFFFFu) << 5 | d; }
static uint32_t movk_w(unsigned d, unsigned i, unsigned hw) { return 0x72800000u | hw << 21 | (i & 0xFFFFu) << 5 | d; }
static uint32_t movk_x(unsigned d, unsigned i, unsigned hw) { return 0xF2800000u | hw << 21 | (i & 0xFFFFu) << 5 | d; }
static uint32_t movn_w(unsigned d, unsigned i) { return 0x12800000u | (i & 0xFFFFu) << 5 | d; }
static uint32_t csel_w(unsigned d, unsigned n, unsigned m, unsigned c) { return 0x1A800000u | m << 16 | c << 12 | n << 5 | d; }
static uint32_t csel_x(unsigned d, unsigned n, unsigned m, unsigned c) { return 0x9A800000u | m << 16 | c << 12 | n << 5 | d; }
static uint32_t csinc_w(unsigned d, unsigned n, unsigned m, unsigned c) { return 0x1A800400u | m << 16 | c << 12 | n << 5 | d; }
static uint32_t csinv_w(unsigned d, unsigned n, unsigned m, unsigned c) { return 0x5A800000u | m << 16 | c << 12 | n << 5 | d; }
// CSET is CSINC Rd, ZR, ZR with the inverted condition.
static uint32_t cset_w(unsigned d, unsigned c) { return 0x1A9F07E0u | (c ^ 1u) << 12 | d; }
static uint32_t madd_w(unsigned d, unsigned n, unsigned m, unsigned a) { return 0x1B000000u | m << 16 | a << 10 | n << 5 | d; }
static uint32_t cmp_imm(bool x, bool cmn, unsigned n, unsigned i) { return (x ? 0x80000000u : 0) | (cmn ? 0x3100001Fu : 0x7100001Fu) | (i & 0xFFFu) << 10 | n << 5; }
static uint32_t ccmp_imm(bool x, bool ccmn, unsigned n, unsigned i, unsigned nzcv, unsigned c) { return (x ? 0x80000000u : 0) | (ccmn ? 0x3A400800u : 0x7A400800u) | (i & 31u) << 16 | c << 12 | n << 5 | nzcv; }
static uint32_t cmp_x(unsigned n, unsigned m) { return 0xEB00001Fu | m << 16 | n << 5; }
static uint32_t cmp_w(unsigned n, unsigned m) { return 0x6B00001Fu | m << 16 | n << 5; }
static uint32_t cmn_w_imm(unsigned n, unsigned i, bool lsl12) { return 0x3100001Fu | (lsl12 ? 1u << 22 : 0) | (i & 0xFFFu) << 10 | n << 5; }
static uint32_t tst_w_low(unsigned n, unsigned w) { return 0x7200001Fu | (w - 1u) << 10 | n << 5; }
static uint32_t ldrb_w(unsigned t, unsigned i) { return 0x39400000u | (i & 0xFFFu) << 10 | REG_BUF << 5 | t; }
static uint32_t ldrh_w(unsigned t, unsigned i) { return 0x79400000u | (i & 0xFFFu) << 10 | REG_BUF << 5 | t; }
static uint32_t ldr_w(unsigned t, unsigned i) { return 0xB9400000u | (i & 0xFFFu) << 10 | REG_BUF << 5 | t; }
static uint32_t ldr_x(unsigned t, unsigned i) { return 0xF9400000u | (i & 0xFFFu) << 10 | REG_BUF << 5 | t; }
static uint32_t ldrsb_x(unsigned t, unsigned i) { return 0x39800000u | (i & 0xFFFu) << 10 | REG_BUF << 5 | t; }
static uint32_t ldrsh_w(unsigned t, unsigned i) { return 0x79C00000u | (i & 0xFFFu) << 10 | REG_BUF << 5 | t; }
static uint32_t ldrsw_x(unsigned t, unsigned i) { return 0xB9800000u | (i & 0xFFFu) << 10 | REG_BUF << 5 | t; }
static uint32_t ldarb_w(unsigned t) { return 0x08DFFC00u | REG_BUF << 5 | t; }
static uint32_t ldaddb_w(unsigned s, unsigned t) { return 0x38200000u | s << 16 | REG_BUF << 5 | t; }
static uint32_t ldadd_x(unsigned s, unsigned t) { return 0xF8200000u | s << 16 | REG_BUF << 5 | t; }
// Branches take their displacement in words.
static uint32_t cbz(bool x, bool nonzero, unsigned t, int words) { return (x ? 0x80000000u : 0) | (nonzero ? 0x35000000u : 0x34000000u) | ((unsigned)words & 0x7FFFFu) << 5 | t; }
static uint32_t tbz(bool nonzero, unsigned t, unsigned bit, int words) { return (bit >> 5) << 31 | (nonzero ? 0x37000000u : 0x36000000u) | (bit & 31u) << 19 | ((unsigned)words & 0x3FFFu) << 5 | t; }
static uint32_t b_(int words) { return 0x14000000u | ((unsigned)words & 0x3FFFFFFu); }
static uint32_t sub_x(unsigned d, unsigned n, unsigned m) { return 0xCB000000u | m << 16 | n << 5 | d; }
static uint32_t and_w(unsigned d, unsigned n, unsigned m) { return 0x0A000000u | m << 16 | n << 5 | d; }
static uint32_t mul_x(unsigned d, unsigned n, unsigned m) { return 0x9B007C00u | m << 16 | n << 5 | d; }
static uint32_t udiv_w(unsigned d, unsigned n, unsigned m) { return 0x1AC00800u | m << 16 | n << 5 | d; }
static uint32_t lslv_x(unsigned d, unsigned n, unsigned m) { return 0x9AC02000u | m << 16 | n << 5 | d; }
// AND immediate clearing the low k bits, and keeping the one bit b.
static uint32_t and_clear_low(bool x, unsigned d, unsigned n, unsigned k) { return x ? 0x92400000u | ((64u - k) & 63u) << 16 | (63u - k) << 10 | n << 5 | d : 0x12000000u | ((32u - k) & 31u) << 16 | (31u - k) << 10 | n << 5 | d; }
static uint32_t and_bit(bool x, unsigned d, unsigned n, unsigned b) { return x ? 0x92400000u | ((64u - b) & 63u) << 16 | n << 5 | d : 0x12000000u | ((32u - b) & 31u) << 16 | n << 5 | d; }
static uint32_t b_cond(unsigned c, int words) { return 0x54000000u | ((unsigned)words & 0x7FFFFu) << 5 | c; }
static uint32_t bl(int words) { return 0x94000000u | ((unsigned)words & 0x3FFFFFFu); }
static uint32_t cmn_reg(bool x, unsigned n, unsigned m) { return (x ? 0xAB00001Fu : 0x2B00001Fu) | m << 16 | n << 5; }
static uint32_t movn_x(unsigned d, unsigned i, unsigned hw) { return 0x92800000u | hw << 21 | (i & 0xFFFFu) << 5 | d; }
// ADD/SUB (and ADDS/SUBS) shifted register, Rm shifted left by lsl.
static uint32_t addsub_reg(bool x, bool sub, bool s, unsigned d, unsigned n, unsigned m, unsigned lsl) { return (x ? 0x80000000u : 0) | (sub ? 0x40000000u : 0) | (s ? 0x20000000u : 0) | 0x0B000000u | m << 16 | (lsl & 63u) << 10 | n << 5 | d; }
// ADD/SUB immediate, the imm12 optionally shifted left by 12.
static uint32_t addsub_imm(bool x, bool sub, unsigned d, unsigned n, unsigned i, bool lsl12) { return (x ? 0x80000000u : 0) | (sub ? 0x51000000u : 0x11000000u) | (lsl12 ? 1u << 22 : 0) | (i & 0xFFFu) << 10 | n << 5 | d; }
static uint32_t tst_reg(bool x, unsigned n, unsigned m) { return (x ? 0xEA00001Fu : 0x6A00001Fu) | m << 16 | n << 5; }

// === Programs ===

// stp x29, x30, [sp, #-96]! ; mov x29, sp ; stp x19..x28 at [sp, #16..80]
// mov x15, x0 ; ldp x0..x7 from [x15] ; ldp x28, x16, [x15, #64] ;
// ldp q0..q7 from [x15, #80] ; msr nzcv, x16 ; clrex -- every run starts
// with the exclusive monitor clear, whatever the last one left it.
static const uint32_t prologue[] = {
    0xA9BA7BFDu, 0x910003FDu, 0xA90153F3u, 0xA9025BF5u, 0xA90363F7u,
    0xA9046BF9u, 0xA90573FBu, 0xAA0003EFu, 0xA94005E0u, 0xA9410DE2u,
    0xA94215E4u, 0xA9431DE6u, 0xA94441FCu, 0xAD4285E0u, 0xAD438DE2u,
    0xAD4495E4u, 0xAD459DE6u, 0xD51B4210u, 0xD503305Fu,
};
// stp x0..x7 to [x15] ; stp q0..q7 to [x15, #80] ; mrs x16, nzcv ;
// str x16, [x15, #72] ; ldp x19..x28 ; ldp x29, x30, [sp], #96 ; ret
static const uint32_t epilogue[] = {
    0xA90005E0u, 0xA9010DE2u, 0xA90215E4u, 0xA9031DE6u, 0xAD0285E0u,
    0xAD038DE2u, 0xAD0495E4u, 0xAD059DE6u, 0xD53B4210u, 0xF90025F0u,
    0xA94153F3u, 0xA9425BF5u, 0xA94363F7u, 0xA9446BF9u, 0xA94573FBu,
    0xA8C67BFDu, RET,
};

// The state block the prologue loads and the epilogue stores: x0..x7,
// the scratch pointer for x28, NZCV, and v0..v7 whole.
typedef struct {
    uint64_t x[8];
    uint64_t buf;
    uint64_t nzcv;
    uint8_t q[8][16];
} regs_t;

// A body slot: a finished word, an instruction in assembly text the
// batch's assembler run turns into one, or a control transfer whose word
// is fixed up once the layout is known.
enum { SLOT_PLAIN, SLOT_TEXT, SLOT_BRANCH, SLOT_READER, SLOT_CALL,
       SLOT_JUMP };

typedef struct {
    int kind;
    uint32_t word;      // SLOT_PLAIN
    const char *text;   // SLOT_TEXT: the assembler's text, as cached
    int target;         // SLOT_BRANCH/SLOT_READER/SLOT_JUMP: body index,
                        // or the end
    unsigned reg;       // SLOT_BRANCH: the CBZ/CBNZ/TBZ/TBNZ register
    unsigned cond;      // SLOT_BRANCH/SLOT_READER: the B.cond condition
    unsigned form;      // SLOT_BRANCH: 0 CBZ X, 1 CBNZ W, 2 B.cond,
                        // 3 CBZ W, 4 CBNZ X, 5 TBZ, 6 TBNZ
    unsigned bit;       // SLOT_BRANCH: the TBZ/TBNZ bit
    int aim;            // a transfer's target this many slots on, when
                        // nonzero; otherwise gen_body draws it
    bool interior;      // no branch may land here: past the start of a
                        // plant whose accesses need its base set up
} slot_t;

#define BODY_MAX 40
#define PROG_MAX 256

static slot_t body[BODY_MAX];
static int nbody;
static uint32_t prog[PROG_MAX];
static int nprog, epi_start, stub_start;

// A literal pool the plants load from (LDR literal, ADR + load): eight
// doublewords between the prologue and the body, which a B steps over.
// Some fold to a MOV, MOVN, ORR or MOVI and some to nothing; 1.0f and
// 2.0 to an FMOV.
static const uint64_t pool[8] = {
    0x2Aull, 0xFFFFFFFFFFFFFFF0ull, 0x3F800000ull, 0x4000000000000000ull,
    0x0000FFFF0000FFFFull, 0x123456789ABCDEF0ull, 0x2A2A2A2A2A2A2A2Aull,
    0x2A2A2A2A2A2A2A2Aull,
};

#define POOL_AT 20      // the pool's first word: the prologue, the B, a pad
static const int body_start = POOL_AT + 16;

static void push(uint32_t word)
{
    if (nbody < BODY_MAX) {
        body[nbody++] = (slot_t){ .kind = SLOT_PLAIN, .word = word };
    }
}

static const char *asm_intern(const char *text, size_t at);

// An instruction in assembly text, for the batch's assembler run. A
// PC-relative operand is an absolute offset, as in a finding's edits.
static void push_text(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

static void push_text(const char *fmt, ...)
{
    char text[96];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(text, sizeof(text), fmt, ap);
    va_end(ap);
    if (nbody < BODY_MAX) {
        const char *key = asm_intern(text, (size_t)(body_start + nbody));
        body[nbody++] = (slot_t){ .kind = SLOT_TEXT, .text = key };
    }
}

// The pool's i-th doubleword, as an absolute offset.
static unsigned pool_off(unsigned i)
{
    return 4u * POOL_AT + 8u * i;
}

static void push_transfer(int kind)
{
    // Drawn one statement at a time: initializers are evaluated in an
    // unspecified order, and a seed should give the same program
    // whichever compiler built this.
    unsigned reg = body_reg();
    unsigned cond = rr(14);
    unsigned form = rr(3);
    if (nbody < BODY_MAX) {
        body[nbody++] = (slot_t){ .kind = kind, .reg = reg, .cond = cond,
                                  .form = form };
    }
}

static unsigned lowmask_width(bool x)
{
    return 1u + rr(x ? 62u : 30u);
}

// A consumer of r in one of the redundant-zero-extension spellings.
static uint32_t zext_consumer(unsigned r)
{
    switch (rr(6)) {
    case 0: return mov_w(r, r);
    case 1: return ubfm_w(r, r, 0, 7);               // uxtb
    case 2: return ubfm_w(r, r, 0, 15);              // uxth
    case 3: return and_w_low(r, r, lowmask_width(false));
    case 4: return and_x_low(r, r, lowmask_width(true));
    default: return ubfm_x(r, r, 0, rr(62));         // ubfx x #0, #k
    }
}

// A write of r that bounds its value -- or, now and then, does not.
static uint32_t producer(unsigned r)
{
    unsigned a = body_reg(), b = body_reg();
    switch (rr(18)) {
    case 0: return add_w(r, a, b);
    case 1: return ldrb_w(r, rr(256));
    case 2: return ldrh_w(r, rr(128));
    case 3: return ldr_w(r, rr(64));
    case 4: return ubfm_w(r, a, rr(32), 31);         // lsr w
    case 5: {
        unsigned l = rr(32), w = 1u + rr(32u - l);
        return ubfm_w(r, a, l, l + w - 1u);          // ubfx w
    }
    case 6: {
        unsigned l = rr(64), w = 1u + rr(64u - l);
        return ubfm_x(r, a, l, l + w - 1u);          // ubfx x
    }
    case 7: return and_x_low(r, a, lowmask_width(true));
    case 8: return movz_w(r, rr(0x10000), rr(2));
    case 9: return movz_x(r, rr(0x10000), rr(4));
    case 10: return cset_w(r, rr(14));
    case 11: return csel_w(r, a, b, rr(14));
    case 12: return ldarb_w(r);
    case 13: return ldaddb_w(a, r);
    case 14: return ldrsh_w(r, rr(128));
    case 15: return orr_w_low(r, a, lowmask_width(false));
    case 16: return madd_w(r, a, b, body_reg());
    default: return add_x(r, a, b);                  // bounds nothing
    }
}

// Anything else the body may do.
static uint32_t filler(void)
{
    unsigned d = body_reg(), a = body_reg(), b = body_reg();
    switch (rr(34)) {
    case 0: return add_x(d, a, b);
    case 1: return addi_x(d, a, rr(4096));
    case 2: return addi_w(d, a, rr(4096));
    case 3: return subi_w(d, a, rr(4096));
    case 4: return eor_x(d, a, b);
    case 5: return eor_w(d, a, b);
    case 6: return orr_x(d, a, b);
    case 7: return mov_x(d, a);
    case 8: return mov_w(d, a);
    case 9: return neg_x(d, a);
    case 10: return neg_w(d, a);
    case 11: return ubfm_x(d, a, rr(64), 63);        // lsr x
    case 12: return sbfm_x(d, a, rr(64), 63);        // asr x
    case 13: return sbfm_w(d, a, rr(32), 31);        // asr w
    case 14: return ubfm_x(d, a, 1u + rr(63), 0);    // lsl-shaped insert
    case 15: return sbfm_x(d, a, 0, 31);             // sxtw
    case 16: return movk_x(d, rr(0x10000), rr(4));
    case 17: return movk_w(d, rr(0x10000), rr(2));
    case 18: return movn_w(d, rr(0x10000));
    case 19: return csel_x(d, a, b, rr(14));
    case 20: return ldr_x(d, rr(32));
    case 21: return ldrsb_x(d, rr(256));
    case 22: return ldrsw_x(d, rr(64));
    case 23: return ldadd_x(a, d);
    case 24: return cmp_imm(false, false, a, rr(4096));
    case 25: return cmp_x(a, b);
    case 26: return tst_w_low(a, lowmask_width(false));
    case 27: return zext_consumer(d);
    case 28:
    case 29: return producer(d);
    case 30: return movz_x(d, rr(0x10000), rr(4));
    case 31: return and_w_low(d, a, lowmask_width(false));
    case 32: return ubfm_w(d, a, 0, 7);              // uxtb of another
    default: return madd_w(d, a, b, body_reg());
    }
}

// zext: a producer of r, a gap, and a consumer of r.
static void plant_zext(void)
{
    unsigned r = body_reg();
    push(producer(r));
    for (unsigned gap = rr(5); gap > 0; gap--) {
        push(filler());
    }
    push(zext_consumer(r));
}

// ubfx: a right shift into t, an AND low-mask of t (into t or not), then
// t killed, read, or left alone.
static void plant_shift_and(void)
{
    bool x = rr(2) == 0;
    unsigned ds = x ? 64u : 32u;
    unsigned t = body_reg(), s = body_reg();
    unsigned n = 1u + rr(ds - 1u);
    unsigned w = 1u + rr(ds - 1u);
    if (rr(2) == 0 && n + w > ds) {
        w = 1u + rr(ds - n);                          // mostly in range
    }
    bool asr = rr(2) == 0;
    push(x ? (asr ? sbfm_x(t, s, n, 63) : ubfm_x(t, s, n, 63))
           : (asr ? sbfm_w(t, s, n, 31) : ubfm_w(t, s, n, 31)));
    unsigned d = rr(2) == 0 ? t : body_reg();
    push(x ? and_x_low(d, t, w) : and_w_low(d, t, w));
    switch (rr(3)) {
    case 0: push(movz_x(t, rr(0x10000), 0)); break;
    case 1: push(add_x(body_reg(), t, body_reg())); break;
    default: break;
    }
}

// Compare immediates: mostly small, near the small register values.
static unsigned small_imm(void)
{
    return rr(4) == 0 ? rr(4096) : rr(40);
}

// ccmp: CMP/CMN and one to three CCMP/CCMN of one register, a B.cond or
// CSEL-family reader, then a flag overwrite, a flag read, or neither.
static void plant_ccmp_chain(void)
{
    bool x = rr(2) == 0;
    unsigned r = body_reg();
    unsigned links = 2u + rr(3);
    push(cmp_imm(x, rr(3) == 0, r, small_imm()));
    for (unsigned i = 1; i < links; i++) {
        push(ccmp_imm(x, rr(3) == 0, r, rr(32), rr(16), rr(14)));
    }
    if (rr(2) == 0) {
        push_transfer(SLOT_READER);
    } else {
        unsigned d = body_reg(), a = body_reg(), b = body_reg();
        unsigned c = rr(14);
        switch (rr(4)) {
        case 0: push(csel_x(d, a, b, c)); break;
        case 1: push(cset_w(d, c)); break;
        case 2: push(csinv_w(d, a, b, c)); break;
        default: push(csinc_w(d, a, b, c)); break;
        }
    }
    switch (rr(3)) {
    case 0: push(cmp_x(body_reg(), body_reg())); break;
    case 1: push(csel_x(body_reg(), body_reg(), body_reg(), rr(14))); break;
    default: break;
    }
}

// lvn: a pure instruction, a gap, and the same value computed again --
// the same word, another spelling of its constant, a copy back, or a
// computation equal through a copy.
static uint32_t pure_op(void)
{
    unsigned d = body_reg(), a = body_reg(), b = body_reg();
    switch (rr(12)) {
    case 0: return add_x(d, a, b);
    case 1: return add_w(d, a, b);
    case 2: return addi_x(d, a, rr(4096));
    case 3: return eor_x(d, a, b);
    case 4: return ubfm_x(d, a, rr(64), 63);        // lsr x
    case 5: return sbfm_w(d, a, rr(32), 31);        // asr w
    case 6: return csel_x(d, a, b, rr(14));
    case 7: return madd_w(d, a, b, body_reg());
    case 8: return cmp_x(a, b);
    case 9: return cmp_imm(rr(2) == 0, rr(2) == 0, a, small_imm());
    case 10: return adds_x(d, a, b);
    default: return neg_x(d, a);
    }
}

static void plant_gap(void)
{
    for (unsigned gap = rr(4); gap > 0; gap--) {
        push(filler());
    }
}

static void plant_recompute(void)
{
    switch (rr(4)) {
    case 0: {
        uint32_t w = pure_op();
        push(w);
        plant_gap();
        push(w);
        break;
    }
    case 1: {
        unsigned r = body_reg();
        unsigned v = rr(4) == 0 ? rr(0x10000) : rr(48);
        push(movz_x(r, v, 0));
        plant_gap();
        push(rr(2) == 0 ? movz_w(r, v, 0) : movz_x(r, v, 0));
        break;
    }
    case 2: {
        unsigned a = body_reg(), b = body_reg();
        push(mov_x(a, b));
        plant_gap();
        push(mov_x(b, a));
        break;
    }
    default: {
        unsigned a = body_reg(), b = body_reg(), c = body_reg();
        unsigned d = body_reg();
        push(mov_x(a, b));
        push(add_x(c, a, d));
        plant_gap();
        push(add_x(c, b, d));
        break;
    }
    }
}

// dead: a write of r, a gap, and an overwrite of r that may or may not
// read it first.
static void plant_dead_write(void)
{
    unsigned r = body_reg(), a = body_reg(), b = body_reg();
    switch (rr(7)) {
    case 0: push(add_x(r, a, b)); break;
    case 1: push(addi_w(r, a, rr(4096))); break;
    case 2: push(movz_x(r, rr(0x10000), rr(4))); break;
    case 3: push(ubfm_x(r, a, rr(64), 63)); break;
    case 4: push(csel_x(r, a, b, rr(14))); break;
    case 5: push(adds_x(r, a, b)); break;      // its flags may be read
    default: push(madd_w(r, a, b, body_reg())); break;
    }
    plant_gap();
    unsigned c = body_reg(), d = body_reg();
    switch (rr(5)) {
    case 0: push(movz_w(r, rr(0x10000), rr(2))); break;
    case 1: push(ldr_x(r, rr(32))); break;
    case 2: push(add_x(r, c, d)); break;       // may read r
    case 3: push(eor_w(r, c, d)); break;       // may read r
    default: push(ldadd_x(c, r)); break;       // reads c, loads r
    }
}

// cmn: a producer of r (zero-extending, now and then not), a MOV of
// 2^32 - k into c, CMP Xr, Xc, a reader of any condition, then c and the
// flags overwritten or not.
static void plant_cmp_cmn(void)
{
    unsigned r = body_reg(), c = body_reg(), a = body_reg();
    if (c == r) {
        c = (r + 1u) % 8u;
    }
    switch (rr(6)) {
    case 0: push(mov_w(r, a)); break;
    case 1: push(ubfm_x(r, a, 32, 63)); break;           // lsr x, #32
    case 2: push(and_x_low(r, a, 32)); break;
    case 3: push(ldr_w(r, rr(64))); break;
    case 4: push(add_w(r, a, body_reg())); break;
    default: push(add_x(r, a, body_reg())); break;       // top unknown
    }
    switch (rr(4)) {
    case 0: push(movz_w(c, 0xFFFFu, 1)); break;          // k = 0x10000
    case 1: push(movn_w(c, 4096u)); break;               // k = 4097: no
    default: push(movn_w(c, rr(40))); break;             // k = 1..40
    }
    push(cmp_x(r, c));
    if (rr(2) == 0) {
        push_transfer(SLOT_READER);
    } else {
        push(rr(2) == 0 ? cset_w(body_reg(), rr(14))
                        : csel_x(body_reg(), body_reg(), body_reg(), rr(14)));
    }
    if (rr(3) != 0) {
        push(movz_x(c, rr(0x10000), 0));
    }
    if (rr(3) != 0) {
        push(cmp_x(body_reg(), body_reg()));
    }
}

// branch: a branch of a known form on register r (or the flags).
static void push_branch(unsigned form, unsigned reg, unsigned cond,
                        unsigned bit)
{
    if (nbody < BODY_MAX) {
        body[nbody++] = (slot_t){ .kind = SLOT_BRANCH, .reg = reg,
                                  .cond = cond, .form = form, .bit = bit };
    }
}

// A zero or bit test of r, now and then of a width or bit the fact
// does not cover.
static void push_test(unsigned r)
{
    unsigned form = 3u + rr(4);
    unsigned bit = rr(3) == 0 ? rr(64) : rr(8);
    if (rr(4) == 0) {
        form = rr(2);           // the X CBZ / W CBNZ forms
    }
    push_branch(form, r, 0, bit);
}

// branch: something that establishes a fact about r or the flags, a
// gap, and a branch the fact may decide -- a second test of r, a
// compare of r with another immediate, a repeated compare, a branch on
// a constant or on the bits a producer left.
static void plant_decided(void)
{
    unsigned r = body_reg();
    bool x = rr(2) == 0;
    switch (rr(7)) {
    case 0:
        push_test(r);
        break;
    case 1:
        push(cmp_imm(x, rr(4) == 0, r, small_imm()));
        push_branch(2, 0, rr(14), 0);
        break;
    case 2: {
        uint32_t c = rr(2) == 0 ? cmp_x(r, body_reg())
                                : cmp_imm(x, rr(4) == 0, r, small_imm());
        push(c);
        push_branch(2, 0, rr(14), 0);
        plant_gap();
        push(c);
        push_branch(2, 0, rr(14), 0);
        return;
    }
    case 3:
        push(rr(2) == 0 ? movz_x(r, rr(4) == 0 ? rr(0x10000) : rr(48), 0)
                        : movn_w(r, rr(48)));
        break;
    case 6: {
        // A W compare with a negative constant, under any condition.
        unsigned c = (r + 1u + rr(7)) % 8u;
        push(movn_w(c, rr(48)));
        push(cmp_w(r, c));
        push_branch(2, 0, rr(14), 0);
        plant_gap();
        push(cmp_w(r, c));
        push_branch(2, 0, rr(14), 0);
        return;
    }
    case 4:
        push(producer(r));
        break;
    default:
        push(tst_w_low(r, lowmask_width(false)));
        push_branch(2, 0, rr(2), 0);            // b.eq / b.ne
        break;
    }
    plant_gap();
    if (rr(2) == 0) {
        push(cmp_imm(x, rr(4) == 0, r, small_imm()));
        push_branch(2, 0, rr(14), 0);
    } else {
        push_test(r);
    }
}

// fold: known values -- one or two constants, or a register a branch
// fell through to pin -- a gap, and an operation on them.
static uint32_t fold_op(unsigned d, unsigned a, unsigned b)
{
    switch (rr(14)) {
    case 0: return add_x(d, a, b);
    case 1: return add_w(d, a, b);
    case 2: return sub_x(d, a, b);
    case 3: return eor_w(d, a, b);
    case 4: return and_w(d, a, b);
    case 5: return addi_x(d, a, rr(4096));
    case 6: return subi_w(d, a, rr(4096));
    case 7: return and_x_low(d, a, lowmask_width(true));
    case 8: return ubfm_x(d, a, rr(64), 63);        // lsr x
    case 9: return sbfm_w(d, a, rr(32), 31);        // asr w
    case 10: return ubfm_w(d, a, 1u + rr(31), 31u - rr(31)); // lsl-ish
    case 11: return mul_x(d, a, b);
    case 12: return udiv_w(d, a, b);
    default: return lslv_x(d, a, b);
    }
}

static void plant_fold(void)
{
    unsigned a = body_reg(), b = body_reg(), d = body_reg();
    switch (rr(4)) {
    case 0:
        push_branch(4, a, 0, 0);                // cbnz x_a
        break;
    case 1:
        push(cmp_imm(true, false, a, small_imm()));
        push_branch(2, 0, 1, 0);                // b.ne
        break;
    default:
        push(rr(2) == 0 ? movz_x(a, rr(4) == 0 ? rr(0x10000) : rr(48), 0)
                        : movn_w(a, rr(48)));
        if (rr(2) == 0) {
            push(movz_w(b, rr(48), 0));
        }
        break;
    }
    plant_gap();
    push(fold_op(d, a, rr(3) == 0 ? d : b));
}

// and: bits of r bounded -- by a producer, a TST + B.NE, a TBNZ, or a
// CMP + B.HS -- a gap, and an AND/UBFX of r, in place or not, whose mask
// may or may not cover them.
static void plant_and(void)
{
    unsigned r = body_reg();
    bool x = rr(2) == 0;
    unsigned width = x ? 64u : 32u;
    unsigned how = rr(4);
    unsigned bit = 0;
    if (how != 0 && rr(2) == 0) {
        push(producer(r));      // a branch then narrows what it bounded
    }
    switch (how) {
    case 0:
        push(producer(r));
        break;
    case 1:
        push(tst_w_low(r, lowmask_width(false)));
        push_branch(2, 0, 1, 0);                    // b.ne
        break;
    case 2:
        bit = rr(3) == 0 ? rr(64) : 1u + rr(8);
        push_branch(6, r, 0, bit);                  // tbnz
        break;
    default:
        push(cmp_imm(true, false, r, small_imm()));
        push_branch(2, 0, 2, 0);                    // b.hs
        break;
    }
    plant_gap();
    unsigned d = rr(2) == 0 ? r : body_reg();
    if (bit != 0 && bit < 32u && rr(2) == 0) {
        // The mask stopping at the bit the TBNZ found clear.
        push(x ? and_x_low(d, r, bit) : and_w_low(d, r, bit));
        return;
    }
    switch (rr(4)) {
    case 0: push(x ? and_x_low(d, r, lowmask_width(true))
                   : and_w_low(d, r, lowmask_width(false))); break;
    case 1: push(and_clear_low(x, d, r, 1u + rr(width - 1u))); break;
    case 2: push(and_bit(x, d, r, rr(width))); break;
    default: {
        unsigned w = 1u + rr(width - 1u);
        push(x ? ubfm_x(d, r, 0, w - 1u) : ubfm_w(d, r, 0, w - 1u));
        break;
    }
    }
}

// cbz: a zero test of r -- CMP #0, CMP ZR, CMN #0, CMN ZR or TST r, r
// -- and a B.cond reading it, mostly under a condition the fold takes;
// now and then a forward B after them, a jump for some target proof to
// follow.
static void push_jump(void)
{
    if (nbody < BODY_MAX) {
        body[nbody++] = (slot_t){ .kind = SLOT_JUMP };
    }
}

// A reader of NZCV, a writer, or neither.
static uint32_t edge_op(void)
{
    unsigned d = body_reg(), a = body_reg(), b = body_reg();
    switch (rr(3)) {
    case 0: return csel_w(d, a, b, rr(14));
    case 1: return cmp_x(a, b);
    default: return filler();
    }
}

static void plant_cbz(void)
{
    static const unsigned folded[8] = { 0, 1, 8, 9, 4, 5, 10, 11 };
    unsigned r = body_reg();
    bool x = rr(2) == 0;
    switch (rr(5)) {
    case 0: push(cmp_imm(x, false, r, 0)); break;
    case 1: push(x ? cmp_x(r, 31) : cmp_w(r, 31)); break;
    case 2: push(cmp_imm(x, true, r, 0)); break;
    case 3: push(cmn_reg(x, r, 31)); break;
    default: push(tst_reg(x, r, r)); break;
    }
    unsigned c = rr(4) == 0 ? rr(14) : folded[rr(8)];
    if (nbody + 5 <= BODY_MAX && rr(2) == 0) {
        // Aim the B.cond at a CBZ/TBZ or B two slots on, whose edges
        // meet a reader, a writer or neither: a split for the proof at
        // the target to walk.
        push_branch(2, 0, c, 0);
        body[nbody - 1].aim = 2;
        push(filler());
        if (rr(4) == 0) {
            push_jump();
        } else {
            unsigned form = 3u + rr(4);
            push_branch(form, body_reg(), 0, rr(64));
        }
        body[nbody - 1].aim = 2;
        push(edge_op());
        push(edge_op());
        return;
    }
    push_branch(2, 0, c, 0);
    if (rr(3) == 0) {
        push_jump();
    }
}

// split: a W or X MOV chain of c and an ADD/SUB that reads it, then c
// overwritten, read, or left alone. The value is a magnitude of two
// 12-bit halves leaning on their ends (1, 0xfff), negated now and
// then, and now and then one the fold must refuse: a single
// immediate, one past 2^24, a bitmask. So are some consumers: SUB
// with the constant in Rn, the flag-setting forms, a shifted operand.
static void plant_split(void)
{
    unsigned c = body_reg(), o = body_reg(), d;
    if (o == c) {
        o = (c + 1u) % 8u;
    }
    switch (rr(4)) {
    case 0: d = c; break;
    case 1: d = o; break;
    default: d = body_reg(); break;
    }
    bool xc = rr(2) == 0;                       // the chain's width
    bool xa = rr(4) == 0 ? !xc : xc;            // the ADD's, mostly the same
    unsigned hi = rr(3) == 0 ? (rr(2) == 0 ? 1u : 0xFFFu) : 1u + rr(0xFFFu);
    unsigned lo = rr(3) == 0 ? (rr(2) == 0 ? 1u : 0xFFFu) : 1u + rr(0xFFFu);
    uint64_t m = (uint64_t)hi << 12 | lo;
    switch (rr(8)) {
    case 0: m &= ~0xFFFull; break;              // one immediate
    case 1: m += 1ull << 24; break;             // past 2^24
    case 2: m = 0x1FFFFu; break;                // a bitmask
    default: break;
    }
    bool neg = rr(3) == 0;
    uint64_t v = neg ? 0 - m : m;
    unsigned h0 = (unsigned)(v & 0xFFFFu), h1 = (unsigned)(v >> 16) & 0xFFFFu;
    if (neg) {
        push(xc ? movn_x(c, ~h0 & 0xFFFFu, 0) : movn_w(c, ~h0 & 0xFFFFu));
    } else {
        push(xc ? movz_x(c, h0, 0) : movz_w(c, h0, 0));
    }
    push(xc ? movk_x(c, h1, 1) : movk_w(c, h1, 1));
    if (xc && !neg && rr(4) == 0) {
        push(movk_x(c, 1u + rr(0xFFFFu), 2));   // a W ADD reads the low half
    }
    switch (rr(10)) {
    case 0: push(addsub_reg(xa, false, false, d, c, o, 0)); break;
    case 1:
    case 2: push(addsub_reg(xa, true, false, d, o, c, 0)); break;
    case 3: push(addsub_reg(xa, true, false, d, c, o, 0)); break;
    case 4: push(addsub_reg(xa, rr(2) == 0, true, d, o, c, 0)); break;
    case 5: push(addsub_reg(xa, false, false, d, o, c, 1u + rr(3))); break;
    default: push(addsub_reg(xa, false, false, d, o, c, 0)); break;
    }
    switch (rr(4)) {
    case 0:
    case 1: push(movz_x(c, rr(0x10000), 0)); break;
    case 2: push(add_x(body_reg(), c, body_reg())); break;
    default: break;
    }
}

// cbc: a flag writer, a B.cond, a CMP/CMN a CCMP can repeat -- now and
// then one it cannot, or a zero test the CBZ fold takes -- and a second
// B.cond that shares the first's target (OR) or sits where the first
// lands (AND); then what the merged exit meets.
static void plant_cbc(void)
{
    if (nbody + 6 > BODY_MAX) {
        return;
    }
    unsigned a = body_reg(), b = body_reg();
    bool x = rr(2) == 0;
    switch (rr(3)) {
    case 0: push(cmp_imm(x, rr(2) == 0, a, rr(4096))); break;
    case 1: push(x ? cmp_x(a, b) : cmp_w(a, b)); break;
    default: push(tst_reg(x, a, b)); break;
    }
    bool or_shape = rr(2) == 0;
    int reach = 1 + (int)rr(3);
    push_branch(2, 0, rr(14), 0);
    body[nbody - 1].aim = or_shape ? 2 + reach : 3;
    unsigned n = body_reg(), m = body_reg();
    x = rr(2) == 0;
    switch (rr(8)) {
    case 0: push(cmp_imm(x, false, n, 32u + rr(64))); break;
    case 1: push(cmp_imm(x, rr(2) == 0, n, 0)); break;
    case 2: push(addsub_reg(x, true, true, 31, n, m, 1u + rr(8))); break;
    case 3: push(x ? cmp_x(n, m) : cmp_w(n, m)); break;
    case 4: push(cmn_reg(x, n, m)); break;
    default: push(cmp_imm(x, rr(3) == 0, n, rr(32))); break;
    }
    push_branch(2, 0, rr(14), 0);
    body[nbody - 1].aim = or_shape ? reach : 0;
    push(edge_op());
    push(edge_op());
}

// csel: a B.cond over the next instruction, which is one of the forms a
// select spells -- a MOV of a register or of #0, #1, #-1, an ADD #1, a
// NEG or an MVN in place -- or, now and then, one it does not.
static void plant_hammock(void)
{
    if (nbody + 4 > BODY_MAX) {
        return;
    }
    unsigned d = body_reg(), m = body_reg();
    bool x = rr(2) == 0;
    // A W form needs the top half of Xd known zero; give it one, now
    // and then an X write after it that forgets the fact.
    if (!x && rr(3) != 0) {
        push(rr(2) == 0 ? mov_w(d, m) : ldr_w(d, rr(64)));
        if (rr(4) == 0) {
            push(add_x(d, m, body_reg()));
        }
    }
    push_branch(2, 0, rr(14), 0);
    body[nbody - 1].aim = 2;
    switch (rr(11)) {
    case 0: push(x ? mov_x(d, m) : mov_w(d, m)); break;
    case 1: push(x ? mov_x(d, 31) : mov_w(d, 31)); break;
    case 2: push(x ? movz_x(d, 0, 0) : movz_w(d, 0, 0)); break;
    case 3: push(x ? movz_x(d, 1, 0) : movz_w(d, 1, 0)); break;
    case 4: push(x ? movn_x(d, 0, 0) : movn_w(d, 0)); break;
    case 5: push(x ? addi_x(d, d, 1) : addi_w(d, d, 1)); break;
    case 6: push(x ? neg_x(d, d) : neg_w(d, d)); break;
    case 7: push(x ? 0xAA2003E0u | d << 16 | d : 0x2A2003E0u | d << 16 | d);
            break;                                      // mvn Rd, Rd
    case 8: push(x ? movz_x(d, 2u + rr(100), 0) : movz_w(d, 2u + rr(100), 0));
            break;
    case 9: push(x ? addi_x(d, m, 1) : addi_w(d, m, 1)); break;
    default: push(filler()); break;
    }
}

// === Text plants ===
//
// The shapes the hand-encoded plants above do not reach, written as
// assembly text for the batch's assembler run: address arithmetic and
// the accesses it feeds, integer idioms with a constant or a second
// operation to fold, FP and vector code, and exclusive-access loops.
// Each draws its registers from x0..x7 (v0..v7), its bases from x28,
// and its constants from the edges the folds turn on. Every draw is a
// statement of its own, as above: arguments are evaluated in an
// unspecified order, and a seed should give the same program whichever
// compiler built this.

static const char *const cond_text[14] = {
    "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le",
};

// A body register other than a and b.
static unsigned reg_besides(unsigned a, unsigned b)
{
    unsigned r = body_reg();
    while (r == a || r == b) {
        r = (r + 1u) % 8u;
    }
    return r;
}

// An access through base b at byte offset off: a load into a data
// register or a store from one (now and then the zero register), of any
// size and either register file. The assembler picks the scaled or the
// unscaled encoding by the offset.
typedef struct {
    const char *ld, *st;    // st NULL: no store of this kind
    char reg;               // x, w, s, d, q
    unsigned size;
} access_kind;

static const access_kind access_kinds[] = {
    { "ldr", "str", 'x', 8 }, { "ldr", "str", 'w', 4 },
    { "ldrh", "strh", 'w', 2 }, { "ldrb", "strb", 'w', 1 },
    { "ldrsw", NULL, 'x', 4 }, { "ldrsh", NULL, 'w', 2 },
    { "ldrsb", NULL, 'x', 1 }, { "ldr", "str", 's', 4 },
    { "ldr", "str", 'd', 8 }, { "ldr", "str", 'q', 16 },
};

#define ACCESS_KINDS (sizeof(access_kinds) / sizeof(access_kinds[0]))

// A scaled offset for the kind, now and then an unscaled one.
static int access_off(const access_kind *k)
{
    if (rr(4) == 0) {
        return (int)rr(96) - 48;
    }
    return (int)(k->size * rr(24));
}

static void push_access_as(const access_kind *k, bool load, unsigned t,
                           unsigned b, int off)
{
    if (!load && k->st == NULL) {
        k = &access_kinds[0];
    }
    bool fp = k->reg != 'x' && k->reg != 'w';
    char rt[8];
    if (!fp && !load && rr(6) == 0) {
        snprintf(rt, sizeof(rt), "%czr", k->reg);
    } else {
        snprintf(rt, sizeof(rt), "%c%u", k->reg, t);
    }
    const char *mnem = load ? k->ld : k->st;
    if (off == 0) {
        push_text("%s %s, [x%u]", mnem, rt, b);
    } else {
        push_text("%s %s, [x%u, #%d]", mnem, rt, b, off);
    }
}

// A random access through b: a load into a register other than b, now
// and then -- when it is the base's last use -- into b itself.
static void push_access(unsigned b, int off, bool last)
{
    const access_kind *k = &access_kinds[rr(ACCESS_KINDS)];
    unsigned t = last && rr(6) == 0 ? b : reg_besides(b, b);
    bool load = rr(3) != 0;
    push_access_as(k, load, t, b, off);
}

// A base inside the scratch buffer: x28 moved by an ADD or a SUB of an
// immediate, or a copy of it, into b.
static void push_base(unsigned b)
{
    unsigned how = rr(5);
    unsigned k = rr(4) == 0 ? rr(512) : 8u * rr(128);
    switch (how) {
    case 0: push_text("sub x%u, x28, #%u", b, k & ~7u); break;
    case 1: push_text("mov x%u, x28", b); break;
    default: push_text("add x%u, x28, #%u", b, k); break;
    }
}

// Overwrite r, now and then: the end of a value a fold must prove dead.
static void maybe_kill(unsigned r)
{
    if (rr(2) == 0) {
        unsigned v = 0xD1Eu + rr(16);
        push_text("mov x%u, #%u", r, v);
    }
}

// An immediate to move a base by, sized for the access or not.
static unsigned base_step(const access_kind *k)
{
    if (rr(3) == 0) {
        return rr(300);
    }
    return k->size * (1u + rr(16));
}

static void plant_mem_shape(void);

// mem: the accesses go through registers the plant itself sets up, so
// its slots past the first are no landing place for a branch.
static void plant_mem(void)
{
    if (nbody + 8 > BODY_MAX) {
        return;
    }
    int first = nbody;
    plant_mem_shape();
    for (int i = first + 1; i < nbody; i++) {
        body[i].interior = true;
    }
}

// An instruction between a base's set-up and its use that leaves the
// base alone.
static void push_gap_besides(unsigned b)
{
    unsigned d = reg_besides(b, b);
    unsigned m = body_reg();
    unsigned n = body_reg();
    push_text("eor x%u, x%u, x%u", d, m, n);
}

static void plant_mem_shape(void)
{
    unsigned b = body_reg();
    unsigned t = reg_besides(b, b);
    unsigned i = reg_besides(b, t);
    const access_kind *k = &access_kinds[rr(ACCESS_KINDS)];
    bool load = rr(2) == 0;
    switch (rr(17)) {
    case 0:
    case 1: {
        // An address computed once and used once or more, adjacent or
        // not: the immediate-offset folds and the multi-use rebase.
        push_base(b);
        unsigned uses = 1u + rr(3);
        for (unsigned u = 0; u < uses; u++) {
            if (rr(3) == 0) {
                push_gap_besides(b);
            }
            int off = access_off(k);
            push_access(b, off, u + 1u == uses);
        }
        maybe_kill(b);
        break;
    }
    case 2: {
        // An access and then its base moved: post-indexing.
        bool sub = rr(3) == 0;
        unsigned step = base_step(k);
        push_base(b);
        push_access_as(k, load, t, b, 0);
        push_text("%s x%u, x%u, #%u", sub ? "sub" : "add", b, b, step);
        break;
    }
    case 3: {
        // The base moved and then accessed: pre-indexing.
        bool sub = rr(3) == 0;
        unsigned step = base_step(k);
        push_base(b);
        push_text("%s x%u, x%u, #%u", sub ? "sub" : "add", b, b, step);
        push_access_as(k, load, t, b, 0);
        break;
    }
    case 4: {
        // An index added to the base, scaled or not: register offset.
        unsigned s = rr(5);
        unsigned v = 8u * rr(32);
        push_text("mov x%u, #%u", i, v);
        if (s == 4) {
            push_text("add x%u, x28, x%u", b, i);
        } else {
            push_text("add x%u, x28, x%u, lsl #%u", b, i, s);
        }
        push_access_as(k, rr(3) != 0, t, b, 0);
        maybe_kill(b);
        break;
    }
    case 5: {
        // A constant index in a register: an immediate offset.
        int c;
        if (rr(4) == 0) {
            c = -(int)(1u + rr(256));
        } else {
            c = (int)(k->size * rr(512));
        }
        push_text("mov x%u, #%d", i, c);
        const char *mnem = load || k->st == NULL ? k->ld : k->st;
        push_text("%s %c%u, [x28, x%u]", mnem, k->reg, t, i);
        maybe_kill(i);
        break;
    }
    case 6: {
        // A constant past one MOV in the index, the base moved down by
        // as much: an ADD of its high part and an immediate offset.
        unsigned c = 0x10000u + 8u * rr(0x8000);
        push_text("mov x%u, #%u", b, c & 0xFFFFu);
        push_text("movk x%u, #%u, lsl #16", b, c >> 16);
        push_text("sub x%u, x28, x%u", b, b);
        push_text("mov x%u, #%u", i, c & 0xFFFFu);
        push_text("movk x%u, #%u, lsl #16", i, c >> 16);
        push_text("ldr x%u, [x%u, x%u]", t, b, i);
        maybe_kill(i);
        break;
    }
    case 7: {
        // Two accesses to neighbouring slots: a pair, or one zero store.
        static const struct { const char *mnem; const char *reg; unsigned size; }
            pk[] = {
            { "ldr", "x", 8 }, { "ldr", "w", 4 }, { "str", "x", 8 },
            { "str", "w", 4 }, { "ldrsw", "x", 4 }, { "str", "wzr", 4 },
            { "ldr", "d", 8 }, { "str", "q", 16 },
        };
        unsigned j = rr(8);
        int off = (int)(pk[j].size * rr(16));
        if (rr(4) == 0) {
            off -= 4 * (int)pk[j].size;
        }
        bool reverse = rr(3) == 0;
        bool stp_wzr = rr(4) == 0;
        unsigned t2 = reg_besides(b, t);
        unsigned zoff = 4u * rr(32);
        push_base(b);
        for (unsigned n = 0; n < 2; n++) {
            int o = off + (int)((reverse ? 1u - n : n) * pk[j].size);
            if (strcmp(pk[j].reg, "wzr") == 0) {
                push_text("str wzr, [x%u, #%d]", b, o);
            } else {
                push_text("%s %s%u, [x%u, #%d]", pk[j].mnem, pk[j].reg,
                          n == 0 ? t : t2, b, o);
            }
        }
        if (stp_wzr) {
            push_text("stp wzr, wzr, [x%u, #%u]", b, zoff);
        }
        break;
    }
    case 8: {
        // A zero made for a store alone.
        bool x = rr(2) == 0;
        int off = 4 * (int)rr(64);
        push_base(b);
        push_text("mov %c%u, #0", x ? 'x' : 'w', t);
        push_text("str %c%u, [x%u, #%d]", x ? 'x' : 'w', t, b, off);
        maybe_kill(t);
        break;
    }
    case 9: {
        // A load and its sign extension.
        static const char *const lx[][2] = {
            { "ldrb w%u, [x%u, #%u]", "sxtb w%u, w%u" },
            { "ldrb w%u, [x%u, #%u]", "sxtb x%u, w%u" },
            { "ldrh w%u, [x%u, #%u]", "sxth w%u, w%u" },
            { "ldrh w%u, [x%u, #%u]", "sxth x%u, w%u" },
            { "ldr w%u, [x%u, #%u]", "sxtw x%u, w%u" },
            { "ldrsb w%u, [x%u, #%u]", "sxtb x%u, w%u" },
        };
        unsigned j = rr(6);
        unsigned off = 4u * rr(32);
        unsigned d = rr(5) == 0 ? i : t;
        push_base(b);
        push_text(lx[j][0], t, b, off);
        push_text(lx[j][1], d, t);
        break;
    }
    case 10: {
        // A sign-extended index: the extend folded into the access.
        int c = (int)rr(64) - 32;
        unsigned x = rr(4) == 0 ? t : i;
        bool scaled = rr(2) == 0;
        bool byte = rr(2) == 0;
        unsigned d = reg_besides(i, x);
        push_text("mov w%u, #%d", i, c);
        push_text("sxtw x%u, w%u", x, i);
        if (scaled) {
            push_text("ldr x%u, [x28, x%u, lsl #3]", d, x);
        } else {
            push_text("%s w%u, [x28, x%u]", byte ? "ldrb" : "str", d, x);
        }
        maybe_kill(x);
        break;
    }
    case 11: {
        // A store-release through a moved base (LRCPC2), at an address
        // aligned for it: a store-release faults on one that is not.
        unsigned kind = rr(3);
        unsigned imm = rr(256) & (kind == 0 ? ~0u : kind == 1 ? ~1u : ~3u);
        push_text("add x%u, x28, #%u", b, imm);
        push_text("%s w%u, [x%u]",
                  kind == 0 ? "stlrb" : kind == 1 ? "stlrh" : "stlr", t, b);
        maybe_kill(b);
        break;
    }
    case 12: {
        // The literal pool: an LDR (literal), or an ADR and a load.
        static const char *const lit[] = {
            "ldr x%u, #%u", "ldr w%u, #%u", "ldrsw x%u, #%u",
            "ldr d%u, #%u", "ldr s%u, #%u", "ldr q%u, #%u",
        };
        unsigned p = rr(7);
        unsigned j = rr(6);
        if (rr(3) == 0) {
            bool sw = rr(2) == 0;
            push_text("adr x%u, #%u", b, pool_off(p & 6u));
            push_text("%s x%u, [x%u]", sw ? "ldrsw" : "ldr", t, b);
            maybe_kill(b);
        } else {
            push_text(lit[j], t, pool_off(j == 5u ? 6u : p));
        }
        break;
    }
    case 13: {
        // A pair and its base: moved after (post-indexing), moved
        // before (pre-indexing), or a new base added once for an
        // offset (immediate).
        bool ldp = rr(2) == 0;
        unsigned how = rr(3);
        bool sub = rr(2) == 0;
        unsigned step = 16u * (1u + rr(4));
        int off = 8 * ((int)rr(16) - 4);
        unsigned t2 = reg_besides(b, t);
        unsigned t3 = reg_besides(i, t);
        const char *op = ldp ? "ldp" : "stp";
        push_base(b);
        if (how == 0) {
            push_text("%s x%u, x%u, [x%u]", op, t, t2, b);
            push_text("%s x%u, x%u, #%u", sub ? "sub" : "add", b, b, step);
        } else if (how == 1) {
            push_text("%s x%u, x%u, #%u", sub ? "sub" : "add", b, b, step);
            push_text("%s x%u, x%u, [x%u]", op, t, t2, b);
        } else {
            push_text("add x%u, x%u, #%u", i, b, step);
            push_text("%s x%u, x%u, [x%u, #%d]", op, t, t3, i, off);
            maybe_kill(i);
        }
        break;
    }
    case 15: {
        // An ADR of the word after a BR through it: a direct branch.
        unsigned at = (unsigned)(body_start + nbody) * 4u;
        bool x17 = rr(2) == 0;
        push_text("adr x%u, #%u", x17 ? 17u : 16u, at + 8u);
        push_text("br x%u", x17 ? 17u : 16u);
        break;
    }
    case 16: {
        // The same address made twice: the second ADR is a recompute.
        unsigned p = rr(8);
        push_text("adr x%u, #%u", b, pool_off(p));
        if (rr(2) == 0) {
            push_gap_besides(b);
        }
        push_text("adr x%u, #%u", b, pool_off(p));
        break;
    }
    default: {
        // A word loaded and converted through a general register.
        bool wide = rr(2) == 0;
        bool cross = rr(4) == 0;
        bool sgn = rr(2) == 0;
        unsigned v = rr(8);
        unsigned off = 8u * rr(16);
        push_base(b);
        push_text("ldr %c%u, [x%u, #%u]", wide ? 'x' : 'w', t, b, off);
        push_text("%s %c%u, %c%u", sgn ? "scvtf" : "ucvtf",
                  wide != cross ? 'd' : 's', v, wide ? 'x' : 'w', t);
        maybe_kill(t);
        break;
    }
    }
}

// A constant for a multiply, a divide or a shift to fold: a power of
// two, one either side of one, or anything.
static uint64_t mul_const(unsigned width)
{
    unsigned n = 1u + rr(width - 2u);
    switch (rr(5)) {
    case 0: return (1ull << n) + 1u;
    case 1: return (1ull << n) - 1u;
    case 2: return 2u + rr(30);
    default: return 1ull << n;
    }
}

// A MOVZ/MOVK chain of value v into r at the width: as short as the
// halfwords need, now and then a halfword longer.
static void push_chain(char w, unsigned r, uint64_t v)
{
    unsigned halves = w == 'x' ? 4u : 2u;
    bool first = true;
    for (unsigned h = 0; h < halves; h++) {
        unsigned part = (unsigned)(v >> (16u * h)) & 0xFFFFu;
        if (part == 0 && !(first && h + 1u == halves)) {
            continue;
        }
        if (first) {
            push_text("movz %c%u, #%u, lsl #%u", w, r, part, 16u * h);
            first = false;
        } else {
            push_text("movk %c%u, #%u, lsl #%u", w, r, part, 16u * h);
        }
    }
}

static void plant_arith(void)
{
    if (nbody + 8 > BODY_MAX) {
        return;
    }
    unsigned a = body_reg();
    unsigned b = reg_besides(a, a);
    unsigned c = reg_besides(a, b);
    unsigned d = rr(3) == 0 ? a : reg_besides(b, c);
    bool x = rr(2) == 0;
    char w = x ? 'x' : 'w';
    unsigned width = x ? 64u : 32u;
    unsigned cond = rr(14);
    const char *cc = cond_text[cond];
    switch (rr(40)) {
    case 0: {
        // MUL, MNEG, MADD or MSUB by a constant.
        static const char *const op[] = { "mul", "mneg", "madd", "msub" };
        unsigned j = rr(4);
        bool swap = rr(2) == 0;
        push_chain(w, a, mul_const(width));
        if (j < 2) {
            push_text("%s %c%u, %c%u, %c%u", op[j], w, d, w, swap ? a : b, w,
                      swap ? b : a);
        } else {
            push_text("%s %c%u, %c%u, %c%u, %c%u", op[j], w, d, w,
                      swap ? a : b, w, swap ? b : a, w, c);
        }
        maybe_kill(a);
        break;
    }
    case 1: {
        // UDIV by a constant, and the remainder after it.
        uint64_t k = rr(4) == 0 ? mul_const(width) : 1ull << (1u + rr(8));
        bool rem = rr(2) == 0;
        unsigned r = rr(2) == 0 ? c : a;
        push_chain(w, a, k);
        push_text("udiv %c%u, %c%u, %c%u", w, c, w, b, w, a);
        if (rem) {
            push_text("msub %c%u, %c%u, %c%u, %c%u", w, r, w, c, w, a, w, b);
        }
        break;
    }
    case 2: {
        // A MUL and the ADD, SUB or NEG of its product.
        unsigned j = rr(3);
        push_text("mul %c%u, %c%u, %c%u", w, a, w, b, w, c);
        if (j == 0) {
            push_text("add %c%u, %c%u, %c%u", w, d, w, a, w, c);
        } else if (j == 1) {
            push_text("sub %c%u, %c%u, %c%u", w, d, w, b, w, a);
        } else {
            push_text("neg %c%u, %c%u", w, d, w, a);
        }
        maybe_kill(a);
        break;
    }
    case 3: {
        // A widening multiply and the ADD, SUB or NEG of it.
        bool sgn = rr(2) == 0;
        unsigned j = rr(3);
        push_text("%s x%u, w%u, w%u", sgn ? "smull" : "umull", a, b, c);
        if (j == 0) {
            push_text("add x%u, x%u, x%u", d, a, b);
        } else if (j == 1) {
            push_text("sub x%u, x%u, x%u", d, c, a);
        } else {
            push_text("neg x%u, x%u", d, a);
        }
        maybe_kill(a);
        break;
    }
    case 4: {
        // NEG or MVN, then a consumer that has the inverted form.
        static const char *const neg_use[] = { "add", "sub", "csel" };
        static const char *const mvn_use[] = { "and", "orr", "eor", "ands",
                                               "csel" };
        bool neg = rr(2) == 0;
        unsigned j = neg ? rr(3) : rr(5);
        const char *use = neg ? neg_use[j] : mvn_use[j];
        push_text("%s %c%u, %c%u", neg ? "neg" : "mvn", w, a, w, b);
        if (strcmp(use, "csel") == 0) {
            push_text("csel %c%u, %c%u, %c%u, %s", w, d, w, c, w, a, cc);
        } else {
            push_text("%s %c%u, %c%u, %c%u", use, w, d, w, c, w, a);
        }
        maybe_kill(a);
        break;
    }
    case 5: {
        // ADD #1, MOV #1 or MOV #-1, then a CSEL of it: CSINC, CSINV.
        unsigned j = rr(3);
        bool then_slot = rr(2) == 0;
        if (j == 0) {
            push_text("add %c%u, %c%u, #1", w, a, w, b);
        } else {
            push_text("mov %c%u, #%d", w, a, j == 1 ? 1 : -1);
        }
        if (then_slot) {
            push_text("csel %c%u, %c%u, %c%u, %s", w, d, w, a, w, c, cc);
        } else {
            push_text("csel %c%u, %c%u, %c%u, %s", w, d, w, c, w, a, cc);
        }
        maybe_kill(a);
        break;
    }
    case 6: {
        // A MOV of a small constant and a CCMP/CCMN of it.
        int k = (int)rr(70) - 35;
        unsigned nzcv = rr(16);
        bool ccmn = rr(3) == 0;
        push_text("cmp %c%u, %c%u", w, b, w, c);
        push_text("mov %c%u, #%d", w, a, k);
        push_text("%s %c%u, %c%u, #%u, %s", ccmn ? "ccmn" : "ccmp", w, b, w,
                  a, nzcv, cc);
        maybe_kill(a);
        break;
    }
    case 7: {
        // A MOV and a shift by it.
        static const char *const sh[] = { "lsl", "lsr", "asr", "ror" };
        unsigned j = rr(4);
        unsigned k = rr(2 * width);
        push_text("mov %c%u, #%u", w, a, k);
        push_text("%s %c%u, %c%u, %c%u", sh[j], w, d, w, b, w, a);
        maybe_kill(a);
        break;
    }
    case 8: {
        // An extend and an ADD/SUB of it.
        static const char *const ext[] = { "sxtw x", "sxth x", "sxtb x",
                                           "uxth w", "uxtb w", "mov w" };
        unsigned j = rr(6);
        unsigned sh = rr(5);
        bool sub = rr(3) == 0;
        bool xa = ext[j][5] == 'x';
        push_text("%s%u, w%u", ext[j], a, b);
        if (sh == 0) {
            push_text("%s %c%u, %c%u, %c%u", sub ? "sub" : "add",
                      xa ? 'x' : w, d, xa ? 'x' : w, c, xa ? 'x' : w, a);
        } else {
            push_text("%s %c%u, %c%u, %c%u, lsl #%u", sub ? "sub" : "add",
                      xa ? 'x' : w, d, xa ? 'x' : w, c, xa ? 'x' : w, a, sh);
        }
        maybe_kill(a);
        break;
    }
    case 9: {
        // CSET or CSETM, then EOR #1, NEG, or a branch on it.
        unsigned j = rr(4);
        push_text("cmp %c%u, %c%u", w, b, w, c);
        push_text("cset w%u, %s", a, cc);
        if (j == 0) {
            push_text("eor w%u, w%u, #1", d, a);
        } else if (j == 1) {
            push_text("neg w%u, w%u", d, a);
        } else {
            unsigned form = j == 2 ? 3u + 2u * rr(2) : 6u;
            push_branch(form, a, 0, 0);
        }
        maybe_kill(a);
        break;
    }
    case 10: {
        // A single-bit TST and a CSET/CSETM or a B.EQ/NE on it, or a
        // CMP #0 and a sign CSET.
        unsigned bit = rr(width);
        unsigned j = rr(4);
        bool m = rr(2) == 0;
        bool lt = rr(2) == 0;
        if (j == 3) {
            push_text("cmp %c%u, #0", w, b);
            push_text("%s %c%u, %s", m ? "csetm" : "cset", w, d,
                      lt ? "lt" : "mi");
            break;
        }
        push_text("tst %c%u, #0x%llx", w, b, 1ull << bit);
        if (j == 0) {
            push_text("cset w%u, ne", d);
        } else if (j == 1) {
            push_text("csetm %c%u, %s", w, d, bit == width - 1u ? "mi" : "ne");
        } else {
            unsigned eq = rr(2);
            push_branch(2, 0, eq, 0);
        }
        break;
    }
    case 11: {
        // Bitfield pairs: AND/UXT + LSL, LSL + LSR/ASR, LSR + LSL,
        // AND + LSR.
        unsigned k1 = 1u + rr(width - 1u);
        unsigned k2 = 1u + rr(width - 1u);
        unsigned m = 1u + rr(width - 1u);
        bool h = rr(2) == 0;
        bool asr = rr(2) == 0;
        unsigned pick = rr(width);
        switch (rr(5)) {
        case 0:
            push_text("and %c%u, %c%u, #0x%llx", w, a, w, b,
                      (1ull << m) - 1u);
            push_text("lsl %c%u, %c%u, #%u", w, a, w, a, k1);
            break;
        case 1:
            push_text("%s w%u, w%u", h ? "uxth" : "uxtb", a, b);
            push_text("lsl w%u, w%u, #%u", a, a, k1 % 32u);
            break;
        case 2:
            push_text("lsl %c%u, %c%u, #%u", w, a, w, b, k1);
            push_text("%s %c%u, %c%u, #%u", asr ? "asr" : "lsr", w, a, w, a,
                      k2);
            break;
        case 3:
            push_text("lsr %c%u, %c%u, #%u", w, a, w, b, k1);
            push_text("lsl %c%u, %c%u, #%u", w, a, w, a, k1);
            break;
        default: {
            unsigned lo = pick % (width - 1u);
            unsigned hi = lo + (k2 % (width - lo));
            uint64_t mask = (hi - lo + 1u >= 64u ? ~0ull
                             : ((1ull << (hi - lo + 1u)) - 1u)) << lo;
            if (mask == (x ? ~0ull : 0xFFFFFFFFull)) {
                mask >>= 1;
            }
            push_text("and %c%u, %c%u, #0x%llx", w, a, w, b,
                      (unsigned long long)mask);
            push_text("lsr %c%u, %c%u, #%u", w, a, w, a,
                      lo + k1 % (hi - lo + 1u));
            break;
        }
        }
        break;
    }
    case 12: {
        // A funnel: two shifts of opposite ways ORed or added: EXTR,
        // or ROR when one register feeds both.
        unsigned k = 1u + rr(width - 1u);
        bool rot = rr(3) == 0;
        static const char *const comb[] = { "orr", "add", "eor" };
        unsigned j = rr(3);
        push_text("lsl %c%u, %c%u, #%u", w, a, w, b, k);
        push_text("%s %c%u, %c%u, %c%u, lsr #%u", comb[j], w, d, w, a, w,
                  rot ? b : c, width - k);
        maybe_kill(a);
        break;
    }
    case 13: {
        // BFI/BFXIL synthesized: clear a field, isolate one, OR them.
        unsigned lsb = rr(width / 2u);
        unsigned len = 1u + rr(width / 2u - 1u);
        uint64_t field = ((1ull << len) - 1u) << lsb;
        uint64_t keep = ~field & (x ? ~0ull : 0xFFFFFFFFull);
        unsigned j = rr(3);
        if (j == 2) {
            push_text("and %c%u, %c%u, #0x%llx", w, d, w, d,
                      (unsigned long long)((1ull << lsb) - 1u | (lsb == 0 ? 1u : 0u)));
            push_text("orr %c%u, %c%u, %c%u, lsl #%u", w, d, w, d, w, b,
                      lsb == 0 ? 1u : lsb);
            break;
        }
        push_text("and %c%u, %c%u, #0x%llx", w, d, w, d,
                  (unsigned long long)keep);
        if (lsb == 0 || j == 0) {
            push_text("and %c%u, %c%u, #0x%llx", w, a, w, b,
                      (unsigned long long)((1ull << len) - 1u));
        } else {
            push_text("ubfiz %c%u, %c%u, #%u, #%u", w, a, w, b, lsb, len);
        }
        push_text("orr %c%u, %c%u, %c%u", w, d, w, d, w, a);
        maybe_kill(a);
        break;
    }
    case 14: {
        // A shift and a consumer with a shifted-register form.
        static const char *const sh[] = { "lsl", "lsr", "asr" };
        static const char *const use[] = { "add", "sub", "and", "orr",
                                           "eor", "bic" };
        unsigned j = rr(3);
        unsigned u = rr(6);
        unsigned k = 1u + rr(width - 1u);
        push_text("%s %c%u, %c%u, #%u", sh[j], w, a, w, b, k);
        push_text("%s %c%u, %c%u, %c%u", use[u], w, d, w, c, w, a);
        maybe_kill(a);
        break;
    }
    case 15: {
        // A MOV chain and a logical operation of it: a bitmask
        // immediate, two of them, or neither.
        static const char *const op[] = { "and", "orr", "eor", "ands",
                                          "bic", "orn", "eon", "tst" };
        unsigned j = rr(8);
        unsigned lo = rr(width - 1u);
        unsigned len = 1u + rr(width - lo - 1u);
        uint64_t v = ((len >= 64u ? ~0ull : (1ull << len) - 1u) << lo);
        unsigned flip = rr(width);
        if (rr(3) == 0) {
            v ^= 1ull << flip;          // two runs now and then
        }
        if (!x) {
            v &= 0xFFFFFFFFull;
        }
        push_chain(w, a, v);
        if (j == 7) {
            push_text("tst %c%u, %c%u", w, b, w, a);
        } else {
            push_text("%s %c%u, %c%u, %c%u", op[j], w, d, w, b, w, a);
        }
        maybe_kill(a);
        break;
    }
    case 16: {
        // A compare against INT_MIN or INT_MAX and a branch on equality.
        bool min = rr(2) == 0;
        push_text("mov %c%u, #%s", w, a,
                  x ? (min ? "0x8000000000000000" : "0x7fffffffffffffff")
                    : (min ? "0x80000000" : "0x7fffffff"));
        push_text("cmp %c%u, %c%u", w, b, w, a);
        push_branch(2, 0, rr(2), 0);
        maybe_kill(a);
        break;
    }
    case 17: {
        // A masked field compared with a constant that fits shifted.
        unsigned lo = 4u + rr(7);
        unsigned len = 2u + rr(5);
        uint64_t mask = ((1ull << len) - 1u) << lo;
        uint64_t k = (1u + rr((1u << len) - 1u)) << lo;
        unsigned m = reg_besides(a, c);
        unsigned eq = rr(2);
        push_text("and w%u, w%u, #0x%llx", a, b, (unsigned long long)mask);
        push_text("mov w%u, #0x%llx", c, (unsigned long long)k);
        push_text("cmp w%u, w%u", a, c);
        // To a block that kills the field, the constant and the flags,
        // which the fall-through runs into too: the fold changes all
        // three, so both edges must prove them dead.
        push_branch(2, 0, eq, 0);
        body[nbody - 1].aim = 2;
        push_text("eor x%u, x%u, x%u", m, m, b);
        push_text("mov w%u, #2", a);
        push_text("mov w%u, #3", c);
        push_text("cmp x%u, x%u", m, b);
        break;
    }
    case 18: {
        // An ADD/SUB and a compare of its operands, either order; a
        // flag-setting one and its redundant compare.
        bool sub = rr(2) == 0;
        unsigned j = rr(3);
        if (j == 0) {
            push_text("%s %c%u, %c%u, %c%u", sub ? "sub" : "add", w, a, w, b,
                      w, c);
            push_text("%s %c%u, %c%u", sub ? "cmp" : "cmn", w, b, w, c);
        } else if (j == 1) {
            push_text("%s %c%u, %c%u", sub ? "cmp" : "cmn", w, b, w, c);
            push_text("%s %c%u, %c%u, %c%u", sub ? "sub" : "add", w, a, w, b,
                      w, c);
        } else {
            push_text("%s %c%u, %c%u, %c%u", sub ? "subs" : "adds", w, a, w,
                      b, w, c);
            push_text("%s %c%u, %c%u", sub ? "cmp" : "cmn", w, b, w, c);
        }
        break;
    }
    case 19: {
        // An ALU result and its zero test: the S-variant fold.
        static const char *const op[] = { "add", "sub", "and", "bic" };
        unsigned j = rr(4);
        bool tst = rr(3) == 0;
        push_text("%s %c%u, %c%u, %c%u", op[j], w, a, w, b, w, c);
        if (tst) {
            push_text("tst %c%u, %c%u", w, a, w, a);
        } else {
            push_text("cmp %c%u, #0", w, a);
        }
        push_branch(2, 0, rr(14), 0);
        break;
    }
    case 20: {
        // NEG and a CBZ/CBNZ of it.
        unsigned src = rr(3) == 0 ? a : b;
        bool nz = rr(2) == 0;
        push_text("neg %c%u, %c%u", w, a, w, src);
        push_branch(x ? (nz ? 4u : 0u) : (nz ? 1u : 3u), a, 0, 0);
        break;
    }
    case 21: {
        // A single-bit AND and a CBZ/CBNZ of it.
        unsigned bit = rr(32);
        bool nz = rr(2) == 0;
        push_text("and w%u, w%u, #0x%x", a, b, 1u << bit);
        push_branch(nz ? 1u : 3u, a, 0, 0);
        break;
    }
    case 22: {
        // Identities: ADD/SUB #0, a self-op, a ZR operand, a CSEL of
        // one register, a low-32 mask, a MOV to self.
        unsigned j = rr(9);
        unsigned s = rr(2) == 0 ? d : b;
        static const char *const self[] = { "and", "orr", "eor", "bic",
                                            "orn", "eon", "sub" };
        unsigned k = rr(7);
        bool sub = rr(2) == 0;
        switch (j) {
        case 0: push_text("%s %c%u, %c%u, #0", sub ? "sub" : "add", w, d, w,
                          s); break;
        case 1: push_text("%s %c%u, %c%u, %c%u", self[k], w, d, w, b, w, b);
                break;
        case 2: push_text("%s %c%u, %c%u, %czr", self[k], w, d, w, b, w);
                break;
        case 3: push_text("csel %c%u, %c%u, %c%u, %s", w, d, w, s, w, s, cc);
                break;
        case 4: push_text("and x%u, x%u, #0xffffffff", d, b); break;
        case 5: push_text("ubfx x%u, x%u, #0, #32", d, b); break;
        case 6: push_text("mov x%u, x%u", d, d); break;
        case 7: push_text("madd %c%u, %c%u, %czr, %c%u", w, d, w, b, w, w, c);
                break;
        default: push_text("mul %c%u, %c%u, %czr", w, d, w, b, w); break;
        }
        break;
    }
    case 23: {
        // ADD/SUB immediate chains, adjacent or not.
        unsigned k1 = rr(4096);
        unsigned k2 = rr(4096);
        bool s1 = rr(2) == 0;
        bool s2 = rr(2) == 0;
        push_text("%s %c%u, %c%u, #%u", s1 ? "sub" : "add", w, a, w, b, k1);
        if (rr(2) == 0) {
            push(filler());
        }
        push_text("%s %c%u, %c%u, #%u", s2 ? "sub" : "add", w, d, w, a, k2);
        break;
    }
    case 24: {
        // Copies: a copy then an in-place ADD/SUB, a copy of a copy, a
        // copy back.
        unsigned j = rr(3);
        bool sub = rr(2) == 0;
        unsigned k = 1u + rr(4095);
        push_text("mov %c%u, %c%u", w, a, w, b);
        if (j == 0) {
            push_text("%s %c%u, %c%u, #%u", sub ? "sub" : "add", w, a, w, a,
                      k);
        } else if (j == 1) {
            push_text("mov %c%u, %c%u", w, d == a ? c : d, w, a);
        } else {
            push_text("mov %c%u, %c%u", w, b, w, a);
        }
        break;
    }
    case 25: {
        // A one-instruction constant and a copy of it; a chain longer
        // than its value needs.
        uint64_t v = rr(2) == 0 ? rr(0x10000) : 0x55555555u;
        bool copy = rr(2) == 0;
        if (copy) {
            push_chain(w, a, v);
            push_text("mov %c%u, %c%u", w, d == a ? c : d, w, a);
        } else {
            push_text("movz %c%u, #%u", w, a, (unsigned)(v & 0xFFFFu));
            push_text("movk %c%u, #%u, lsl #16", w, a,
                      (unsigned)((v >> 16) & 0xFFFFu));
        }
        break;
    }
    case 26: {
        // A MOV chain and an ADD/SUB/CMP of it: one immediate, two, or
        // the other sign.
        uint64_t v;
        switch (rr(4)) {
        case 0: v = rr(4096); break;
        case 1: v = (uint64_t)rr(4096) << 12; break;
        case 2: v = (uint64_t)(1u + rr(4095)) << 12 | (1u + rr(4095)); break;
        default: v = 0 - (uint64_t)(1u + rr(4096)); break;
        }
        if (!x) {
            v &= 0xFFFFFFFFull;
        }
        unsigned j = rr(4);
        push_chain(w, a, v);
        if (j == 3) {
            push_text("cmp %c%u, %c%u", w, b, w, a);
        } else {
            push_text("%s %c%u, %c%u, %c%u", j == 0 ? "add" : j == 1 ? "sub"
                                                                     : "adds",
                      w, d, w, b, w, a);
        }
        maybe_kill(a);
        break;
    }
    case 27: {
        // A MOV #0 and a use the zero register can take.
        static const char *const use[] = { "add", "orr", "eor", "and" };
        unsigned j = rr(4);
        push_text("mov %c%u, #0", w, a);
        if (rr(3) == 0) {
            push_text("csel %c%u, %c%u, %c%u, %s", w, d, w, b, w, a, cc);
        } else {
            push_text("%s %c%u, %c%u, %c%u", use[j], w, d, w, b, w, a);
        }
        maybe_kill(a);
        break;
    }
    case 28: {
        // A CSET re-compared against zero for an EQ/NE select.
        bool ne = rr(2) == 0;
        unsigned e = reg_besides(a, d);
        push_text("cmp %c%u, %c%u", w, b, w, c);
        push_text("cset w%u, %s", a, cc);
        push_text("cmp w%u, #0", a);
        push_text("csel x%u, x%u, x%u, %s", d, e, b, ne ? "ne" : "eq");
        push_text("cmp x%u, x%u", e, b);
        maybe_kill(a);
        break;
    }
    case 29: {
        // A flag-setting ALU and a zero test it already made.
        static const char *const op[] = { "adds", "subs", "ands", "bics" };
        unsigned j = rr(4);
        unsigned eq = rr(2);
        push_text("%s %c%u, %c%u, %c%u", op[j], w, a, w, b, w, c);
        push_text("cmp %c%u, #0", w, a);
        push_branch(2, 0, eq, 0);
        break;
    }
    case 30: {
        // BFXIL synthesized: the top bits kept, an ORR of a register
        // shifted down into the rest.
        unsigned k = 1u + rr(width - 1u);
        uint64_t top = (x ? ~0ull : 0xFFFFFFFFull) << (width - k);
        if (!x) {
            top &= 0xFFFFFFFFull;
        }
        push_text("and %c%u, %c%u, #0x%llx", w, d, w, d,
                  (unsigned long long)top);
        push_text("orr %c%u, %c%u, %c%u, lsr #%u", w, d, w, d, w, b, k);
        break;
    }
    default: {
        // A MOV of 2^32 - k and a 64-bit compare of a 32-bit value.
        unsigned k = 1u + rr(4096);
        push_text("mov w%u, w%u", b, c);
        push_text("mov w%u, #%d", a, -(int)k);
        push_text("cmp x%u, x%u", b, a);
        push_branch(2, 0, rr(14), 0);
        maybe_kill(a);
        break;
    }
    }
}

static void plant_fp(void)
{
    if (nbody + 6 > BODY_MAX) {
        return;
    }
    unsigned a = body_reg();
    unsigned b = reg_besides(a, a);
    unsigned c = reg_besides(a, b);
    unsigned d = rr(3) == 0 ? a : reg_besides(b, c);
    bool dbl = rr(2) == 0;
    char f = dbl ? 'd' : 's';
    char g = dbl ? 'x' : 'w';
    unsigned cond = rr(14);
    const char *cc = cond_text[cond];
    static const char *const arr[] = { "16b", "8b" };
    const char *ar = arr[rr(2)];
    switch (rr(10)) {
    case 0:
        // FMUL and an FNEG of the product: FNMUL.
        push_text("fmul %c%u, %c%u, %c%u", f, a, f, b, f, c);
        push_text("fneg %c%u, %c%u", f, d, f, a);
        break;
    case 1: {
        // A constant moved through a general register: FMOV immediate,
        // or MOVI for zero.
        static const char *const k32[] = { "0x3f800000", "0x40000000",
                                           "0xbf800000", "0x3e000000", "0" };
        static const char *const k64[] = { "0x3ff0000000000000",
                                           "0x4000000000000000",
                                           "0xbfc0000000000000", "0" };
        unsigned j = dbl ? rr(4) : rr(5);
        unsigned how = rr(4);
        unsigned small = rr(8);
        if (how == 0) {
            push_text("mov w%u, #%u", a, small);
            push_text("%s %c%u, w%u", rr(2) == 0 ? "scvtf" : "ucvtf", f, d,
                      a);
        } else if (how == 1) {
            push_text("fmov %c%u, %czr", f, d, g);
        } else {
            push_text("mov %c%u, #%s", g, a, dbl ? k64[j] : k32[j]);
            push_text("fmov %c%u, %c%u", f, d, g, a);
        }
        maybe_kill(a);
        break;
    }
    case 2:
        // An FCSEL of one register.
        push_text("fcsel %c%u, %c%u, %c%u, %s", f, d, f, b, f, b, cc);
        break;
    case 3: {
        // UMOV of lane 0, and of another lane.
        static const char *const um[] = { "umov w%u, v%u.s[0]",
                                          "umov x%u, v%u.d[0]",
                                          "umov w%u, v%u.h[0]",
                                          "umov w%u, v%u.s[1]" };
        push_text(um[rr(4)], d, b);
        break;
    }
    case 4: {
        // Vector logic of one register: zero, a copy, or itself.
        static const char *const op[] = { "and", "orr", "eor", "bic", "sub" };
        unsigned j = rr(5);
        bool in_place = rr(2) == 0;
        if (j == 4) {
            push_text("sub v%u.4s, v%u.4s, v%u.4s", d, b, b);
        } else if (in_place) {
            push_text("%s v%u.%s, v%u.%s, v%u.%s", op[j], d, ar, d, ar, d, ar);
        } else {
            push_text("%s v%u.%s, v%u.%s, v%u.%s", op[j], d, ar, b, ar, b, ar);
        }
        break;
    }
    case 5: {
        // MOVI #0 and a compare against it: compare-with-zero.
        static const char *const cmp[] = { "cmeq", "cmge", "cmgt", "fcmeq",
                                           "fcmge", "fcmgt" };
        unsigned j = rr(6);
        bool left = rr(2) == 0;
        push_text("movi v%u.2d, #0", a);
        if (left) {
            push_text("%s v%u.4s, v%u.4s, v%u.4s", cmp[j], a, a, b);
        } else {
            push_text("%s v%u.4s, v%u.4s, v%u.4s", cmp[j], a, b, a);
        }
        break;
    }
    case 6: {
        // Two EORs, or a BIC and an EOR: EOR3, BCAX (SHA3).
        bool bic = rr(2) == 0;
        bool first = rr(2) == 0;
        unsigned e = rr(2) == 0 ? c : reg_besides(a, b);
        push_text("%s v%u.16b, v%u.16b, v%u.16b", bic ? "bic" : "eor", a, b,
                  c);
        if (first) {
            push_text("eor v%u.16b, v%u.16b, v%u.16b", d, a, e);
        } else {
            push_text("eor v%u.16b, v%u.16b, v%u.16b", d, e, a);
        }
        break;
    }
    case 7: {
        // A widening extend and an SCVTF/UCVTF of it.
        bool sx = rr(2) == 0;
        bool sgn = rr(2) == 0;
        if (sx) {
            push_text("sxtw x%u, w%u", a, b);
        } else {
            push_text("mov w%u, w%u", a, b);
        }
        push_text("%s %c%u, x%u", sgn ? "scvtf" : "ucvtf", f, d, a);
        maybe_kill(a);
        break;
    }
    case 8: {
        // FMOV copies: a chain, and a copy back.
        bool back = rr(2) == 0;
        push_text("fmov %c%u, %c%u", f, a, f, b);
        push_text("fmov %c%u, %c%u", f, back ? b : d, f, a);
        break;
    }
    default: {
        // Zero broadcast or converted from ZR.
        bool dup = rr(2) == 0;
        if (dup) {
            push_text("dup v%u.4s, wzr", d);
        } else {
            push_text("scvtf %c%u, %czr", f, d, g);
        }
        break;
    }
    }
}

static void plant_lse_loop(void);

// An exclusive-access loop on the scratch buffer: a fetch-and-op, a
// swap, or a compare-and-swap with its early exit -- what LSE does in
// one instruction. The loop's back edge is the only backward branch a
// program has. Its slots past the load-exclusive are no landing place
// for a branch: a store-exclusive reached without its load is not code
// the rewrite has to agree with (a failed CAS leaves the monitor armed
// for one).
static void plant_lse(void)
{
    if (nbody + 6 > BODY_MAX) {
        return;
    }
    int first = nbody;
    plant_lse_loop();
    for (int i = first + 1; i < nbody; i++) {
        body[i].interior = true;
    }
}

static void plant_lse_loop(void)
{
    unsigned old = body_reg();
    unsigned val = reg_besides(old, old);
    unsigned nv = reg_besides(old, val);
    unsigned st = reg_besides(nv, val);
    while (st == old) {
        st = reg_besides(nv, val);
    }
    static const char *const sizes[] = { "", "b", "h" };
    unsigned size = rr(4);          // 3: X
    bool x = size == 3;
    char w = x ? 'x' : 'w';
    const char *sz = size == 3 ? "" : sizes[size];
    bool acq = rr(2) == 0;
    bool rel = rr(2) == 0;
    unsigned at = (unsigned)(body_start + nbody) * 4u;
    switch (rr(4)) {
    case 0:
    case 1: {
        static const char *const op[] = { "add", "orr", "eor", "bic", "and",
                                          "sub" };
        unsigned j = rr(7);
        unsigned imm = 1u + rr(4095);
        push_text("ld%sxr%s %c%u, [x28]", acq ? "a" : "", sz, w, old);
        if (j == 6) {
            push_text("add %c%u, %c%u, #%u", w, nv, w, old, imm);
        } else {
            push_text("%s %c%u, %c%u, %c%u", op[j], w, nv, w, old, w, val);
        }
        push_text("st%sxr%s w%u, %c%u, [x28]", rel ? "l" : "", sz, st, w, nv);
        push_text("cbnz w%u, #%u", st, at);
        break;
    }
    case 2:
        push_text("ld%sxr%s %c%u, [x28]", acq ? "a" : "", sz, w, old);
        push_text("st%sxr%s w%u, %c%u, [x28]", rel ? "l" : "", sz, st, w, val);
        push_text("cbnz w%u, #%u", st, at);
        break;
    default:
        push_text("ld%sxr %c%u, [x28]", acq ? "a" : "", w, old);
        push_text("cmp %c%u, %c%u", w, old, w, val);
        push_text("b.ne #%u", at + 20u);
        push_text("st%sxr w%u, %c%u, [x28]", rel ? "l" : "", st, w, nv);
        push_text("cbnz w%u, #%u", st, at);
        break;
    }
}

static void gen_body(void (*plant)(void))
{
    nbody = 0;
    int len = 10 + (int)rr(20);
    while (nbody < len) {
        unsigned p = rr(100);
        if (p < 35) {
            plant();
        } else if (p < 45) {
            push_transfer(SLOT_BRANCH);
        } else if (p < 49) {
            push_transfer(SLOT_CALL);
        } else {
            push(filler());
        }
    }
    // Branches go forward only -- to a later body slot or the epilogue
    // -- so every program terminates; and never into a plant's interior,
    // where an access would go through a base no path set up.
    for (int i = 0; i < nbody; i++) {
        int t = body[i].aim > 0 && i + body[i].aim <= nbody
            ? i + body[i].aim
            : i + 1 + (int)rr((unsigned)(nbody - i));
        while (t < nbody && body[t].interior && body[i].aim == 0) {
            t++;
        }
        body[i].target = t;
    }
}

static bool asm_word(const char *key, uint32_t *word);

static void assemble(void)
{
    int k = 0;
    for (size_t i = 0; i < sizeof(prologue) / 4u; i++) {
        prog[k++] = prologue[i];
    }
    prog[k] = b_(POOL_AT + 16 - k);
    k++;
    while (k < POOL_AT) {
        prog[k++] = NOP;
    }
    for (unsigned i = 0; i < 8; i++) {
        prog[k++] = (uint32_t)pool[i];
        prog[k++] = (uint32_t)(pool[i] >> 32);
    }
    k += nbody;
    epi_start = k;
    for (size_t i = 0; i < sizeof(epilogue) / 4u; i++) {
        prog[k++] = epilogue[i];
    }
    // The stub: x0..x7 get top halves set, v0..v7 a byte pattern, NZCV
    // a fixed pattern.
    stub_start = k;
    for (unsigned r = 0; r < 8; r++) {
        prog[k++] = movz_x(r, 0xBEE0u + r, 0);
        prog[k++] = movk_x(r, 0xDEADu, 3);
        prog[k++] = 0x4F05E600u + 0x21u * r;    // movi vr.16b, #0xb0+r
    }
    prog[k++] = cmp_x(0, 1);
    prog[k++] = RET;
    nprog = k;

    for (int i = 0; i < nbody; i++) {
        const slot_t *s = &body[i];
        int at = body_start + i;
        int words = body_start + s->target - at;
        switch (s->kind) {
        case SLOT_PLAIN:
            prog[at] = s->word;
            break;
        case SLOT_TEXT:
            if (!asm_word(s->text, &prog[at])) {
                fprintf(stderr, "rwfuzz: the assembler refused a plant's "
                        "\"%s\"\n", s->text);
                exit(2);
            }
            break;
        case SLOT_BRANCH:
            switch (s->form) {
            case 2: prog[at] = b_cond(s->cond, words); break;
            case 3: prog[at] = cbz(false, false, s->reg, words); break;
            case 4: prog[at] = cbz(true, true, s->reg, words); break;
            case 5: prog[at] = tbz(false, s->reg, s->bit, words); break;
            case 6: prog[at] = tbz(true, s->reg, s->bit, words); break;
            default:
                prog[at] = cbz(s->form == 0, s->form == 1, s->reg, words);
                break;
            }
            break;
        case SLOT_READER:
            prog[at] = b_cond(s->cond, words);
            break;
        case SLOT_JUMP:
            prog[at] = b_(words);
            break;
        default:
            prog[at] = bl(stub_start - at);
            break;
        }
    }
}

// === armlint ===

static csh cs;
static unsigned features;       // the extensions the host runs

typedef struct {
    const char *name;
    size_t start;       // word index of the finding's first instruction
    unsigned count;
    char detail[ARMLINT_FINDING_DETAIL_LEN];
    unsigned nedits;
    armlint_edit edits[ARMLINT_FINDING_EDITS];
} hit_t;

#define HITS_MAX 64

// A program and the findings of interest in it: generated and analyzed
// a batch at a time, so that one run of the assembler serves the batch,
// and then run.
typedef struct {
    slot_t body[BODY_MAX];
    int nbody;
    uint32_t prog[PROG_MAX];
    int nprog, epi_start, stub_start;
    int nhits;
    hit_t hits[HITS_MAX];
} program_t;

static program_t *cur;

typedef struct mode mode_t_;
static const mode_t_ *mode;

static bool wanted(const armlint_finding *f);

static void record(const armlint_finding *f)
{
    if (cur->nhits < HITS_MAX && wanted(f)) {
        hit_t *h = &cur->hits[cur->nhits++];
        h->name = f->name;
        h->start = f->start_offset / 4u;
        h->count = f->insn_count;
        snprintf(h->detail, sizeof(h->detail), "%s", f->detail);
        h->nedits = f->nedits;
        memcpy(h->edits, f->edits, sizeof(h->edits));
    }
}

// Run the registry over the program the way the driver does -- with the
// buffer and the host's features set, so branch targets and target
// scans work and no finding suggests what the host cannot run -- and
// keep the mode's findings.
static void analyze(void)
{
    cur->nhits = 0;
    armlint_state *st = armlint_state_create();
    armlint_state_set_features(st, features);
    armlint_state_set_buffer(st, (const uint8_t *)prog, (size_t)nprog * 4u);
    cs_insn *insn = cs_malloc(cs);
    const uint8_t *p = (const uint8_t *)prog;
    size_t size = (size_t)nprog * 4u;
    uint64_t addr = 0;
    armlint_finding f;
    while (size >= 4) {
        uint64_t at = addr;
        if (cs_disasm_iter(cs, &p, &size, &addr, insn)) {
            for (size_t k = 0; k < armlint_check_registry_count; k++) {
                if (armlint_check_registry[k](st, insn, (size_t)at, &f)
                        && !armlint_finding_has_side_entry(st, &f)) {
                    record(&f);
                }
            }
        } else {
            if (armlint_flush(st, &f)
                    && !armlint_finding_has_side_entry(st, &f)) {
                record(&f);
            }
            p += 4;
            size -= 4;
            addr += 4;
        }
    }
    if (armlint_flush(st, &f) && !armlint_finding_has_side_entry(st, &f)) {
        record(&f);
    }
    cs_free(insn, 1);
    armlint_state_destroy(st);
}

// === Execution ===

// The memory the programs load from and store to: x28 points at its
// middle, so that a base a plant moves down by an ADD's or a SUB's
// immediate, or an unscaled negative offset, stays inside it. What the
// original left there is compared with what the rewrite did.
#define SCRATCH_SIZE 16384u
static uint32_t *jit;           // the code as it runs
static uint32_t *jit_rw;        // ... and as it is written (jit on macOS)
static uint8_t *scratch;
static uint8_t scratch_init[SCRATCH_SIZE];
static uint8_t scratch_after[SCRATCH_SIZE];

// The code and the scratch memory sit at the same addresses in every
// run: their addresses reach the registers (x28 plus an offset, an ADR
// of the pool), so a control arm's outcome -- or a broken rewrite's --
// can turn on their bits, which ASLR would change from one run, or one
// worker, to the next. The addresses are hints, which both kernels take
// when the range is free. macOS scatters malloc's regions at random
// over 0x7000000000..0x7fffffffff and takes no hint below it, so they
// sit above, at 1 TB; a Linux kernel with a 39-bit user space cannot
// place them there. Where one is not taken the run goes on, and says
// so.
//
// The code sits 3 GB below x28: off the multiples of 2 GB that the
// edge values move a base by (0x80000000, 1 << 32, a top half of ones),
// so that a base a refused rewrite left off by one of them meets
// unmapped memory rather than the program. At 4 GB below, the control
// arm reached into the code.
#define JIT_AT     0x10040000000ull
#define SCRATCH_AT 0x10100000000ull

// Map SIZE bytes at AT (none in particular when 0), of FD or anonymous.
static void *map_at(uint64_t at, size_t size, int prot, int flags, int fd)
{
    void *m = mmap((void *)(uintptr_t)at, size, prot, flags, fd, 0);
    if (m == MAP_FAILED) {
        perror("rwfuzz: mmap");
        return NULL;
    }
    if (at != 0 && (uintptr_t)m != at) {
        fprintf(stderr, "rwfuzz: memory for %#" PRIx64 " landed at %p, so "
                "runs may differ in what turns on its address\n", at, m);
    }
    return m;
}

static bool jit_open(void)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t size = (PROG_MAX * 4u + page - 1u) / page * page;
#if defined(__APPLE__)
    jit = map_at(JIT_AT, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANON | MAP_JIT, -1);
    jit_rw = jit;
#else
    // Two views of one memory, the way a JIT keeps W^X: the code is
    // written through one and runs from the other, which the program
    // cannot write. A store a refused rewrite aims into the code then
    // faults, as macOS's write protection makes it there, rather than
    // changing the program under it.
    int fd = -1;
#if defined(MFD_EXEC)
    // Executable by request: since Linux 6.3, vm.memfd_noexec can make
    // a memfd that asks for nothing unexecutable. A kernel from before
    // knows no MFD_EXEC, and refuses it.
    fd = memfd_create("rwfuzz", MFD_CLOEXEC | MFD_EXEC);
#endif
    if (fd < 0) {
        fd = memfd_create("rwfuzz", MFD_CLOEXEC);
    }
    if (fd < 0 || ftruncate(fd, (off_t)size) != 0) {
        perror("rwfuzz: memfd_create");
        return false;
    }
    jit_rw = map_at(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd);
    jit = map_at(JIT_AT, size, PROT_READ | PROT_EXEC, MAP_SHARED, fd);
    close(fd);
#endif
    scratch = map_at(SCRATCH_AT, SCRATCH_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1);
    return jit != NULL && jit_rw != NULL && scratch != NULL;
}

static void jit_load(const uint32_t *code, size_t words)
{
#if defined(__APPLE__)
    pthread_jit_write_protect_np(0);
    memcpy(jit, code, words * 4u);
    pthread_jit_write_protect_np(1);
    sys_icache_invalidate(jit, words * 4u);
#else
    memcpy(jit_rw, code, words * 4u);
    // Cleaned to the point of unification through the view written,
    // and invalidated in the instruction cache through the view run.
    __builtin___clear_cache((char *)jit_rw, (char *)(jit_rw + words));
    __builtin___clear_cache((char *)jit, (char *)(jit + words));
#endif
}

// A rewrite can fault where the original did not -- an instruction the
// host lacks, an address the original never formed -- or loop where it
// branched forward. Either is a difference, so a run ends in the
// signal that stopped it rather than taking rwfuzz down: faults on an
// alternate stack (the rewrite may have moved SP), and a 50 ms tick
// that stops a run still going since the tick before (a run takes
// microseconds).
static sigjmp_buf run_env;
static volatile sig_atomic_t run_active, run_signal;
static volatile unsigned long run_seq, run_seen;

// Where rwfuzz is, for a fault outside a run: that one is rwfuzz's own
// (or a run's that corrupted it), and kills it, so the handler says
// where before it does -- what is printed at the end never will be.
static const char *volatile at_phase = "starting";
static volatile long at_program = -1;

static const char *signal_name(int sig);

// Append S to the message in BUF at *N, as far as CAP allows; a signal
// handler cannot call printf.
static void note_str(char *buf, size_t cap, size_t *n, const char *s)
{
    for (; *s != '\0' && *n + 1u < cap; s++) {
        buf[(*n)++] = *s;
    }
}

static void note_crash(int sig)
{
    char buf[160], digits[24];
    size_t n = 0, d = 0;
    unsigned long v = at_program < 0 ? 0 : (unsigned long)at_program;
    do {
        digits[d++] = (char)('0' + v % 10u);
        v /= 10u;
    } while (v != 0 && d < sizeof(digits));
    char num[24];
    for (size_t i = 0; i < d; i++) {
        num[i] = digits[d - 1u - i];
    }
    num[d] = '\0';
    note_str(buf, sizeof(buf), &n, "rwfuzz: ");
    note_str(buf, sizeof(buf), &n, signal_name(sig));
    note_str(buf, sizeof(buf), &n, " outside a run, ");
    note_str(buf, sizeof(buf), &n, at_phase);
    if (at_program >= 0) {
        note_str(buf, sizeof(buf), &n, " program ");
        note_str(buf, sizeof(buf), &n, num);
    }
    note_str(buf, sizeof(buf), &n, "\n");
    ssize_t w = write(2, buf, n);
    (void)w;
}

static void on_signal(int sig)
{
    if (sig == SIGALRM) {
        if (!run_active || run_seq != run_seen) {
            run_seen = run_seq;
            return;
        }
    }
    if (run_active) {
        run_active = 0;
        run_signal = sig;
        siglongjmp(run_env, 1);
    }
    note_crash(sig);
    signal(sig, SIG_DFL);
    raise(sig);
}

static bool guard_open(void)
{
    static uint8_t altstack[1u << 16];
    stack_t ss = { .ss_sp = altstack, .ss_size = sizeof(altstack) };
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sa.sa_flags = SA_ONSTACK | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    struct itimerval tick = { { 0, 50000 }, { 0, 50000 } };
    if (sigaltstack(&ss, NULL) != 0
            || sigaction(SIGSEGV, &sa, NULL) != 0
            || sigaction(SIGBUS, &sa, NULL) != 0
            || sigaction(SIGILL, &sa, NULL) != 0
            || sigaction(SIGTRAP, &sa, NULL) != 0
            || sigaction(SIGFPE, &sa, NULL) != 0
            || sigaction(SIGALRM, &sa, NULL) != 0
            || setitimer(ITIMER_REAL, &tick, NULL) != 0) {
        perror("rwfuzz: signals");
        return false;
    }
    return true;
}

// Run code from *in into *out: 0, or the signal that stopped it
// (SIGALRM: it ran on past a tick).
static int run(const uint32_t *code, const regs_t *in, regs_t *out)
{
    jit_load(code, (size_t)nprog);
    memcpy(scratch, scratch_init, SCRATCH_SIZE);
    *out = *in;
    out->buf = (uint64_t)(uintptr_t)(scratch + SCRATCH_SIZE / 2u);
    if (sigsetjmp(run_env, 1) != 0) {
        return run_signal;
    }
    run_seq++;
    run_active = 1;
    ((void (*)(regs_t *))(void *)jit)(out);
    run_active = 0;
    return 0;
}

static uint64_t edge_value(void)
{
    switch (rr(10)) {
    case 0: return 0;
    case 1: return ~0ull;
    case 2: return 0xFFFFFFFFull;
    case 3: return 0x80000000ull;
    case 4: return 0xFFFFFFFF00000000ull | rr(0x10000);
    case 5: return rr(4) == 0 ? rr(0x1000) : rr(48);
    case 6: return 0 - (uint64_t)rr(48);
    case 7: return (uint64_t)(1u + rr(3)) << 32;    // W zero, X not
    default: return rnd();
    }
}

// A vector register's 128 bits: zero, all ones, lanes of small integers
// or of the floats an FP fold must keep exact -- 1.0, -0.0, an
// infinity, a NaN -- or random bits.
static void edge_vector(uint8_t q[16])
{
    static const uint32_t floats[] = {
        0x3F800000u, 0x80000000u, 0x7F800000u, 0x7FC00001u, 0xBF800000u,
        0x40490FDBu, 0x00000001u,
    };
    unsigned kind = rr(6);
    for (unsigned i = 0; i < 16; i += 4) {
        uint32_t lane;
        switch (kind) {
        case 0: lane = 0; break;
        case 1: lane = ~0u; break;
        case 2: lane = rr(8); break;
        case 3: lane = floats[rr(sizeof(floats) / sizeof(floats[0]))]; break;
        case 4: lane = (uint32_t)edge_value(); break;
        default: lane = (uint32_t)rnd(); break;
        }
        memcpy(q + i, &lane, 4);
    }
}

static void random_state(regs_t *s)
{
    for (int i = 0; i < 8; i++) {
        s->x[i] = edge_value();
        edge_vector(s->q[i]);
    }
    s->nzcv = (uint64_t)rr(16) << 28;
    for (size_t i = 0; i < sizeof(scratch_init); i += 8) {
        uint64_t v = rnd();
        memcpy(scratch_init + i, &v, 8);
    }
}

static void dump(FILE *o, const uint32_t *code, const char *heading)
{
    fprintf(o, "---- %s\n", heading);
    cs_insn *insn = cs_malloc(cs);
    for (int i = 0; i < nprog; i++) {
        const uint8_t *p = (const uint8_t *)&code[i];
        size_t size = 4;
        uint64_t addr = (uint64_t)i * 4u;
        if (i >= POOL_AT && i < body_start) {
            fprintf(o, "  %4x: %08x  (pool)\n", i * 4, code[i]);
        } else if (cs_disasm_iter(cs, &p, &size, &addr, insn)) {
            fprintf(o, "  %4x: %08x  %s %s\n", i * 4, code[i],
                    insn->mnemonic, insn->op_str);
        } else {
            fprintf(o, "  %4x: %08x  .word\n", i * 4, code[i]);
        }
    }
    cs_free(insn, 1);
}

// Run both programs from TRIALS random states; true if all agreed. On a
// difference, *diff_in gets the state that showed it and *sig the
// signal that stopped the rewrite, or 0. The original only branches
// forward and only touches the scratch buffer, so its faulting is the
// harness's bug, and rwfuzz stops there.
#define TRIALS 6

static bool same_results(const uint32_t *alt, regs_t *diff_in, int *sig)
{
    for (int t = 0; t < TRIALS; t++) {
        regs_t in, a, b;
        random_state(&in);
        int sa = run(prog, &in, &a);
        if (sa != 0) {
            dump(stdout, prog, "the original program");
            fprintf(stderr, "rwfuzz: the original program stopped on "
                    "signal %d\n", sa);
            exit(2);
        }
        memcpy(scratch_after, scratch, SCRATCH_SIZE);
        int sb = run(alt, &in, &b);
        if (sb != 0 || memcmp(a.x, b.x, sizeof(a.x)) != 0
                || a.nzcv != b.nzcv || memcmp(a.q, b.q, sizeof(a.q)) != 0
                || memcmp(scratch_after, scratch, SCRATCH_SIZE) != 0) {
            if (diff_in != NULL) {
                *diff_in = in;
            }
            if (sig != NULL) {
                *sig = sb;
            }
            return false;
        }
    }
    return true;
}


// === Assembling the rewrites ===
//
// A finding carries its rewrite as text, the advice a reader sees, so
// that what runs here is what the text says: each instruction goes
// through the host's own assembler. It runs once per batch of programs
// over every text the batch needs that no batch before it did, and the
// words are cached by text. RWFUZZ_CC names the compiler driver that
// assembles (default cc); the -march it is given covers what the host
// runs.

static char asm_dir[512];       // a private temporary directory
static char asm_march[128];

typedef struct {
    char *text;                 // NULL: a free slot
    uint32_t word;
    int state;                  // 1 assembled, -1 refused, 0 pending
} asm_entry;

static asm_entry *asm_tab;
static size_t asm_cap, asm_used;
static char **asm_pending;      // texts owned by asm_tab
static size_t asm_npending, asm_pending_cap;

static uint64_t fnv1a(const char *s)
{
    uint64_t h = 0xCBF29CE484222325ull;
    for (; *s != '\0'; s++) {
        h = (h ^ (uint8_t)*s) * 0x100000001B3ull;
    }
    return h;
}

static asm_entry *asm_find(const char *text)
{
    size_t i = (size_t)fnv1a(text) & (asm_cap - 1u);
    while (asm_tab[i].text != NULL && strcmp(asm_tab[i].text, text) != 0) {
        i = (i + 1u) & (asm_cap - 1u);
    }
    return &asm_tab[i];
}

// The entry for TEXT, made pending when it is new.
static asm_entry *asm_entry_for(const char *text)
{
    if (2u * (asm_used + 1u) > asm_cap) {
        asm_entry *old = asm_tab;
        size_t old_cap = asm_cap;
        asm_cap = asm_cap != 0 ? 2u * asm_cap : 4096u;
        asm_tab = calloc(asm_cap, sizeof(*asm_tab));
        if (asm_tab == NULL) {
            perror("rwfuzz: calloc");
            exit(2);
        }
        for (size_t i = 0; i < old_cap; i++) {
            if (old[i].text != NULL) {
                *asm_find(old[i].text) = old[i];
            }
        }
        free(old);
    }
    asm_entry *e = asm_find(text);
    if (e->text == NULL) {
        e->text = strdup(text);
        e->state = 0;
        asm_used++;
        if (asm_npending == asm_pending_cap) {
            asm_pending_cap = asm_pending_cap != 0 ? 2u * asm_pending_cap
                                                   : 1024u;
            asm_pending = realloc(asm_pending,
                                  asm_pending_cap * sizeof(*asm_pending));
        }
        if (e->text == NULL || asm_pending == NULL) {
            perror("rwfuzz: alloc");
            exit(2);
        }
        asm_pending[asm_npending++] = e->text;
    }
    return e;
}

// An edit's text as the assembler takes it in word AT. A PC-relative
// operand -- a branch's target, a literal load's address, ADR's -- is
// the absolute offset the finding shows (the program is analyzed at
// address 0), and becomes .+N from the word the instruction lands in.
static bool asm_text(const char *text, size_t at, char *out, size_t cap)
{
    const char *sp = strchr(text, ' ');
    size_t mlen = sp != NULL ? (size_t)(sp - text) : strlen(text);
    char mnem[16];
    if (mlen >= sizeof(mnem)) {
        return false;
    }
    memcpy(mnem, text, mlen);
    mnem[mlen] = '\0';
    const char *ops = sp != NULL ? sp + 1 : "";
    bool pcrel = strcmp(mnem, "b") == 0 || strcmp(mnem, "bl") == 0
        || strncmp(mnem, "b.", 2) == 0 || strncmp(mnem, "bc.", 3) == 0
        || strncmp(mnem, "cb", 2) == 0              // CBZ/CBNZ and CMPBR
        || strcmp(mnem, "tbz") == 0 || strcmp(mnem, "tbnz") == 0
        || strcmp(mnem, "adr") == 0
        || ((strncmp(mnem, "ldr", 3) == 0 || strcmp(mnem, "prfm") == 0)
            && strchr(ops, '[') == NULL);
    if (!pcrel) {
        return (size_t)snprintf(out, cap, "%s", text) < cap;
    }
    const char *opnd = strrchr(ops, ',');
    opnd = opnd != NULL ? opnd + 1 : ops;
    while (*opnd == ' ') {
        opnd++;
    }
    const char *num = *opnd == '#' ? opnd + 1 : opnd;
    char *end;
    unsigned long long target = strtoull(num, &end, 0);
    if (end == num || *end != '\0') {
        return false;
    }
    long long rel = (long long)target - (long long)(at * 4u);
    return (size_t)snprintf(out, cap, "%.*s.%c%lld", (int)(opnd - text),
                            text, rel < 0 ? '-' : '+',
                            rel < 0 ? -rel : rel) < cap;
}

// A plant's text, made pending under the key the assembler takes at
// word AT; the key, owned by the cache. A text asm_text cannot place is
// the plant's bug.
static const char *asm_intern(const char *text, size_t at)
{
    char key[160];
    if (!asm_text(text, at, key, sizeof(key))) {
        fprintf(stderr, "rwfuzz: a plant's \"%s\" has no assembler text\n",
                text);
        exit(2);
    }
    return asm_entry_for(key)->text;
}

// The word for KEY, once the assembler has run over it.
static bool asm_word(const char *key, uint32_t *word)
{
    asm_entry *e = asm_find(key);
    if (e->text == NULL || e->state != 1) {
        return false;
    }
    *word = e->word;
    return true;
}

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)rd16(p) | (uint32_t)rd16(p + 2) << 16; }
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | (uint64_t)rd32(p + 4) << 32; }

// Where the object's text section lies: a Mach-O or ELF 64-bit object.
static bool text_section(const uint8_t *b, size_t n, size_t *off,
                         size_t *size)
{
    if (n >= 32 && rd32(b) == 0xFEEDFACFu) {
        uint32_t ncmds = rd32(b + 16);
        size_t p = 32;
        for (uint32_t c = 0; c < ncmds && p + 8 <= n; c++) {
            uint32_t cmd = rd32(b + p), cmdsize = rd32(b + p + 4);
            if (cmd == 0x19u && p + 72 <= n) {      // LC_SEGMENT_64
                uint32_t nsects = rd32(b + p + 64);
                for (uint32_t k = 0; k < nsects; k++) {
                    size_t s = p + 72 + 80u * k;
                    if (s + 80 > n) {
                        return false;
                    }
                    if (strncmp((const char *)b + s, "__text", 16) == 0) {
                        *size = (size_t)rd64(b + s + 40);
                        *off = rd32(b + s + 48);
                        return *off + *size <= n;
                    }
                }
            }
            if (cmdsize == 0) {
                return false;
            }
            p += cmdsize;
        }
        return false;
    }
    if (n >= 64 && memcmp(b, "\177ELF", 4) == 0 && b[4] == 2) {
        uint64_t shoff = rd64(b + 0x28);
        size_t shentsize = rd16(b + 0x3A), shnum = rd16(b + 0x3C);
        size_t shstrndx = rd16(b + 0x3E);
        if (shentsize < 0x28 || shstrndx >= shnum
                || shoff + shnum * shentsize > n) {
            return false;
        }
        uint64_t strtab = rd64(b + shoff + shstrndx * shentsize + 0x18);
        for (size_t k = 0; k < shnum; k++) {
            const uint8_t *sh = b + shoff + k * shentsize;
            uint64_t name = strtab + rd32(sh);
            if (name + 6 <= n
                    && memcmp(b + name, ".text", 6) == 0) {
                *off = (size_t)rd64(sh + 0x18);
                *size = (size_t)rd64(sh + 0x20);
                return *off + *size <= n;
            }
        }
    }
    return false;
}

// Assemble the n texts, one per line; true with their words when the
// assembler took them all. Otherwise the lines it named are marked in
// bad[] and *named counts them -- zero when it failed some other way,
// with its output on stderr.
static bool asm_once(char **texts, size_t n, uint32_t *words, bool *bad,
                     size_t *named)
{
    char src[600], obj[600], cmd[2048];
    snprintf(src, sizeof(src), "%s/r.s", asm_dir);
    snprintf(obj, sizeof(obj), "%s/r.o", asm_dir);
    *named = 0;
    FILE *f = fopen(src, "w");
    if (f == NULL) {
        perror(src);
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        fprintf(f, "%s\n", texts[i]);
    }
    fclose(f);
    const char *cc = getenv("RWFUZZ_CC");
    snprintf(cmd, sizeof(cmd), "%s -c -x assembler -march=%s -o '%s' '%s' "
             "2>&1", cc != NULL ? cc : "cc", asm_march, obj, src);
    FILE *p = popen(cmd, "r");
    if (p == NULL) {
        perror("rwfuzz: popen");
        return false;
    }
    char line[1024], first[1024] = "";
    while (fgets(line, sizeof(line), p) != NULL) {
        if (first[0] == '\0') {
            snprintf(first, sizeof(first), "%s", line);
        }
        const char *at = strstr(line, "r.s:");
        char *end = NULL;
        unsigned long l = at != NULL ? strtoul(at + 4, &end, 10) : 0;
        if (l >= 1 && l <= n && end != at + 4 && *end == ':' && !bad[l - 1]) {
            bad[l - 1] = true;
            (*named)++;
        }
    }
    int status = pclose(p);
    if (status != 0 || *named != 0) {
        if (*named == 0) {
            fprintf(stderr, "rwfuzz: %s\n  %s", cmd, first);
        }
        return false;
    }
    f = fopen(obj, "rb");
    if (f == NULL) {
        perror(obj);
        return false;
    }
    uint8_t *buf = NULL;
    size_t len = 0, cap = 0, got;
    do {
        if (len == cap) {
            cap = cap != 0 ? 2u * cap : 65536u;
            uint8_t *nb = realloc(buf, cap);
            if (nb == NULL) {
                free(buf);
                fclose(f);
                return false;
            }
            buf = nb;
        }
        got = fread(buf + len, 1, cap - len, f);
        len += got;
    } while (got != 0);
    fclose(f);
    size_t off, size;
    bool ok = text_section(buf, len, &off, &size) && size == 4u * n;
    for (size_t i = 0; ok && i < n; i++) {
        words[i] = rd32(buf + off + 4u * i);
    }
    free(buf);
    if (!ok) {
        fprintf(stderr, "rwfuzz: %s: no text section of %zu words\n", obj,
                n);
    }
    return ok;
}

// Assemble every pending text. False when the assembler cannot be run
// at all; a text it refuses is only marked, and costs its findings.
static bool asm_flush(void)
{
    while (asm_npending > 0) {
        size_t n = asm_npending;
        uint32_t *words = malloc(n * sizeof(*words));
        bool *bad = calloc(n, sizeof(*bad));
        if (words == NULL || bad == NULL) {
            perror("rwfuzz: alloc");
            exit(2);
        }
        size_t named;
        bool ok = asm_once(asm_pending, n, words, bad, &named);
        if (ok) {
            for (size_t i = 0; i < n; i++) {
                asm_entry *e = asm_find(asm_pending[i]);
                e->word = words[i];
                e->state = 1;
            }
            asm_npending = 0;
        } else if (named != 0) {
            size_t k = 0;
            for (size_t i = 0; i < n; i++) {
                if (bad[i]) {
                    asm_find(asm_pending[i])->state = -1;
                } else {
                    asm_pending[k++] = asm_pending[i];
                }
            }
            asm_npending = k;
        }
        free(words);
        free(bad);
        if (!ok && named == 0) {
            return false;
        }
    }
    return true;
}

// The extensions the host runs, as armlint's feature bits -- so that no
// finding suggests an instruction the host would fault on -- and as the
// assembler's -march.
#if defined(__APPLE__)
static bool sysctl_flag(const char *name)
{
    int v = 0;
    size_t len = sizeof(v);
    return sysctlbyname(name, &v, &len, NULL, 0) == 0 && v != 0;
}
#endif

static unsigned host_features(void)
{
    bool lse = false, sha3 = false, rcpc2 = false, fp16 = false;
    bool cssc = false, cmpbr = false;
#if defined(__APPLE__)
    lse = sysctl_flag("hw.optional.arm.FEAT_LSE");
    sha3 = sysctl_flag("hw.optional.arm.FEAT_SHA3");
    rcpc2 = sysctl_flag("hw.optional.arm.FEAT_LRCPC2");
    fp16 = sysctl_flag("hw.optional.arm.FEAT_FP16");
    cssc = sysctl_flag("hw.optional.arm.FEAT_CSSC");
    cmpbr = sysctl_flag("hw.optional.arm.FEAT_CMPBR");
#elif defined(__linux__)
    unsigned long hw = getauxval(AT_HWCAP);
    lse = (hw & HWCAP_ATOMICS) != 0;
    sha3 = (hw & HWCAP_SHA3) != 0;
    rcpc2 = (hw & HWCAP_ILRCPC) != 0;
    fp16 = (hw & HWCAP_FPHP) != 0 && (hw & HWCAP_ASIMDHP) != 0;
#if defined(HWCAP2_CSSC)
    cssc = (getauxval(AT_HWCAP2) & HWCAP2_CSSC) != 0;
#endif
#endif
    snprintf(asm_march, sizeof(asm_march), "armv8.4-a%s%s%s%s",
             sha3 ? "+sha3" : "", fp16 ? "+fp16" : "", cssc ? "+cssc" : "",
             cmpbr ? "+cmpbr" : "");
    return (lse ? ARMLINT_FEATURE_LSE : 0u)
        | (sha3 ? ARMLINT_FEATURE_SHA3 : 0u)
        | (rcpc2 ? ARMLINT_FEATURE_LRCPC2 : 0u)
        | (fp16 ? ARMLINT_FEATURE_FP16 : 0u)
        | (cssc ? ARMLINT_FEATURE_CSSC : 0u)
        | (cmpbr ? ARMLINT_FEATURE_CMPBR : 0u);
}

static bool asm_open(void)
{
    const char *tmp = getenv("TMPDIR");
    snprintf(asm_dir, sizeof(asm_dir), "%s/rwfuzz.XXXXXX",
             tmp != NULL && tmp[0] != '\0' ? tmp : "/tmp");
    if (mkdtemp(asm_dir) == NULL) {
        perror("rwfuzz: mkdtemp");
        return false;
    }
    return true;
}

static void asm_close(void)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/r.s", asm_dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/r.o", asm_dir);
    unlink(path);
    rmdir(asm_dir);
}

// === Applying a finding ===

// What a finding's edits come to in this program.
enum { EDITS_APPLY, EDITS_OUTSIDE, EDITS_NONE, EDITS_REFUSED };

// Each edit's text as the assembler takes it, into keys; EDITS_OUTSIDE
// when an edit falls outside the body (the prologue, epilogue and stub
// are the harness's), EDITS_NONE when the finding names no rewrite.
static int edit_keys(const hit_t *h,
                     char keys[][ARMLINT_FINDING_EDIT_LEN + 32])
{
    if (h->nedits == 0 || h->nedits > ARMLINT_FINDING_EDITS) {
        return EDITS_NONE;
    }
    for (unsigned i = 0; i < h->nedits; i++) {
        const armlint_edit *e = &h->edits[i];
        size_t w = e->offset / 4u;
        if (e->offset % 4u != 0 || w < (size_t)body_start
                || w >= (size_t)epi_start) {
            return EDITS_OUTSIDE;
        }
        keys[i][0] = '\0';
        if (e->text[0] != '\0'
                && !asm_text(e->text, w, keys[i], sizeof(keys[i]))) {
            return EDITS_REFUSED;
        }
    }
    return EDITS_APPLY;
}

// Ask for the words a finding's edits need.
static void request_edits(const hit_t *h)
{
    char keys[ARMLINT_FINDING_EDITS][ARMLINT_FINDING_EDIT_LEN + 32];
    if (edit_keys(h, keys) == EDITS_APPLY) {
        for (unsigned i = 0; i < h->nedits; i++) {
            if (keys[i][0] != '\0') {
                asm_entry_for(keys[i]);
            }
        }
    }
}

// Apply a finding's edits to code: a deleted word becomes a NOP, so
// that every branch keeps its target.
static int apply_edits(const hit_t *h, uint32_t *code)
{
    char keys[ARMLINT_FINDING_EDITS][ARMLINT_FINDING_EDIT_LEN + 32];
    int r = edit_keys(h, keys);
    if (r != EDITS_APPLY) {
        return r;
    }
    for (unsigned i = 0; i < h->nedits; i++) {
        size_t w = h->edits[i].offset / 4u;
        if (keys[i][0] == '\0') {
            code[w] = NOP;
            continue;
        }
        asm_entry *e = asm_find(keys[i]);
        if (e->text == NULL || e->state != 1) {
            return EDITS_REFUSED;
        }
        code[w] = e->word;
    }
    return EDITS_APPLY;
}

// === Modes ===
//
// Each per-check mode's special count, and its control arm.

// zext: the consumer is further on than the instruction after its
// producer.
static bool zext_special(const hit_t *h)
{
    return h->count > 2u;
}

// An in-place UXT*/UBFX #0, a low-mask AND in place, or MOV Wd, Wd.
static bool is_zext_consumer(uint32_t w)
{
    unsigned d = w & 31u, n = (w >> 5) & 31u, m = (w >> 16) & 31u;
    if ((w & 0xFFE0FFE0u) == 0x2A0003E0u) {
        return d == m;
    }
    return d == n && ((w >> 16) & 63u) == 0
        && ((w & 0xFFC00000u) == 0x53000000u
            || (w & 0xFFC00000u) == 0xD3400000u
            || (w & 0xFFC00000u) == 0x12000000u
            || (w & 0xFFC00000u) == 0x92400000u);
}

// Control: delete a quarter of the unflagged consumers.
static bool zext_control(int i, uint32_t *alt)
{
    if (!is_zext_consumer(prog[i]) || rr(4) != 0) {
        return false;
    }
    alt[i] = NOP;
    return true;
}

// The UBFX a shift + AND pair folds to, from the two words; the LSR arm's
// width cap is applied, the ASR arm never needs it.
static uint32_t ubfx_of(uint32_t shift, uint32_t and_w)
{
    bool x = (shift >> 31) != 0;
    unsigned ds = x ? 64u : 32u;
    unsigned n = (shift >> 16) & 63u;
    unsigned s = (shift >> 5) & 31u;
    unsigned d = and_w & 31u;
    unsigned w = ((and_w >> 10) & 63u) + 1u;
    if (n + w > ds) {
        w = ds - n;
    }
    return x ? ubfm_x(d, s, n, n + w - 1u) : ubfm_w(d, s, n, n + w - 1u);
}

// ubfx: the AND writes another register than the shift.
static bool ubfx_special(const hit_t *h)
{
    return (prog[h->start + 1u] & 31u) != (prog[h->start] & 31u);
}

// Control: fold an unflagged LSR/ASR + AND low-mask of its result.
static bool ubfx_control(int i, uint32_t *alt)
{
    if (i + 1 >= epi_start) {
        return false;
    }
    uint32_t a = prog[i], b = prog[i + 1];
    bool shift = ((a & 0x7F800000u) == 0x53000000u
                  || (a & 0x7F800000u) == 0x13000000u)
        && ((a >> 10) & 63u) == ((a >> 31) != 0 ? 63u : 31u)
        && ((a >> 16) & 63u) != 0;
    bool mask = ((b & 0xFFC00000u) == 0x12000000u
                 || (b & 0xFFC00000u) == 0x92400000u)
        && ((b >> 16) & 63u) == 0 && ((b >> 5) & 31u) == (a & 31u)
        && (a >> 31) == (b >> 31);
    if (!shift || !mask) {
        return false;
    }
    alt[i + 1] = ubfx_of(a, b);
    alt[i] = NOP;
    return true;
}

// ccmp: the chain's reader is a branch.
static bool ccmp_special(const hit_t *h)
{
    return (prog[h->start + h->count - 1u] & 0xFF000010u) == 0x54000000u;
}

// Control: cut an unflagged chain to a CMP/CMN of its last immediate.
static bool ccmp_control(int i, uint32_t *alt)
{
    uint32_t a = prog[i];
    if ((a & 0x3FC0001Fu) != 0x3100001Fu || i + 1 >= epi_start) {
        return false;
    }
    int j = i + 1;
    while (j < epi_start && (prog[j] & 0x3FE00C10u) == 0x3A400800u
            && ((prog[j] >> 5) & 31u) == ((a >> 5) & 31u)) {
        j++;
    }
    if (j == i + 1) {
        return false;
    }
    uint32_t last = prog[j - 1];
    alt[i] = cmp_imm((a >> 31) != 0, ((last >> 30) & 1u) == 0,
                     (a >> 5) & 31u, (last >> 16) & 31u);
    for (int k = i + 1; k < j; k++) {
        alt[k] = NOP;
    }
    return true;
}

// The value came from further back than the previous instruction.
static bool lvn_special(const hit_t *h)
{
    const char *s = strstr(h->detail, "(set 0x");
    unsigned long back = s != NULL ? strtoul(s + 5, NULL, 16) : 0;
    return back > 4u;
}

// Control: delete an unflagged instruction whose exact word ran within the
// last six slots.
static bool lvn_control(int i, uint32_t *alt)
{
    bool repeat = false;
    for (int j = i - 1; j >= body_start && j >= i - 6; j--) {
        if (prog[j] == prog[i]) {
            repeat = true;
        }
    }
    if (!repeat || prog[i] == NOP) {
        return false;
    }
    alt[i] = NOP;
    return true;
}

// The overwrite is not the next instruction: some slot between writes
// another register.
static bool dead_special(const hit_t *h)
{
    size_t next = h->start + 1u;
    return next < (size_t)epi_start
        && (prog[next] & 31u) != (prog[h->start] & 31u);
}

// Control: delete an unflagged ALU or move write whose register the next
// four slots write again.
static bool dead_control(int i, uint32_t *alt)
{
    uint32_t w = prog[i];
    bool alu = (w & 0x1F000000u) == 0x0B000000u        // add/sub (shifted)
        || (w & 0x1F000000u) == 0x0A000000u            // logical (shifted)
        || (w & 0x1F800000u) == 0x11000000u            // add/sub (immediate)
        || (w & 0x1F800000u) == 0x12800000u            // move wide
        || (w & 0x1F800000u) == 0x13000000u            // bitfield
        || (w & 0x1FE00000u) == 0x1A800000u            // csel family
        || (w & 0x1F000000u) == 0x1B000000u;           // 3-source
    if (!alu || ((w >> 29) & 1u) != 0 || (w & 31u) == 31u) {
        return false;
    }
    for (int j = i + 1; j < epi_start && j <= i + 4; j++) {
        if ((prog[j] & 31u) == (w & 31u)) {
            alt[i] = NOP;
            return true;
        }
    }
    return false;
}

// cmn: the compare's reader is a branch.
static bool cmn_special(const hit_t *h)
{
    return (prog[h->start + 2u] & 0xFF000010u) == 0x54000000u;
}

// Control: fold an unflagged MOV of 2^32 - k (k encodable) + CMP Xr, Xc.
static bool cmn_control(int i, uint32_t *alt)
{
    if (i + 1 >= epi_start) {
        return false;
    }
    uint32_t mov = prog[i], cmp = prog[i + 1];
    unsigned c = mov & 31u;
    uint64_t v;
    if ((mov & 0xFFE00000u) == 0x12800000u) {            // movn w, #imm
        v = ~((uint64_t)((mov >> 5) & 0xFFFFu)) & 0xFFFFFFFFu;
    } else if (mov == movz_w(c, 0xFFFFu, 1)) {
        v = 0xFFFF0000u;
    } else {
        return false;
    }
    uint64_t k = (1ull << 32) - v;
    bool lsl12 = k > 0xFFFu;
    if ((lsl12 && ((k & 0xFFFu) != 0 || k > 0xFFF000u))
            || (cmp & 0xFFE0FC1Fu) != 0xEB00001Fu
            || ((cmp >> 16) & 31u) != c) {
        return false;
    }
    unsigned n = (cmp >> 5) & 31u;
    alt[i] = NOP;
    alt[i + 1] = cmn_w_imm(n, (unsigned)(lsl12 ? k >> 12 : k), lsl12);
    return true;
}

// A conditional branch's displacement in words: TBZ/TBNZ's imm14,
// CBZ/CBNZ's and B.cond's imm19.
static int32_t branch_disp(uint32_t w)
{
    if ((w & 0x7E000000u) == 0x36000000u) {
        return (int32_t)(((w >> 5) & 0x3FFFu) << 18) >> 18;
    }
    return (int32_t)(((w >> 5) & 0x7FFFFu) << 13) >> 13;
}

// branch: always taken, made a B.
static bool branch_special(const hit_t *h)
{
    return strstr(h->detail, "always taken") != NULL;
}

// Control: delete an unflagged conditional branch, or make it a B --
// a forward one: an exclusive loop's back edge made a B would spin.
static bool branch_control(int i, uint32_t *alt)
{
    uint32_t w = prog[i];
    bool cond = ((w & 0xFF000010u) == 0x54000000u && (w & 0xFu) < 14u)
        || (w & 0x7E000000u) == 0x34000000u
        || (w & 0x7E000000u) == 0x36000000u;
    if (!cond || branch_disp(w) <= 0 || rr(2) != 0) {
        return false;
    }
    alt[i] = rr(2) == 0 ? NOP : b_(branch_disp(w));
    return true;
}

// fold: the operation is deleted rather than made a MOV.
static bool fold_special(const hit_t *h)
{
    return strncmp(h->detail, "-> delete;", 10) == 0;
}

// Control: replace an unflagged ALU write by a MOV of a small constant.
static bool fold_control(int i, uint32_t *alt)
{
    uint32_t w = prog[i];
    bool alu = ((w & 0x1F000000u) == 0x0B000000u
                || (w & 0x1F000000u) == 0x0A000000u
                || (w & 0x1F800000u) == 0x11000000u
                || (w & 0x1F800000u) == 0x13000000u
                || (w & 0x1F000000u) == 0x1B000000u)
        && ((w >> 29) & 1u) == 0 && (w & 31u) < 8u;
    if (!alu || rr(2) != 0) {
        return false;
    }
    alt[i] = movz_x(w & 31u, rr(48), 0);
    return true;
}

// and: the AND/UBFX is deleted rather than made a MOV.
static bool and_special(const hit_t *h)
{
    return strncmp(h->detail, "-> delete;", 10) == 0;
}

// Control: make an unflagged AND/UBFX #0 of a body register the copy (or,
// in place, delete it).
static bool and_control(int i, uint32_t *alt)
{
    uint32_t w = prog[i];
    bool x = (w >> 31) != 0;
    bool ubfx = (w & 0x7F800000u) == 0x53000000u && ((w >> 16) & 63u) == 0;
    if (((w & 0x7F800000u) != 0x12000000u && !ubfx) || (w & 31u) >= 8u
            || ((w >> 5) & 31u) >= 8u || rr(2) != 0) {
        return false;
    }
    unsigned d = w & 31u, n = (w >> 5) & 31u;
    alt[i] = d == n ? NOP : x ? mov_x(d, n) : mov_w(d, n);
    return true;
}

// Special: the straight walk from the branch target meets a B, CBZ/CBNZ
// or TBZ/TBNZ before anything that touches the flags -- a proof that
// had to follow it.
static bool cbz_special(const hit_t *h)
{
    int i = (int)h->start + 1 + branch_disp(prog[h->start + 1u]);
    for (; i >= 0 && i < nprog; i++) {
        uint32_t w = prog[i];
        if ((w & 0xFC000000u) == 0x14000000u
                || (w & 0x7C000000u) == 0x34000000u) {
            return true;
        }
        if (classify_liveness(w) != LIV_UNKNOWN) {
            return false;
        }
    }
    return false;
}

// A zero test the fold opens on: CMP/CMN Rn, #0 or Rn, ZR, or TST Rn,
// Rn. *subs is false for the CMN and TST forms, which leave C clear.
static bool zero_test(uint32_t w, bool *x, unsigned *rn, bool *subs)
{
    unsigned n = (w >> 5) & 31u;
    if ((w & 31u) != 31u || n >= 8u) {
        return false;
    }
    bool imm0 = ((w >> 10) & 0xFFFu) == 0;
    bool zr = ((w >> 16) & 31u) == 31u && ((w >> 10) & 63u) == 0;
    if ((w & 0x7F800000u) == 0x71000000u && imm0) {
        *subs = true;                   // cmp Rn, #0
    } else if ((w & 0x7F800000u) == 0x31000000u && imm0) {
        *subs = false;                  // cmn Rn, #0
    } else if ((w & 0x7F200000u) == 0x6B000000u && zr) {
        *subs = true;                   // cmp Rn, zr
    } else if ((w & 0x7F200000u) == 0x2B000000u && zr) {
        *subs = false;                  // cmn Rn, zr
    } else if ((w & 0x7F200000u) == 0x6A000000u
               && ((w >> 16) & 31u) == n && ((w >> 10) & 63u) == 0) {
        *subs = false;                  // tst Rn, Rn
    } else {
        return false;
    }
    *x = (w >> 31) != 0;
    *rn = n;
    return true;
}

// Control: fold an unflagged zero test + B.cond the way the finding
// would have.
static bool cbz_control(int i, uint32_t *alt)
{
    bool x, subs;
    unsigned rn;
    if (i - 1 < body_start || (prog[i] & 0xFF000010u) != 0x54000000u
            || !zero_test(prog[i - 1], &x, &rn, &subs)) {
        return false;
    }
    int32_t words = branch_disp(prog[i]);
    unsigned bit = x ? 63u : 31u;
    switch (prog[i] & 15u) {
    case 0: alt[i] = cbz(x, false, rn, words); break;               // eq
    case 1: alt[i] = cbz(x, true, rn, words); break;                // ne
    case 9: if (!subs) return false;                                 // ls
            alt[i] = cbz(x, false, rn, words); break;
    case 8: if (!subs) return false;                                 // hi
            alt[i] = cbz(x, true, rn, words); break;
    case 4: case 11: alt[i] = tbz(true, rn, bit, words); break;     // mi, lt
    case 5: case 10: alt[i] = tbz(false, rn, bit, words); break;    // pl, ge
    default: return false;
    }
    alt[i - 1] = NOP;
    return true;
}

static uint32_t ccmp_reg_word(bool x, bool ccmn, unsigned n, unsigned m,
                              unsigned nzcv, unsigned c)
{
    return (x ? 0x80000000u : 0) | (ccmn ? 0x3A400000u : 0x7A400000u)
        | m << 16 | c << 12 | n << 5 | nzcv;
}

// Special: the two branches share a target (OR); otherwise the first
// lands past the second (AND).
static bool cbc_special(const hit_t *h)
{
    size_t b1 = h->start, b2 = h->start + 2u;
    return (int)b1 + branch_disp(prog[b1]) == (int)b2 + branch_disp(prog[b2]);
}

// The NZCV under which COND holds, as the check tables it.
static unsigned cbc_nzcv_holding(unsigned cond)
{
    static const unsigned nzcv[14] = {
        4, 0, 2, 0, 8, 0, 1, 0, 2, 0, 0, 8, 0, 4,
    };
    return cond < 14u ? nzcv[cond] : 0;
}

// Control: merge any B.cond + CMP/CMN + B.cond in the OR or AND shape
// the way the finding would have, with no proof at the merged exit.
static bool cbc_control(int i, uint32_t *alt)
{
    if (i + 2 >= epi_start || (prog[i] & 0xFF000010u) != 0x54000000u
            || (prog[i + 2] & 0xFF000010u) != 0x54000000u) {
        return false;
    }
    unsigned c1 = prog[i] & 15u, c2 = prog[i + 2] & 15u;
    uint32_t c = prog[i + 1];
    bool imm_form = (c & 0x3F80001Fu) == 0x3100001Fu;
    bool reg_form = (c & 0x3F20001Fu) == 0x2B00001Fu;
    if (c1 >= 14u || c2 >= 14u
            || !(imm_form ? ((c >> 22) & 1u) == 0 && ((c >> 10) & 0xFFFu) <= 31u
                            && ((c >> 5) & 31u) != 31u
                          : reg_form && ((c >> 22) & 3u) == 0
                            && ((c >> 10) & 63u) == 0)) {
        return false;
    }
    int t1 = i + branch_disp(prog[i]), t2 = i + 2 + branch_disp(prog[i + 2]);
    bool is_or = t1 == t2 && t2 != i + 3, is_and = t1 == i + 3 && t2 != i + 3;
    if (!is_or && !is_and) {
        return false;
    }
    unsigned nzcv = cbc_nzcv_holding(is_or ? c2 : c2 ^ 1u);
    bool x = (c >> 31) != 0, ccmn = ((c >> 30) & 1u) == 0;
    unsigned n = (c >> 5) & 31u;
    alt[i] = imm_form
        ? ccmp_imm(x, ccmn, n, (c >> 10) & 31u, nzcv, c1 ^ 1u)
        : ccmp_reg_word(x, ccmn, n, (c >> 16) & 31u, nzcv, c1 ^ 1u);
    alt[i + 1] = NOP;
    return true;
}

// Special: the in-place forms (CINC/CNEG/CINV), whose alias prints the
// inverted condition.
static bool hammock_special(const hit_t *h)
{
    return strncmp(h->detail, "-> ci", 5) == 0 || strncmp(h->detail, "-> cn", 5) == 0;
}

// The select for a skipped word, as the check spells it, or 0.
static uint32_t csel_for(uint32_t op, unsigned cond)
{
    unsigned d = op & 31u, n = (op >> 5) & 31u, m = (op >> 16) & 31u;
    uint32_t sf = op & 0x80000000u;
    if (d == 31u) {
        return 0;
    }
    if ((op & 0x7FE0FFE0u) == 0x2A0003E0u) {
        return m == d ? 0 : sf | 0x1A800000u | m << 16 | cond << 12 | d << 5 | d;
    }
    if ((op & 0x7F800000u) == 0x52800000u) {
        unsigned imm = (op >> 5) & 0xFFFFu, hw = (op >> 21) & 3u;
        if (imm == 0) {
            return sf | 0x1A800000u | 31u << 16 | cond << 12 | d << 5 | d;
        }
        return imm == 1u && hw == 0
            ? sf | 0x1A800400u | 31u << 16 | cond << 12 | d << 5 | d : 0;
    }
    if ((op & 0x7F800000u) == 0x12800000u) {
        return ((op >> 5) & 0xFFFFu) == 0
            ? sf | 0x5A800000u | 31u << 16 | cond << 12 | d << 5 | d : 0;
    }
    if ((op & 0x7FFFFC00u) == 0x11000400u && n == d) {
        return sf | 0x1A800400u | d << 16 | cond << 12 | d << 5 | d;
    }
    if ((op & 0x7FE0FFE0u) == 0x4B0003E0u && m == d) {
        return sf | 0x5A800400u | d << 16 | cond << 12 | d << 5 | d;
    }
    if ((op & 0x7FE0FFE0u) == 0x2A2003E0u && m == d) {
        return sf | 0x5A800000u | d << 16 | cond << 12 | d << 5 | d;
    }
    return 0;
}

// Control: fold any B.cond over one instruction with a select, side
// entry or not and whatever the top half of a W form's register holds.
static bool hammock_control(int i, uint32_t *alt)
{
    if (i + 1 >= epi_start || (prog[i] & 0xFF000010u) != 0x54000000u
            || (prog[i] & 15u) >= 14u || ((prog[i] >> 5) & 0x7FFFFu) != 2u) {
        return false;
    }
    uint32_t w = csel_for(prog[i + 1], prog[i] & 15u);
    if (w == 0) {
        return false;
    }
    alt[i] = w;
    alt[i + 1] = NOP;
    return true;
}

// Sign-crossed: an ADD split into SUBs or a SUB into ADDs.
static bool split_special(const hit_t *h)
{
    bool sub = (prog[h->start + h->count - 1u] >> 30) & 1u;
    return sub != (strncmp(h->detail, "-> sub", 6) == 0);
}

// Control: split an unflagged chain + ADD/SUB anyway -- its constant
// register read later or never proven dead, an ADDS or SUBS, a shifted
// operand -- whenever the value it reads is within reach.
static bool split_control(int i, uint32_t *alt)
{
    uint32_t cons = prog[i];
    if ((cons & 0x1F200000u) != 0x0B000000u || i < body_start + 2) {
        return false;
    }
    bool x = (cons >> 31) != 0, sub = ((cons >> 30) & 1u) != 0;
    unsigned d = cons & 31u, n = (cons >> 5) & 31u, m = (cons >> 16) & 31u;
    // The chain before it: MOVKs back to a MOVZ or MOVN, one register
    // and width.
    int first = i - 1;
    uint32_t w = prog[first];
    unsigned c = w & 31u;
    bool xc = (w >> 31) != 0;
    while (first > body_start && (prog[first] & 0x7F800000u) == 0x72800000u
           && (prog[first] & 31u) == c && ((prog[first] >> 31) != 0) == xc) {
        first--;
    }
    w = prog[first];
    unsigned opc = (w >> 29) & 3u;
    if ((w & 0x1F800000u) != 0x12800000u || (w & 31u) != c
            || ((w >> 31) != 0) != xc || (opc != 0u && opc != 2u)
            || first == i - 1) {
        return false;
    }
    uint64_t v = (uint64_t)((w >> 5) & 0xFFFFu) << (16u * ((w >> 21) & 3u));
    if (opc == 0u) {
        v = ~v;
    }
    for (int k = first + 1; k < i; k++) {
        unsigned sh = 16u * ((prog[k] >> 21) & 3u);
        v = (v & ~(0xFFFFull << sh)) | (uint64_t)((prog[k] >> 5) & 0xFFFFu) << sh;
    }
    unsigned other;
    if (m == c && n != c) {
        other = n;
    } else if (!sub && n == c && m != c) {
        other = m;
    } else {
        return false;
    }
    if (other == 31u || d == 31u) {
        return false;
    }
    uint64_t mask = x ? ~0ull : 0xFFFFFFFFull;
    v &= xc ? ~0ull : 0xFFFFFFFFull;
    v &= mask;
    uint64_t mag = v;
    bool crossed = false;
    if (v >= 1ull << 24) {
        mag = (0 - v) & mask;
        if (mag >= 1ull << 24) {
            return false;
        }
        crossed = true;
    }
    unsigned hi = (unsigned)(mag >> 12), lo = (unsigned)(mag & 0xFFFu);
    if (hi == 0 || lo == 0) {
        return false;
    }
    for (int k = first; k < i - 1; k++) {
        alt[k] = NOP;
    }
    alt[i - 1] = addsub_imm(x, sub != crossed, d, other, hi, true);
    alt[i] = addsub_imm(x, sub != crossed, d, d, lo, false);
    return true;
}

struct mode {
    const char *name;
    const char *findings[2];        // the finding names the mode tests;
                                    // none for "all", which tests every
                                    // finding that names a rewrite
    const char *special;            // what the second count counts
    void (*plant)(void);
    bool (*is_special)(const hit_t *);
    bool (*control)(int, uint32_t *);
};

static void plant_any(void);
static bool control_any(int i, uint32_t *alt);

static const mode_t_ modes[] = {
    { "zext", { "redundant zero-extension after zeroing op", NULL },
      "across a gap", plant_zext, zext_special, zext_control },
    { "ubfx", { "LSR+AND foldable into UBFX", "ASR+AND foldable into UBFX" },
      "out of place", plant_shift_and, ubfx_special, ubfx_control },
    { "ccmp", { "CMP + CCMP chain decidable by one compare", NULL },
      "with a branch reader", plant_ccmp_chain, ccmp_special, ccmp_control },
    { "lvn", { "register already holds the recomputed value",
               "ADR/ADRP of an address its register already holds" },
      "not adjacent", plant_recompute, lvn_special, lvn_control },
    { "dead", { "register write overwritten unread", NULL },
      "across a gap", plant_dead_write, dead_special, dead_control },
    { "cmn", { "MOV + CMP of a 32-bit value against 2^32-k foldable to "
               "W-form CMN", NULL },
      "with a branch reader", plant_cmp_cmn, cmn_special, cmn_control },
    { "branch", { "conditional branch that is never taken",
                  "conditional branch that is always taken" },
      "always taken", plant_decided, branch_special, branch_control },
    { "fold", { "operation on known values foldable to MOV #imm",
                "operation on known values leaves its register unchanged" },
      "deleted", plant_fold, fold_special, fold_control },
    { "and", { "AND/UBFX that known bits make a no-op", NULL },
      "deleted", plant_and, and_special, and_control },
    { "cbz", { "compare-zero branch foldable into CBZ/CBNZ",
               "compare-zero signed-branch foldable into TBZ/TBNZ" },
      "through a branch at the target", plant_cbz, cbz_special,
      cbz_control },
    { "split", { "MOV + ADD/SUB foldable to two immediate ADD/SUBs", NULL },
      "sign-crossed", plant_split, split_special, split_control },
    { "cbc", { "B.cond + CMP + B.cond foldable into CCMP + B.cond", NULL },
      "sharing a target", plant_cbc, cbc_special, cbc_control },
    { "hammock", { "B.cond over one instruction foldable into a conditional "
                   "select", NULL },
      "through an alias", plant_hammock, hammock_special, hammock_control },
    // Plants of a family of shapes rather than one check's: every
    // finding with a rewrite in their programs is tested.
    { "mem", { NULL, NULL }, NULL, plant_mem, NULL, NULL },
    { "arith", { NULL, NULL }, NULL, plant_arith, NULL, NULL },
    { "fp", { NULL, NULL }, NULL, plant_fp, NULL, NULL },
    { "lse", { NULL, NULL }, NULL, plant_lse, NULL, NULL },
    { "all", { NULL, NULL }, NULL, plant_any, NULL, control_any },
};

#define NMODES (sizeof(modes) / sizeof(modes[0]))

// all: any mode's plant, and any mode's control that takes the slot.
static void plant_any(void)
{
    modes[rr(NMODES - 1u)].plant();
}

static bool control_any(int i, uint32_t *alt)
{
    unsigned first = rr(NMODES - 1u);
    for (unsigned k = 0; k < NMODES - 1u; k++) {
        const mode_t_ *m = &modes[(first + k) % (NMODES - 1u)];
        if (m->control != NULL && m->control(i, alt)) {
            return true;
        }
    }
    return false;
}

static const char *only;        // -f: findings whose name contains it

static bool wanted(const armlint_finding *f)
{
    if (only != NULL && strstr(f->name, only) == NULL) {
        return false;
    }
    if (mode->findings[0] == NULL) {
        return f->nedits != 0;
    }
    for (int i = 0; i < 2; i++) {
        if (mode->findings[i] != NULL && strcmp(f->name, mode->findings[i]) == 0) {
            return true;
        }
    }
    return false;
}

// === Tallies ===

typedef struct {
    const char *name;
    long tested, special, mismatches, unapplied, outside;
    long noted;         // mismatch reports printed (print_notes)
} tally_t;

#define TALLIES_MAX 256
static tally_t tallies[TALLIES_MAX];
static size_t ntallies;

static tally_t *tally_for(const char *name)
{
    for (size_t i = 0; i < ntallies; i++) {
        if (tallies[i].name == name || strcmp(tallies[i].name, name) == 0) {
            return &tallies[i];
        }
    }
    if (ntallies == TALLIES_MAX) {
        fprintf(stderr, "rwfuzz: more than %d finding names\n", TALLIES_MAX);
        exit(2);
    }
    // A copy: a name a worker sent lives in a line buffer.
    tallies[ntallies].name = strdup(name);
    if (tallies[ntallies].name == NULL) {
        perror("rwfuzz: strdup");
        exit(2);
    }
    return &tallies[ntallies++];
}

static int by_tested(const void *a, const void *b)
{
    const tally_t *x = a, *y = b;
    if (x->tested != y->tested) {
        return x->tested < y->tested ? 1 : -1;
    }
    return strcmp(x->name, y->name);
}

static const char *signal_name(int sig)
{
    switch (sig) {
    case SIGSEGV: return "SIGSEGV";
    case SIGBUS: return "SIGBUS";
    case SIGILL: return "SIGILL";
    case SIGTRAP: return "SIGTRAP";
    case SIGFPE: return "SIGFPE";
    case SIGABRT: return "SIGABRT";
    case SIGKILL: return "SIGKILL";
    case SIGTERM: return "SIGTERM";
    case SIGALRM: return "a timeout";
    default: return "a signal";
    }
}

// The original program with the finding marked, and its edits.
static void report_mismatch(FILE *o, const hit_t *h, const uint32_t *alt,
                            const regs_t *in, int sig)
{
    char heading[2 * ARMLINT_FINDING_DETAIL_LEN];
    snprintf(heading, sizeof(heading), "MISMATCH at word %zu (%u "
             "instructions): %s: %s", h->start, h->count, h->name,
             h->detail);
    dump(o, prog, heading);
    for (unsigned i = 0; i < h->nedits; i++) {
        size_t w = h->edits[i].offset / 4u;
        fprintf(o, "  edit %4zx: %08x  %s\n", w * 4u, alt[w],
                h->edits[i].text[0] != '\0' ? h->edits[i].text : "(delete)");
    }
    fprintf(o, "  from x0..x7 =");
    for (int r = 0; r < 8; r++) {
        fprintf(o, " %#" PRIx64, in->x[r]);
    }
    fprintf(o, ", nzcv = %#" PRIx64 "\n", in->nzcv);
    if (sig != 0) {
        fprintf(o, "  the rewrite stopped on %s\n", signal_name(sig));
    }
}

static void report_unapplied(FILE *o, const hit_t *h)
{
    fprintf(o, "could not apply: %s: %s\n", h->name, h->detail);
    for (unsigned i = 0; i < h->nedits; i++) {
        fprintf(o, "  edit %4zx: %s\n", h->edits[i].offset,
                h->edits[i].text[0] != '\0' ? h->edits[i].text : "(delete)");
    }
}

// === Running the programs ===

// What the summary prints besides the counts -- a mismatch's report or
// an unapplied finding's notice -- with where it was found, so that the
// first ones in program order are printed however the programs were
// shared out.
typedef struct {
    long program;
    int hit;
    bool mismatch;      // else an unapplied finding's notice
    const char *name;
    char *text;
} note_t;

static note_t *notes;
static size_t nnotes, notes_cap;
static long controls, control_diffs;

static void add_note(long program, int hit, bool mismatch, const char *name,
                     char *text)
{
    if (nnotes == notes_cap) {
        notes_cap = notes_cap != 0 ? 2u * notes_cap : 64u;
        notes = realloc(notes, notes_cap * sizeof(*notes));
        if (notes == NULL) {
            perror("rwfuzz: realloc");
            exit(2);
        }
    }
    notes[nnotes++] = (note_t){ program, hit, mismatch, name, text };
}

// A stream that collects what is written to it, as one string.
static FILE *note_open(char **text, size_t *len)
{
    FILE *o = open_memstream(text, len);
    if (o == NULL) {
        perror("rwfuzz: open_memstream");
        exit(2);
    }
    return o;
}

#define BATCH 256

// Run batches of programs, BATCH at a time, taking the next batch's
// number from *next until all PROGRAMS are done, into the tallies and
// notes. One process does it all, or -j workers share *next. A worker
// keeps its first three mismatch reports of each kind and its first five
// unapplied notices, which hold every one the summary prints.
static int run_programs(long programs, long *next)
{
    if (!jit_open() || !guard_open() || !asm_open()) {
        return 2;
    }
    program_t *batch = calloc(BATCH, sizeof(*batch));
    if (batch == NULL) {
        perror("rwfuzz: calloc");
        return 2;
    }
    long unapplied = 0;
    uint32_t alt[PROG_MAX];
    for (;;) {
        long first = __atomic_fetch_add(next, 1, __ATOMIC_RELAXED) * BATCH;
        if (first >= programs) {
            break;
        }
        int n = programs - first < BATCH ? (int)(programs - first) : BATCH;
        // Draw the bodies, assemble the plants' texts, then lay each
        // program out and analyze it.
        rng = &gen_rng;
        at_phase = "drawing";
        for (int k = 0; k < n; k++) {
            at_program = first + k;
            gen_rng = stream_start(first + k, STREAM_GEN);
            gen_body(mode->plant);
            memcpy(batch[k].body, body, sizeof(body));
            batch[k].nbody = nbody;
        }
        at_phase = "assembling the batch from";
        at_program = first;
        if (!asm_flush()) {
            asm_close();
            return 2;
        }
        at_phase = "analyzing";
        for (int k = 0; k < n; k++) {
            at_program = first + k;
            cur = &batch[k];
            memcpy(body, cur->body, sizeof(body));
            nbody = cur->nbody;
            assemble();
            analyze();
            memcpy(cur->prog, prog, sizeof(prog));
            cur->nprog = nprog;
            cur->epi_start = epi_start;
            cur->stub_start = stub_start;
            for (int h = 0; h < cur->nhits; h++) {
                request_edits(&cur->hits[h]);
            }
        }
        at_phase = "assembling the batch from";
        at_program = first;
        if (!asm_flush()) {
            asm_close();
            return 2;
        }
        rng = &run_rng;
        at_phase = "running";
        for (int k = 0; k < n; k++) {
            at_program = first + k;
            run_rng = stream_start(first + k, STREAM_RUN);
            cur = &batch[k];
            memcpy(prog, cur->prog, sizeof(prog));
            nprog = cur->nprog;
            epi_start = cur->epi_start;
            stub_start = cur->stub_start;
            bool flagged[PROG_MAX] = { false };
            for (int h = 0; h < cur->nhits; h++) {
                const hit_t *hit = &cur->hits[h];
                tally_t *t = tally_for(hit->name);
                memcpy(alt, prog, (size_t)nprog * 4u);
                int r = apply_edits(hit, alt);
                if (r == EDITS_OUTSIDE) {
                    t->outside++;
                    continue;
                }
                char *text;
                size_t len;
                if (r != EDITS_APPLY) {
                    t->unapplied++;
                    if (++unapplied <= 5) {
                        FILE *o = note_open(&text, &len);
                        report_unapplied(o, hit);
                        fclose(o);
                        add_note(first + k, h, false, hit->name, text);
                    }
                    continue;
                }
                for (unsigned i = 0; i < hit->nedits; i++) {
                    flagged[hit->edits[i].offset / 4u] = true;
                }
                t->tested++;
                if (mode->is_special != NULL && mode->is_special(hit)) {
                    t->special++;
                }
                regs_t in;
                int sig = 0;
                if (!same_results(alt, &in, &sig)) {
                    t->mismatches++;
                    if (t->mismatches <= 3) {
                        FILE *o = note_open(&text, &len);
                        report_mismatch(o, hit, alt, &in, sig);
                        fclose(o);
                        add_note(first + k, h, true, hit->name, text);
                    }
                }
            }
            for (int i = body_start; i < epi_start && mode->control != NULL;
                 i++) {
                memcpy(alt, prog, (size_t)nprog * 4u);
                if (flagged[i] || !mode->control(i, alt)) {
                    continue;
                }
                controls++;
                control_diffs += !same_results(alt, NULL, NULL);
            }
        }
    }
    asm_close();
    free(batch);
    return 0;
}

// A worker's tallies and notes, sent to the process that started it.
static void send_results(FILE *o)
{
    for (size_t i = 0; i < ntallies; i++) {
        const tally_t *t = &tallies[i];
        fprintf(o, "T %ld %ld %ld %ld %ld %s\n", t->tested, t->special,
                t->mismatches, t->unapplied, t->outside, t->name);
    }
    fprintf(o, "C %ld %ld\n", controls, control_diffs);
    for (size_t i = 0; i < nnotes; i++) {
        const note_t *nt = &notes[i];
        fprintf(o, "N %ld %d %d %zu %s\n", nt->program, nt->hit,
                nt->mismatch, strlen(nt->text), nt->name);
        fputs(nt->text, o);
    }
}

// Add what a worker sent to this process's tallies and notes.
static bool take_results(FILE *in)
{
    char line[512];
    while (fgets(line, sizeof(line), in) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        long v[5];
        int at = -1;
        if (sscanf(line, "T %ld %ld %ld %ld %ld %n", &v[0], &v[1], &v[2],
                   &v[3], &v[4], &at) == 5 && at > 0) {
            tally_t *t = tally_for(line + at);
            t->tested += v[0];
            t->special += v[1];
            t->mismatches += v[2];
            t->unapplied += v[3];
            t->outside += v[4];
        } else if (sscanf(line, "C %ld %ld", &v[0], &v[1]) == 2) {
            controls += v[0];
            control_diffs += v[1];
        } else {
            int hit, mismatch;
            size_t len;
            if (sscanf(line, "N %ld %d %d %zu %n", &v[0], &hit, &mismatch,
                       &len, &at) != 4 || at <= 0) {
                return false;
            }
            char *text = malloc(len + 1u);
            if (text == NULL || fread(text, 1, len, in) != len) {
                free(text);
                return false;
            }
            text[len] = '\0';
            add_note(v[0], hit, mismatch != 0, tally_for(line + at)->name,
                     text);
        }
    }
    return true;
}

// Fork JOBS workers that share *next, and take in their results; false
// if one could not be started, sent what could not be read, or did not
// finish (its own message says why).
static bool run_workers(long programs, long *next, int jobs)
{
    FILE **from = calloc((size_t)jobs, sizeof(*from));
    pid_t *pids = calloc((size_t)jobs, sizeof(*pids));
    if (from == NULL || pids == NULL) {
        perror("rwfuzz: calloc");
        return false;
    }
    fflush(stdout);
    fflush(stderr);
    int started = 0;
    bool ok = true;
    for (; started < jobs; started++) {
        int fd[2];
        if (pipe(fd) != 0) {
            perror("rwfuzz: pipe");
            ok = false;
            break;
        }
        pid_t pid = fork();
        if (pid < 0) {
            perror("rwfuzz: fork");
            close(fd[0]);
            close(fd[1]);
            ok = false;
            break;
        }
        if (pid == 0) {
            // The earlier workers' read ends came along; this one needs
            // only its own write end.
            for (int w = 0; w < started; w++) {
                fclose(from[w]);
            }
            close(fd[0]);
            FILE *o = fdopen(fd[1], "w");
            int rc = o != NULL ? run_programs(programs, next) : 2;
            if (rc == 0) {
                send_results(o);
            }
            if (o != NULL && fclose(o) != 0) {
                rc = 2;
            }
            fflush(stdout);
            _exit(rc);
        }
        close(fd[1]);
        pids[started] = pid;
        from[started] = fdopen(fd[0], "r");
        if (from[started] == NULL) {
            perror("rwfuzz: fdopen");
            close(fd[0]);
            started++;
            ok = false;
            break;
        }
    }
    // The workers started are stopped if not all could be. Otherwise
    // each is read to the end even after another has failed, so that no
    // closed pipe kills it.
    bool stopped = !ok;
    if (stopped) {
        for (int w = 0; w < started; w++) {
            kill(pids[w], SIGTERM);
        }
    }
    for (int w = 0; w < started; w++) {
        if (from[w] != NULL) {
            if (!take_results(from[w])) {
                fprintf(stderr, "rwfuzz: worker %d sent what could not be "
                        "read\n", w);
                ok = false;
            }
            fclose(from[w]);
        }
        int status;
        if (waitpid(pids[w], &status, 0) < 0) {
            perror("rwfuzz: waitpid");
            ok = false;
        } else if (WIFSIGNALED(status)) {
            if (!stopped || WTERMSIG(status) != SIGTERM) {
                fprintf(stderr, "rwfuzz: worker %d died on %s (signal %d)\n",
                        w, signal_name(WTERMSIG(status)), WTERMSIG(status));
            }
            ok = false;
        } else if (WEXITSTATUS(status) != 0) {
            fprintf(stderr, "rwfuzz: worker %d exited with status %d\n", w,
                    WEXITSTATUS(status));
            ok = false;
        }
    }
    free(from);
    free(pids);
    return ok;
}

static int by_place(const void *a, const void *b)
{
    const note_t *x = a, *y = b;
    if (x->program != y->program) {
        return x->program < y->program ? -1 : 1;
    }
    return (x->hit > y->hit) - (x->hit < y->hit);
}

// The notes one process running the programs in order would print as it
// went: the first three mismatch reports of each kind, twenty at most,
// and the first five unapplied notices.
static void print_notes(void)
{
    qsort(notes, nnotes, sizeof(*notes), by_place);
    long shown = 0, unapplied = 0;
    for (size_t i = 0; i < nnotes; i++) {
        const note_t *nt = &notes[i];
        bool print;
        if (nt->mismatch) {
            print = ++tally_for(nt->name)->noted <= 3 && shown < 20;
            shown += print;
        } else {
            print = ++unapplied <= 5;
        }
        if (print) {
            fputs(nt->text, stdout);
        }
    }
}

static void usage(void)
{
    fprintf(stderr, "usage: rwfuzz [-n PROGRAMS] [-s SEED] [-f NAME] "
            "[-k KINDS] [-j JOBS] MODE\n"
            "modes:");
    for (size_t i = 0; i < NMODES; i++) {
        fprintf(stderr, " %s", modes[i].name);
    }
    fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
    long programs = 100000, min_kinds = 0, jobs = 1;
    int opt;
    while ((opt = getopt(argc, argv, "n:s:f:k:j:")) != -1) {
        switch (opt) {
        case 'n':
            programs = atol(optarg);
            break;
        case 's':
            seed = strtoull(optarg, NULL, 0);
            break;
        case 'f':
            only = optarg;
            break;
        case 'k':
            min_kinds = atol(optarg);
            break;
        case 'j':
            jobs = atol(optarg);
            break;
        default:
            usage();
            return 2;
        }
    }
    if (optind + 1 != argc || programs <= 0 || jobs <= 0 || jobs > 1024) {
        usage();
        return 2;
    }
    for (size_t i = 0; i < NMODES; i++) {
        if (strcmp(argv[optind], modes[i].name) == 0) {
            mode = &modes[i];
        }
    }
    if (mode == NULL) {
        usage();
        return 2;
    }
    if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &cs) != CS_ERR_OK) {
        fprintf(stderr, "rwfuzz: cs_open failed\n");
        return 2;
    }
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);
    // The const audit's rewrites are as concrete as the folds': the
    // consumer takes the immediate and the chain stays.
    features = host_features() | ARMLINT_AUDIT_CONST;

    // The next batch to run, in memory the workers share.
    long *next = mmap(NULL, sizeof(*next), PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANON, -1, 0);
    if (next == MAP_FAILED) {
        perror("rwfuzz: mmap");
        return 2;
    }
    *next = 0;
    if (jobs == 1) {
        int rc = run_programs(programs, next);
        if (rc != 0) {
            return rc;
        }
    } else if (!run_workers(programs, next, (int)jobs)) {
        return 2;
    }
    print_notes();

    long tested = 0, special = 0, mismatches = 0, unapplied = 0;
    long outside = 0;
    // The kinds a finding of which ran; a kind seen only in the
    // harness's code, or only unapplied, does not count.
    size_t kinds = 0;
    for (size_t i = 0; i < ntallies; i++) {
        const tally_t *t = &tallies[i];
        tested += t->tested;
        special += t->special;
        mismatches += t->mismatches;
        unapplied += t->unapplied;
        outside += t->outside;
        kinds += t->tested != 0;
    }
    if (mode->special != NULL) {
        printf("rwfuzz %s: %ld programs, %ld findings run (%ld %s), "
               "%ld mismatches, %ld not applied\n",
               mode->name, programs, tested, special, mode->special,
               mismatches, unapplied);
    } else {
        printf("rwfuzz %s: %ld programs, %ld findings of %zu kinds run, "
               "%ld mismatches, %ld not applied\n",
               mode->name, programs, tested, kinds, mismatches, unapplied);
    }
    if (outside != 0) {
        printf("  %ld findings in the harness's own code left alone\n",
               outside);
    }
    if (mode->control != NULL) {
        printf("  control: %ld refused rewrites applied anyway, %ld changed "
               "the result\n", controls, control_diffs);
    }
    if (mode->findings[0] == NULL || only != NULL) {
        qsort(tallies, ntallies, sizeof(tallies[0]), by_tested);
        printf("  %8s %8s %8s %8s  %s\n", "run", "mismatch", "unapplied",
               "harness", "finding");
        for (size_t i = 0; i < ntallies; i++) {
            const tally_t *t = &tallies[i];
            printf("  %8ld %8ld %8ld %8ld  %s\n", t->tested, t->mismatches,
                   t->unapplied, t->outside, t->name);
        }
    }
    fflush(stdout);
    if (tested == 0) {
        fprintf(stderr, "rwfuzz: no finding was tested -- has the finding "
                "name or the check changed?\n");
        return 2;
    }
    if ((long)kinds < min_kinds) {
        fprintf(stderr, "rwfuzz: findings of %zu kinds run, fewer than the "
                "%ld -k asks for -- has a plant stopped producing its "
                "finding?\n", kinds, min_kinds);
        return 1;
    }
    return mismatches != 0 || unapplied != 0 ? 1 : 0;
}

#endif
