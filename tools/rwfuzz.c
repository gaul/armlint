// rwfuzz: check that the rewrites armlint suggests compute what the code
// they replace computed, by running both.
//
// A check's decision can be right and its advice still wrong -- a proof
// that misses a write, a rendering that inverts a condition -- and the
// unit tests and fixtures cover only the cases someone thought to write
// down. rwfuzz generates random AArch64 programs, lets armlint's check
// registry find the opportunities of one kind in each, applies every
// finding's rewrite to a copy of the program, and runs original and
// rewrite natively from the same random registers, flags and memory.
// Any difference in x0..x7 or NZCV at the end is a soundness bug in the
// check -- or in the harness.
//
// Each program is a fixed prologue that loads x0..x7, NZCV and a
// scratch-buffer pointer (x28) from a state block, a random body, and an
// epilogue that stores x0..x7 and NZCV back; after it sits a stub the
// body can call, which clobbers x0..x7 and NZCV as a callee may. The
// body writes only x0..x7: W and X arithmetic, logic, shifts and
// bitfields, moves, conditional selects, loads off x28 (atomics
// included), compares, forward CBZ/CBNZ/B.cond, calls to the stub, and
// the patterns the mode plants for its check to find. Register values
// lean on the edges -- zero, all ones, the 32-bit boundaries, small
// constants and their negatives -- so compares and masks meet the values
// that tell a rewrite from the original.
//
// Modes, one per check:
//   zext   check_redundant_zext: delete the consumer (a UXT*, a low-mask
//          AND or MOV Wd, Wd), adjacent to its producer or not.
//   ubfx   check_lsr_and_to_ubfx: delete the LSR/ASR and turn the AND
//          into the UBFX, in place or not.
//   ccmp   check_ccmp_chain: replace the CMP + CCMP chain by the one
//          compare the finding renders, deleting the other links and
//          changing the reader's condition, or making the branch the
//          CBZ/CBNZ it renders.
//   lvn    check_value_recompute: delete the instruction whose result its
//          destination (and NZCV) already holds.
//   dead   check_dead_write: delete the write whose value is overwritten
//          before anything reads it.
//   cmn    check_cmp_cmn_w: delete the MOV of 2^32 - k and turn the 64-bit
//          CMP into the W-form CMN the finding renders.
//   branch check_branch_decided: delete a conditional branch that is never
//          taken, or make an always-taken one a B to its target.
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
// Usage: rwfuzz [-n PROGRAMS] [-s SEED] MODE
//   -n  programs to generate (default 100000)
//   -s  seed, mixed into the fixed default one (default 0)
// Exit status: 0 when every finding was applied and matched; 1 on a
// mismatch, or on a finding the harness could not apply (a rendering it
// no longer parses would otherwise drop out of the test silently); 2 on
// a usage or environment error, a run that tested no finding included.
//
// The programs run on the host, so rwfuzz needs an AArch64 one: MAP_JIT
// memory on macOS, plain read-write-execute memory elsewhere. Built by
// `make tools`; it links libarmlint.a.

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
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#endif

#include "armlint.h"

// === Randomness ===

static uint64_t rng_state = 0x9E3779B97F4A7C15ull;

// xorshift64*: fast, and reproducible from the seed.
static uint64_t rnd(void)
{
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 0x2545F4914F6CDD1Dull;
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
static uint32_t b_cond(unsigned c, int words) { return 0x54000000u | ((unsigned)words & 0x7FFFFu) << 5 | c; }
static uint32_t bl(int words) { return 0x94000000u | ((unsigned)words & 0x3FFFFFFu); }

// === Programs ===

// stp x29, x30, [sp, #-96]! ; mov x29, sp ; stp x19..x28 at [sp, #16..80]
// mov x15, x0 ; ldp x0..x7 from [x15] ; ldr x28, [x15, #64]
// ldr x16, [x15, #72] ; msr nzcv, x16
static const uint32_t prologue[] = {
    0xA9BA7BFDu, 0x910003FDu, 0xA90153F3u, 0xA9025BF5u, 0xA90363F7u,
    0xA9046BF9u, 0xA90573FBu, 0xAA0003EFu, 0xA94005E0u, 0xA9410DE2u,
    0xA94215E4u, 0xA9431DE6u, 0xF94021FCu, 0xF94025F0u, 0xD51B4210u,
};
// stp x0..x7 to [x15] ; mrs x16, nzcv ; str x16, [x15, #72]
// ldp x19..x28 ; ldp x29, x30, [sp], #96 ; ret
static const uint32_t epilogue[] = {
    0xA90005E0u, 0xA9010DE2u, 0xA90215E4u, 0xA9031DE6u, 0xD53B4210u,
    0xF90025F0u, 0xA94153F3u, 0xA9425BF5u, 0xA94363F7u, 0xA9446BF9u,
    0xA94573FBu, 0xA8C67BFDu, RET,
};

// The state block the prologue loads and the epilogue stores.
typedef struct {
    uint64_t x[8];
    uint64_t buf;
    uint64_t nzcv;
} regs_t;

// A body slot: a finished word, or a control transfer whose word is
// fixed up once the layout is known.
enum { SLOT_PLAIN, SLOT_BRANCH, SLOT_READER, SLOT_CALL };

typedef struct {
    int kind;
    uint32_t word;      // SLOT_PLAIN
    int target;         // SLOT_BRANCH/SLOT_READER: body index, or the end
    unsigned reg;       // SLOT_BRANCH: the CBZ/CBNZ/TBZ/TBNZ register
    unsigned cond;      // SLOT_BRANCH/SLOT_READER: the B.cond condition
    unsigned form;      // SLOT_BRANCH: 0 CBZ X, 1 CBNZ W, 2 B.cond,
                        // 3 CBZ W, 4 CBNZ X, 5 TBZ, 6 TBNZ
    unsigned bit;       // SLOT_BRANCH: the TBZ/TBNZ bit
} slot_t;

#define BODY_MAX 40
#define PROG_MAX 256

static slot_t body[BODY_MAX];
static int nbody;
static uint32_t prog[PROG_MAX];
static int nprog, body_start, epi_start, stub_start;

static void push(uint32_t word)
{
    if (nbody < BODY_MAX) {
        body[nbody++] = (slot_t){ .kind = SLOT_PLAIN, .word = word };
    }
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
    // -- so every program terminates.
    for (int i = 0; i < nbody; i++) {
        body[i].target = i + 1 + (int)rr((unsigned)(nbody - i));
    }
}

static void assemble(void)
{
    int k = 0;
    for (size_t i = 0; i < sizeof(prologue) / 4u; i++) {
        prog[k++] = prologue[i];
    }
    body_start = k;
    k += nbody;
    epi_start = k;
    for (size_t i = 0; i < sizeof(epilogue) / 4u; i++) {
        prog[k++] = epilogue[i];
    }
    // The stub: x0..x7 get top halves set, NZCV a fixed pattern.
    stub_start = k;
    for (unsigned r = 0; r < 8; r++) {
        prog[k++] = movz_x(r, 0xBEE0u + r, 0);
        prog[k++] = movk_x(r, 0xDEADu, 3);
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
        default:
            prog[at] = bl(stub_start - at);
            break;
        }
    }
}

// === armlint ===

static csh cs;

typedef struct {
    size_t start;       // word index of the finding's first instruction
    unsigned count;
    char detail[ARMLINT_FINDING_DETAIL_LEN];
} hit_t;

#define HITS_MAX 64
static hit_t hits[HITS_MAX];
static int nhits;

typedef struct mode mode_t_;
static const mode_t_ *mode;

static bool wanted(const char *name);

static void record(const armlint_finding *f)
{
    if (nhits < HITS_MAX && wanted(f->name)) {
        hits[nhits].start = f->start_offset / 4u;
        hits[nhits].count = f->insn_count;
        snprintf(hits[nhits].detail, sizeof(hits[nhits].detail), "%s",
                 f->detail);
        nhits++;
    }
}

// Run the registry over the program the way the driver does -- with the
// buffer set, so branch targets and target scans work -- and keep the
// mode's findings.
static void analyze(void)
{
    nhits = 0;
    armlint_state *st = armlint_state_create();
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

static uint32_t *jit;
static uint8_t scratch[4096] __attribute__((aligned(64)));   // atomics
static uint8_t scratch_init[4096];

static bool jit_open(void)
{
#if defined(__APPLE__)
    int flags = MAP_PRIVATE | MAP_ANON | MAP_JIT;
#else
    int flags = MAP_PRIVATE | MAP_ANON;
#endif
    void *m = mmap(NULL, PROG_MAX * 4u, PROT_READ | PROT_WRITE | PROT_EXEC,
                   flags, -1, 0);
    if (m == MAP_FAILED) {
        perror("rwfuzz: mmap");
        return false;
    }
    jit = m;
    return true;
}

static void jit_load(const uint32_t *code, size_t words)
{
#if defined(__APPLE__)
    pthread_jit_write_protect_np(0);
    memcpy(jit, code, words * 4u);
    pthread_jit_write_protect_np(1);
    sys_icache_invalidate(jit, words * 4u);
#else
    memcpy(jit, code, words * 4u);
    __builtin___clear_cache((char *)jit, (char *)(jit + words));
#endif
}

static void run(const uint32_t *code, const regs_t *in, regs_t *out)
{
    jit_load(code, (size_t)nprog);
    memcpy(scratch, scratch_init, sizeof(scratch));
    *out = *in;
    out->buf = (uint64_t)(uintptr_t)scratch;
    ((void (*)(regs_t *))(void *)jit)(out);
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

static void random_state(regs_t *s)
{
    for (int i = 0; i < 8; i++) {
        s->x[i] = edge_value();
    }
    s->nzcv = (uint64_t)rr(16) << 28;
    for (size_t i = 0; i < sizeof(scratch_init); i++) {
        scratch_init[i] = (uint8_t)rnd();
    }
}

// Run both programs from TRIALS random states; true if all agreed. On a
// difference, *diff_in gets the state that showed it.
#define TRIALS 6

static bool same_results(const uint32_t *alt, regs_t *diff_in)
{
    for (int t = 0; t < TRIALS; t++) {
        regs_t in, a, b;
        random_state(&in);
        run(prog, &in, &a);
        run(alt, &in, &b);
        if (memcmp(a.x, b.x, sizeof(a.x)) != 0 || a.nzcv != b.nzcv) {
            if (diff_in != NULL) {
                *diff_in = in;
            }
            return false;
        }
    }
    return true;
}

static void dump(const uint32_t *code, const char *heading)
{
    printf("---- %s\n", heading);
    cs_insn *insn;
    size_t c = cs_disasm(cs, (const uint8_t *)code, (size_t)nprog * 4u, 0, 0,
                         &insn);
    for (size_t i = 0; i < c; i++) {
        printf("  %4" PRIx64 ": %08x  %s %s\n", insn[i].address,
               code[insn[i].address / 4u], insn[i].mnemonic, insn[i].op_str);
    }
    cs_free(insn, c);
}

// === Modes ===

static bool in_body(size_t first, size_t last)
{
    return first >= (size_t)body_start && last < (size_t)epi_start;
}

// zext: the consumer is the span's last instruction; delete it.
static bool zext_apply(const hit_t *h, uint32_t *code)
{
    size_t consumer = h->start + h->count - 1u;
    if (!in_body(consumer, consumer)) {
        return false;
    }
    code[consumer] = NOP;
    return true;
}

static size_t zext_slot(const hit_t *h)
{
    return h->start + h->count - 1u;
}

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

static bool ubfx_apply(const hit_t *h, uint32_t *code)
{
    if (!in_body(h->start, h->start + 1u)) {
        return false;
    }
    code[h->start + 1u] = ubfx_of(code[h->start], code[h->start + 1u]);
    code[h->start] = NOP;
    return true;
}

static size_t ubfx_slot(const hit_t *h)
{
    return h->start;
}

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

static const char *const cond_names[16] = {
    "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
};

static int cond_from_name(const char *s)
{
    for (int i = 0; i < 16; i++) {
        if (strncmp(s, cond_names[i], 2) == 0) {
            return i;
        }
    }
    return -1;
}

// ccmp: apply the rewrite as the finding renders it --
//   "-> cbz wN, 0x..."                          (or cbnz)
//   "-> cmp|cmn wN, #0xK ; b.cc 0x..."
//   "-> cmp|cmn wN, #0xK ; <csel-family operands>, cc"
// A CSEL-family alias prints its condition inverted, so the new field is
// taken relative to how the original reader printed its own.
static bool ccmp_apply(const hit_t *h, uint32_t *code)
{
    size_t first = h->start, reader = h->start + h->count - 1u;
    if (!in_body(first, reader)) {
        return false;
    }
    uint32_t rw = code[reader];
    bool x = (code[first] >> 31) != 0;
    unsigned rn = (code[first] >> 5) & 31u;
    char mnem[8];
    unsigned reg_no;
    unsigned long long imm;
    char tail[ARMLINT_FINDING_DETAIL_LEN];
    if (sscanf(h->detail, "-> %7s %*c%u", mnem, &reg_no) != 2
            || reg_no != rn) {
        return false;
    }
    if (strcmp(mnem, "cbz") == 0 || strcmp(mnem, "cbnz") == 0) {
        for (size_t i = first; i < reader; i++) {
            code[i] = NOP;
        }
        code[reader] = cbz(x, mnem[2] == 'n', rn, (int)((rw >> 5) & 0x7FFFFu));
        return true;
    }
    if (sscanf(h->detail, "-> %7s %*c%u, #0x%llx ; %127[^\n]", mnem,
               &reg_no, &imm, tail) != 4) {
        return false;
    }
    code[first] = cmp_imm(x, strcmp(mnem, "cmn") == 0, rn, (unsigned)imm);
    for (size_t i = first + 1u; i < reader; i++) {
        code[i] = NOP;
    }
    if (strncmp(tail, "b.", 2) == 0) {
        int c = cond_from_name(tail + 2);
        if (c < 0) {
            return false;
        }
        code[reader] = (rw & ~0xFu) | (unsigned)c;
        return true;
    }
    const char *comma = strrchr(tail, ',');
    int c = comma != NULL ? cond_from_name(comma + 2) : -1;
    cs_insn *insn;
    size_t n = cs_disasm(cs, (const uint8_t *)&rw, 4, 0, 1, &insn);
    if (n != 1 || c < 0) {
        if (n != 0) {
            cs_free(insn, n);
        }
        return false;
    }
    const char *oc = strrchr(insn->op_str, ',');
    int shown = oc != NULL ? cond_from_name(oc + 2) : -1;
    cs_free(insn, n);
    unsigned field = (rw >> 12) & 15u;
    if (shown < 0) {
        return false;
    }
    unsigned nf = (unsigned)shown == field ? (unsigned)c : (unsigned)c ^ 1u;
    code[reader] = (rw & ~(15u << 12)) | nf << 12;
    return true;
}

static size_t ccmp_slot(const hit_t *h)
{
    return h->start;
}

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

// lvn: the finding's one instruction is deleted.
static bool lvn_apply(const hit_t *h, uint32_t *code)
{
    if (h->count != 1u || !in_body(h->start, h->start)) {
        return false;
    }
    code[h->start] = NOP;
    return true;
}

static size_t lvn_slot(const hit_t *h)
{
    return h->start;
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

// dead: the finding's one instruction, the dead write, is deleted.
static bool dead_apply(const hit_t *h, uint32_t *code)
{
    return lvn_apply(h, code);
}

static size_t dead_slot(const hit_t *h)
{
    return h->start;
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

// cmn: "-> cmn wN, #0xK[, lsl #12] (drop ...)": NOP the MOV, CMN the CMP.
static bool cmn_apply(const hit_t *h, uint32_t *code)
{
    if (h->count != 2u || !in_body(h->start, h->start + 1u)) {
        return false;
    }
    unsigned n;
    unsigned long long k;
    if (sscanf(h->detail, "-> cmn w%u, #0x%llx", &n, &k) != 2 || k > 0xFFFu
            || n != ((code[h->start + 1u] >> 5) & 31u)) {
        return false;
    }
    code[h->start] = NOP;
    code[h->start + 1u] = cmn_w_imm(n, (unsigned)k,
                                    strstr(h->detail, "lsl #12") != NULL);
    return true;
}

static size_t cmn_slot(const hit_t *h)
{
    return h->start;
}

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

// branch: "-> delete; never taken: ..." deletes the branch, "-> b 0x...;
// always taken: ..." makes it a B with the same displacement.
static int32_t branch_disp(uint32_t w)
{
    if ((w & 0x7E000000u) == 0x36000000u) {
        return (int32_t)(((w >> 5) & 0x3FFFu) << 18) >> 18;
    }
    return (int32_t)(((w >> 5) & 0x7FFFFu) << 13) >> 13;
}

static bool branch_apply(const hit_t *h, uint32_t *code)
{
    if (h->count != 1u || !in_body(h->start, h->start)) {
        return false;
    }
    if (strncmp(h->detail, "-> delete; never taken", 22) == 0) {
        code[h->start] = NOP;
        return true;
    }
    unsigned long long target;
    if (sscanf(h->detail, "-> b 0x%llx; always taken", &target) != 1
            || target != h->start * 4u
                          + (uint64_t)(int64_t)branch_disp(code[h->start]) * 4u) {
        return false;
    }
    code[h->start] = b_(branch_disp(code[h->start]));
    return true;
}

static size_t branch_slot(const hit_t *h)
{
    return h->start;
}

static bool branch_special(const hit_t *h)
{
    return strstr(h->detail, "always taken") != NULL;
}

// Control: delete an unflagged conditional branch, or make it a B.
static bool branch_control(int i, uint32_t *alt)
{
    uint32_t w = prog[i];
    bool cond = ((w & 0xFF000010u) == 0x54000000u && (w & 0xFu) < 14u)
        || (w & 0x7E000000u) == 0x34000000u
        || (w & 0x7E000000u) == 0x36000000u;
    if (!cond || rr(2) != 0) {
        return false;
    }
    alt[i] = rr(2) == 0 ? NOP : b_(branch_disp(w));
    return true;
}

struct mode {
    const char *name;
    const char *findings[2];        // the finding names the mode tests
    const char *special;            // what the second count counts
    void (*plant)(void);
    bool (*apply)(const hit_t *, uint32_t *);
    size_t (*slot)(const hit_t *);  // the word the control arm keys on
    bool (*is_special)(const hit_t *);
    bool (*control)(int, uint32_t *);
};

static const mode_t_ modes[] = {
    { "zext", { "redundant zero-extension after zeroing op", NULL },
      "across a gap", plant_zext, zext_apply, zext_slot, zext_special,
      zext_control },
    { "ubfx", { "LSR+AND foldable into UBFX", "ASR+AND foldable into UBFX" },
      "out of place", plant_shift_and, ubfx_apply, ubfx_slot, ubfx_special,
      ubfx_control },
    { "ccmp", { "CMP + CCMP chain decidable by one compare", NULL },
      "with a branch reader", plant_ccmp_chain, ccmp_apply, ccmp_slot,
      ccmp_special, ccmp_control },
    { "lvn", { "register already holds the recomputed value",
               "ADR/ADRP of an address its register already holds" },
      "not adjacent", plant_recompute, lvn_apply, lvn_slot, lvn_special,
      lvn_control },
    { "dead", { "register write overwritten unread", NULL },
      "across a gap", plant_dead_write, dead_apply, dead_slot, dead_special,
      dead_control },
    { "cmn", { "MOV + CMP of a 32-bit value against 2^32-k foldable to "
               "W-form CMN", NULL },
      "with a branch reader", plant_cmp_cmn, cmn_apply, cmn_slot,
      cmn_special, cmn_control },
    { "branch", { "conditional branch that is never taken",
                  "conditional branch that is always taken" },
      "always taken", plant_decided, branch_apply, branch_slot,
      branch_special, branch_control },
};

static bool wanted(const char *name)
{
    for (int i = 0; i < 2; i++) {
        if (mode->findings[i] != NULL && strcmp(name, mode->findings[i]) == 0) {
            return true;
        }
    }
    return false;
}

static void usage(void)
{
    fprintf(stderr, "usage: rwfuzz [-n PROGRAMS] [-s SEED] "
            "zext|ubfx|ccmp|lvn|dead|cmn|branch\n");
}

int main(int argc, char **argv)
{
    long programs = 100000;
    int opt;
    while ((opt = getopt(argc, argv, "n:s:")) != -1) {
        switch (opt) {
        case 'n':
            programs = atol(optarg);
            break;
        case 's':
            rng_state ^= strtoull(optarg, NULL, 0);
            break;
        default:
            usage();
            return 2;
        }
    }
    if (optind + 1 != argc || programs <= 0) {
        usage();
        return 2;
    }
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
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
    if (!jit_open()) {
        return 2;
    }

    long tested = 0, special = 0, mismatches = 0, unapplied = 0;
    long controls = 0, control_diffs = 0;
    uint32_t alt[PROG_MAX];
    for (long it = 0; it < programs; it++) {
        gen_body(mode->plant);
        assemble();
        analyze();
        bool flagged[PROG_MAX] = { false };
        for (int h = 0; h < nhits; h++) {
            memcpy(alt, prog, (size_t)nprog * 4u);
            if (!mode->apply(&hits[h], alt)) {
                unapplied++;
                if (unapplied <= 5) {
                    printf("could not apply: %s\n", hits[h].detail);
                }
                continue;
            }
            flagged[mode->slot(&hits[h])] = true;
            tested++;
            special += mode->is_special(&hits[h]);
            regs_t in;
            if (!same_results(alt, &in)) {
                mismatches++;
                if (mismatches <= 5) {
                    char heading[ARMLINT_FINDING_DETAIL_LEN + 64];
                    snprintf(heading, sizeof(heading),
                             "MISMATCH at word %zu (%u instructions): %s",
                             hits[h].start, hits[h].count, hits[h].detail);
                    dump(prog, heading);
                    printf("  from x0..x7 =");
                    for (int r = 0; r < 8; r++) {
                        printf(" %#" PRIx64, in.x[r]);
                    }
                    printf(", nzcv = %#" PRIx64 "\n", in.nzcv);
                }
            }
        }
        for (int i = body_start; i < epi_start; i++) {
            memcpy(alt, prog, (size_t)nprog * 4u);
            if (flagged[i] || !mode->control(i, alt)) {
                continue;
            }
            controls++;
            control_diffs += !same_results(alt, NULL);
        }
    }

    printf("rwfuzz %s: %ld programs, %ld findings run (%ld %s), "
           "%ld mismatches, %ld not applied\n",
           mode->name, programs, tested, special, mode->special,
           mismatches, unapplied);
    printf("  control: %ld refused rewrites applied anyway, %ld changed "
           "the result\n", controls, control_diffs);
    if (tested == 0) {
        fprintf(stderr, "rwfuzz: no finding was tested -- has the finding "
                "name or the check changed?\n");
        return 2;
    }
    return mismatches != 0 || unapplied != 0 ? 1 : 0;
}

#endif
