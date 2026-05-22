/*
 * Copyright 2026 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <capstone/capstone.h>

#include "armlint.h"

static csh g_handle;

static int run_check(const uint8_t *code, size_t code_size)
{
    cs_insn *insns = NULL;
    size_t count = cs_disasm(g_handle, code, code_size, 0, 0, &insns);
    if (count != code_size / 4) {
        if (insns != NULL) {
            cs_free(insns, count);
        }
        return -1;
    }

    armlint_state *state = armlint_state_create();
    assert(state != NULL);

    int findings = 0;
    for (size_t i = 0; i < count; i++) {
        armlint_finding f;
        size_t offset = (size_t)insns[i].address;
        if (check_movz_movk_bitmask(state, &insns[i], offset, &f)) {
            findings++;
        }
        if (check_lsl_fold(state, &insns[i], offset, &f)) {
            findings++;
        }
        if (check_cmp_zero_branch(state, &insns[i], offset, &f)) {
            findings++;
        }
    }

    armlint_finding f;
    if (armlint_flush(state, &f)) {
        findings++;
    }

    armlint_state_destroy(state);
    cs_free(insns, count);
    return findings;
}

#define EXPECT_FINDINGS(expected, ...) \
do { \
    static const uint8_t bytes[] = { __VA_ARGS__ }; \
    int findings = run_check(bytes, sizeof(bytes)); \
    if (findings != (expected)) { \
        fprintf(stderr, "%s:%d: expected %d findings, got %d for:", \
            __FILE__, __LINE__, (expected), findings); \
        for (size_t _i = 0; _i < sizeof(bytes); _i++) { \
            fprintf(stderr, " %02x", bytes[_i]); \
        } \
        fprintf(stderr, "\n"); \
    } \
    assert(findings == (expected)); \
} while (0)

static void test_is_bitmask_immediate_32(void)
{
    // Excluded values.
    assert(!is_bitmask_immediate(0, 32));
    assert(!is_bitmask_immediate(0xffffffffu, 32));

    // Single-bit and small runs.
    assert(is_bitmask_immediate(1, 32));
    assert(is_bitmask_immediate(2, 32));
    assert(is_bitmask_immediate(3, 32));
    assert(is_bitmask_immediate(0x80000000u, 32));
    assert(is_bitmask_immediate(0xc0000000u, 32));

    // Replicating patterns.
    assert(is_bitmask_immediate(0x55555555u, 32));  // esize=2
    assert(is_bitmask_immediate(0xaaaaaaaau, 32));  // esize=2
    assert(is_bitmask_immediate(0x66666666u, 32));  // esize=4
    assert(is_bitmask_immediate(0x99999999u, 32));  // esize=4
    assert(is_bitmask_immediate(0xf0f0f0f0u, 32));  // esize=8
    assert(is_bitmask_immediate(0x0f0f0f0fu, 32));  // esize=8
    assert(is_bitmask_immediate(0xff00ff00u, 32));  // esize=16
    assert(is_bitmask_immediate(0xffff0000u, 32));  // esize=32, rotated run

    // Common masks.
    assert(is_bitmask_immediate(0xffu, 32));
    assert(is_bitmask_immediate(0xffffu, 32));

    // Non-rotated-run patterns at smallest replicating esize.
    assert(!is_bitmask_immediate(0x12345678u, 32));
    assert(!is_bitmask_immediate(0xdeadbeefu, 32));
    assert(!is_bitmask_immediate(0x10010010u, 32));
}

static void test_is_bitmask_immediate_64(void)
{
    assert(!is_bitmask_immediate(0, 64));
    assert(!is_bitmask_immediate(~(uint64_t)0, 64));

    // 0xffffffff is all-ones in 32-bit but a valid bitmask in 64-bit
    // (a rotated 32-bit run within the 64-bit register).
    assert(is_bitmask_immediate(0xffffffffu, 64));

    assert(is_bitmask_immediate(0x5555555555555555ULL, 64));
    assert(is_bitmask_immediate(0xaaaaaaaaaaaaaaaaULL, 64));
    assert(is_bitmask_immediate(0xf0f0f0f0f0f0f0f0ULL, 64));
    assert(is_bitmask_immediate(0x0000000100000001ULL, 64));  // esize=32

    // NOT(1): one zero bit. Rotated run of 63 ones at esize=64.
    assert(is_bitmask_immediate(0xfffffffffffffffeULL, 64));

    assert(!is_bitmask_immediate(0x123456789abcdef0ULL, 64));
    assert(!is_bitmask_immediate(0x1000001000000000ULL, 64));
}

// MOVZ Wd, #imm16
// sf=0, opc=10, fixed=100101, hw=00, imm16, Rd
// Encoding base: 0x52800000
static void movz_w(uint8_t out[4], unsigned rd, uint16_t imm16)
{
    uint32_t op = 0x52800000u
        | ((uint32_t)(imm16 & 0xffffu) << 5)
        | (rd & 0x1fu);
    out[0] = op & 0xff;
    out[1] = (op >> 8) & 0xff;
    out[2] = (op >> 16) & 0xff;
    out[3] = (op >> 24) & 0xff;
}

// MOVK Wd, #imm16, LSL #(hw*16)
// Encoding base: 0x72800000
static void movk_w(uint8_t out[4], unsigned rd, uint16_t imm16, unsigned hw)
{
    uint32_t op = 0x72800000u
        | ((uint32_t)(hw & 0x3u) << 21)
        | ((uint32_t)(imm16 & 0xffffu) << 5)
        | (rd & 0x1fu);
    out[0] = op & 0xff;
    out[1] = (op >> 8) & 0xff;
    out[2] = (op >> 16) & 0xff;
    out[3] = (op >> 24) & 0xff;
}

// MOVZ Xd, #imm16, LSL #(hw*16). Encoding base: 0xd2800000
static void movz_x(uint8_t out[4], unsigned rd, uint16_t imm16, unsigned hw)
{
    uint32_t op = 0xd2800000u
        | ((uint32_t)(hw & 0x3u) << 21)
        | ((uint32_t)(imm16 & 0xffffu) << 5)
        | (rd & 0x1fu);
    out[0] = op & 0xff;
    out[1] = (op >> 8) & 0xff;
    out[2] = (op >> 16) & 0xff;
    out[3] = (op >> 24) & 0xff;
}

// MOVK Xd. Encoding base: 0xf2800000
static void movk_x(uint8_t out[4], unsigned rd, uint16_t imm16, unsigned hw)
{
    uint32_t op = 0xf2800000u
        | ((uint32_t)(hw & 0x3u) << 21)
        | ((uint32_t)(imm16 & 0xffffu) << 5)
        | (rd & 0x1fu);
    out[0] = op & 0xff;
    out[1] = (op >> 8) & 0xff;
    out[2] = (op >> 16) & 0xff;
    out[3] = (op >> 24) & 0xff;
}

// MOVN Xd. Encoding base: 0x92800000
static void movn_x(uint8_t out[4], unsigned rd, uint16_t imm16, unsigned hw)
{
    uint32_t op = 0x92800000u
        | ((uint32_t)(hw & 0x3u) << 21)
        | ((uint32_t)(imm16 & 0xffffu) << 5)
        | (rd & 0x1fu);
    out[0] = op & 0xff;
    out[1] = (op >> 8) & 0xff;
    out[2] = (op >> 16) & 0xff;
    out[3] = (op >> 24) & 0xff;
}

static int run_helper_check(uint8_t *bytes, size_t len)
{
    return run_check(bytes, len);
}

static void test_movz_movk_sequences(void)
{
    uint8_t code[16];

    // movz w0, #0x6666 ; movk w0, #0x6666, lsl #16  -> 0x66666666 (bitmask).
    movz_w(&code[0], 0, 0x6666);
    movk_w(&code[4], 0, 0x6666, 1);
    assert(run_helper_check(code, 8) == 1);

    // movz w0, #0x1234 ; movk w0, #0x5678, lsl #16  -> 0x56781234 (not bitmask).
    movz_w(&code[0], 0, 0x1234);
    movk_w(&code[4], 0, 0x5678, 1);
    assert(run_helper_check(code, 8) == 0);

    // Single MOVZ -- one instruction, cannot shrink.
    movz_w(&code[0], 0, 0x6666);
    assert(run_helper_check(code, 4) == 0);

    // movz w0, #0x6666 ; movk w1, #0x6666, lsl #16
    // Different registers: w0 seq closes with insn_count=1 (no finding),
    // and MOVK without a base on w1 does not start a new sequence.
    movz_w(&code[0], 0, 0x6666);
    movk_w(&code[4], 1, 0x6666, 1);
    assert(run_helper_check(code, 8) == 0);

    // 4-instruction X-register sequence producing 0x5555555555555555.
    movz_x(&code[0], 0, 0x5555, 0);
    movk_x(&code[4], 0, 0x5555, 1);
    movk_x(&code[8], 0, 0x5555, 2);
    movk_x(&code[12], 0, 0x5555, 3);
    assert(run_helper_check(code, 16) == 1);

    // Same 4-instruction shape, but final value 0x1234567890abcdef is not
    // a bitmask immediate.
    movz_x(&code[0], 0, 0xcdef, 0);
    movk_x(&code[4], 0, 0x90ab, 1);
    movk_x(&code[8], 0, 0x5678, 2);
    movk_x(&code[12], 0, 0x1234, 3);
    assert(run_helper_check(code, 16) == 0);

    // MOVN x0, #0, lsl #0 followed by MOVK -- MOVN starts the sequence
    // (value = ~0 in 64-bit = all ones, which is excluded). Then MOVK
    // clobbers the low 16 bits to 0xffff (still all-ones overall).
    // Final value is the all-ones value, not bitmask-encodable. No flag.
    movn_x(&code[0], 0, 0x0000, 0);
    movk_x(&code[4], 0, 0xffff, 0);
    assert(run_helper_check(code, 8) == 0);

    // movz x0, #0xffff, lsl #16 ; movk x0, #0xffff, lsl #32
    // -> 0x0000ffffffff0000, which is a rotated run of 32 ones in 64
    // bits and therefore bitmask-encodable.
    movz_x(&code[0], 0, 0xffff, 1);
    movk_x(&code[4], 0, 0xffff, 2);
    assert(run_helper_check(code, 8) == 1);

    // MOVK without a preceding MOVZ/MOVN does not start a sequence
    // (the prior value of the register is unknown), so even if two
    // MOVKs together would name a bitmask-imm value, no finding.
    movk_w(&code[0], 0, 0x6666, 0);
    movk_w(&code[4], 0, 0x6666, 1);
    assert(run_helper_check(code, 8) == 0);

    // Two independent MOVZ/MOVK pairs to different registers, back to
    // back. Each pair stands alone; the first should flag.
    movz_w(&code[0], 0, 0x6666);
    movk_w(&code[4], 0, 0x6666, 1);
    movz_w(&code[8], 1, 0x1234);
    movk_w(&code[12], 1, 0x5678, 1);
    assert(run_helper_check(code, 16) == 1);
}

// LSL (immediate) is the UBFM alias with imms = (datasize-1) - shift
// and immr = (datasize - shift) MOD datasize.
static void lsl_w(uint8_t out[4], unsigned rd, unsigned rn, unsigned shift)
{
    unsigned imms = 31u - shift;
    unsigned immr = (32u - shift) & 31u;
    uint32_t op = 0x53000000u
        | (immr << 16)
        | (imms << 10)
        | ((rn & 0x1fu) << 5)
        | (rd & 0x1fu);
    out[0] = op & 0xff;
    out[1] = (op >> 8) & 0xff;
    out[2] = (op >> 16) & 0xff;
    out[3] = (op >> 24) & 0xff;
}

static void lsl_x(uint8_t out[4], unsigned rd, unsigned rn, unsigned shift)
{
    unsigned imms = 63u - shift;
    unsigned immr = (64u - shift) & 63u;
    // sf=1 UBFM (with N=1) base = 0xd3400000
    uint32_t op = 0xd3400000u
        | (immr << 16)
        | (imms << 10)
        | ((rn & 0x1fu) << 5)
        | (rd & 0x1fu);
    out[0] = op & 0xff;
    out[1] = (op >> 8) & 0xff;
    out[2] = (op >> 16) & 0xff;
    out[3] = (op >> 24) & 0xff;
}

// LSR (immediate) -- UBFM with imms = imms_max, immr = shift. Used to
// verify our LSL decoder does NOT mistake LSR for LSL.
static void lsr_w(uint8_t out[4], unsigned rd, unsigned rn, unsigned shift)
{
    uint32_t op = 0x53000000u
        | ((shift & 0x1fu) << 16)
        | (31u << 10)
        | ((rn & 0x1fu) << 5)
        | (rd & 0x1fu);
    out[0] = op & 0xff;
    out[1] = (op >> 8) & 0xff;
    out[2] = (op >> 16) & 0xff;
    out[3] = (op >> 24) & 0xff;
}

// Shifted-register consumer encoders. Each takes a base value for the
// top bits identifying the operation, then Rd/Rn/Rm slots. imm6 = 0
// and shift type = LSL.
static void encode_sr(uint8_t out[4], uint32_t base,
                      unsigned rd, unsigned rn, unsigned rm)
{
    uint32_t op = base
        | ((rm & 0x1fu) << 16)
        | ((rn & 0x1fu) << 5)
        | (rd & 0x1fu);
    out[0] = op & 0xff;
    out[1] = (op >> 8) & 0xff;
    out[2] = (op >> 16) & 0xff;
    out[3] = (op >> 24) & 0xff;
}

#define ADD_W(out, rd, rn, rm)  encode_sr(out, 0x0b000000u, rd, rn, rm)
#define ADDS_W(out, rd, rn, rm) encode_sr(out, 0x2b000000u, rd, rn, rm)
#define SUB_W(out, rd, rn, rm)  encode_sr(out, 0x4b000000u, rd, rn, rm)
#define ADD_X(out, rd, rn, rm)  encode_sr(out, 0x8b000000u, rd, rn, rm)
#define SUB_X(out, rd, rn, rm)  encode_sr(out, 0xcb000000u, rd, rn, rm)
#define AND_W(out, rd, rn, rm)  encode_sr(out, 0x0a000000u, rd, rn, rm)
#define ORR_W(out, rd, rn, rm)  encode_sr(out, 0x2a000000u, rd, rn, rm)
#define EOR_W(out, rd, rn, rm)  encode_sr(out, 0x4a000000u, rd, rn, rm)

// Arithmetic shifted-register with imm6 = 1 (existing shift). Used to
// verify we do NOT fold into a consumer that already has a shift.
static void add_w_lsl1(uint8_t out[4], unsigned rd, unsigned rn, unsigned rm)
{
    uint32_t op = 0x0b000000u
        | ((rm & 0x1fu) << 16)
        | (1u << 10)        // imm6 = 1
        | ((rn & 0x1fu) << 5)
        | (rd & 0x1fu);
    out[0] = op & 0xff;
    out[1] = (op >> 8) & 0xff;
    out[2] = (op >> 16) & 0xff;
    out[3] = (op >> 24) & 0xff;
}

static void test_lsl_fold(void)
{
    uint8_t code[16];

    // lsl w0, w1, #3 ; add w0, w2, w0 -> add w0, w2, w1, lsl #3 (flag).
    lsl_w(&code[0], 0, 1, 3);
    ADD_W(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // lsl x0, x1, #5 ; add x0, x2, x0 (X-register; flag).
    lsl_x(&code[0], 0, 1, 5);
    ADD_X(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // lsl w0, w1, #2 ; sub w0, w2, w0 -> sub w0, w2, w1, lsl #2 (flag).
    lsl_w(&code[0], 0, 1, 2);
    SUB_W(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // lsl w0, w1, #4 ; and w0, w2, w0 (logical; flag).
    lsl_w(&code[0], 0, 1, 4);
    AND_W(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // lsl w0, w1, #1 ; orr w0, w2, w0 (logical; flag).
    lsl_w(&code[0], 0, 1, 1);
    ORR_W(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // lsl w0, w1, #5 ; eor w0, w2, w0 (logical; flag).
    lsl_w(&code[0], 0, 1, 5);
    EOR_W(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // lsl x0, x1, #32 ; add x0, x2, x0 (maximum-width-half shift; flag).
    lsl_x(&code[0], 0, 1, 32);
    ADD_X(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // lsl x0, x1, #63 ; add x0, x2, x0 (maximum shift; flag).
    lsl_x(&code[0], 0, 1, 63);
    ADD_X(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // adds (flag-setting ADD) consumer; still folds.
    lsl_w(&code[0], 0, 1, 3);
    ADDS_W(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // -- Negative cases --

    // Consumer overwrites a different register: v1 safety condition
    // (Rd_consumer == Rd_lsl) does not hold. Don't flag.
    lsl_w(&code[0], 0, 1, 3);
    ADD_W(&code[4], 5, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // LSL Rd is at Rn position of the consumer, not Rm. v1 only folds
    // when the LSL result is at Rm. Don't flag.
    lsl_w(&code[0], 0, 1, 3);
    ADD_W(&code[4], 0, 0, 2);
    assert(run_helper_check(code, 8) == 0);

    // Width mismatch (W LSL followed by X consumer).
    lsl_w(&code[0], 0, 1, 3);
    ADD_X(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Intervening instruction (movz to an unrelated reg) expires LSL.
    lsl_w(&code[0], 0, 1, 3);
    movz_w(&code[4], 5, 0x1234);
    ADD_W(&code[8], 0, 2, 0);
    assert(run_helper_check(code, 12) == 0);

    // Consumer already has a non-zero shift; we don't try to merge.
    lsl_w(&code[0], 0, 1, 3);
    add_w_lsl1(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Single LSL with no consumer.
    lsl_w(&code[0], 0, 1, 3);
    assert(run_helper_check(code, 4) == 0);

    // LSR -- different alias of UBFM; must not be misread as LSL.
    lsr_w(&code[0], 0, 1, 3);
    ADD_W(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Back-to-back LSLs: the first has no consumer, the second is alone.
    lsl_w(&code[0], 0, 1, 3);
    lsl_w(&code[4], 5, 6, 2);
    assert(run_helper_check(code, 8) == 0);

    // Two independent fold patterns back to back. Both flag.
    lsl_w(&code[0], 0, 1, 3);
    ADD_W(&code[4], 0, 2, 0);
    lsl_w(&code[8], 3, 4, 2);
    SUB_W(&code[12], 3, 5, 3);
    assert(run_helper_check(code, 16) == 2);
}

// CMP Wn, #imm (no shift) = SUBS WZR, Wn, #imm.
static void cmp_w_imm(uint8_t out[4], unsigned rn, unsigned imm12)
{
    uint32_t op = 0x7100001fu
        | ((imm12 & 0xfffu) << 10)
        | ((rn & 0x1fu) << 5);
    out[0] = op & 0xff;
    out[1] = (op >> 8) & 0xff;
    out[2] = (op >> 16) & 0xff;
    out[3] = (op >> 24) & 0xff;
}

static void cmp_x_imm(uint8_t out[4], unsigned rn, unsigned imm12)
{
    uint32_t op = 0xf100001fu
        | ((imm12 & 0xfffu) << 10)
        | ((rn & 0x1fu) << 5);
    out[0] = op & 0xff;
    out[1] = (op >> 8) & 0xff;
    out[2] = (op >> 16) & 0xff;
    out[3] = (op >> 24) & 0xff;
}

// SUBS Wd, Wn, #0 with a real Rd (Rd != 31) -- not a CMP alias and
// must not be flagged.
static void subs_w_imm(uint8_t out[4], unsigned rd, unsigned rn,
                       unsigned imm12)
{
    uint32_t op = 0x71000000u
        | ((imm12 & 0xfffu) << 10)
        | ((rn & 0x1fu) << 5)
        | (rd & 0x1fu);
    out[0] = op & 0xff;
    out[1] = (op >> 8) & 0xff;
    out[2] = (op >> 16) & 0xff;
    out[3] = (op >> 24) & 0xff;
}

// B.cond with relative byte offset (signed, multiple of 4).
static void b_cond(uint8_t out[4], unsigned cond, int32_t byte_offset)
{
    int32_t imm19 = byte_offset / 4;
    uint32_t op = 0x54000000u
        | (((uint32_t)imm19 & 0x7ffffu) << 5)
        | (cond & 0xfu);
    out[0] = op & 0xff;
    out[1] = (op >> 8) & 0xff;
    out[2] = (op >> 16) & 0xff;
    out[3] = (op >> 24) & 0xff;
}

static void test_cmp_zero_branch(void)
{
    uint8_t code[16];

    // cmp w0, #0 ; b.eq +8 (positive; W).
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 0, 8);
    assert(run_helper_check(code, 8) == 1);

    // cmp x5, #0 ; b.ne -16 (positive; X, NE, backward target).
    cmp_x_imm(&code[0], 5, 0);
    b_cond(&code[4], 1, -16);
    assert(run_helper_check(code, 8) == 1);

    // cmp w7, #0 ; b.eq +1MB (positive; near-maximum forward offset).
    cmp_w_imm(&code[0], 7, 0);
    b_cond(&code[4], 0, 0x40000);
    assert(run_helper_check(code, 8) == 1);

    // -- Negative cases --

    // cmp w0, #1 (non-zero immediate); not a CMP-zero.
    cmp_w_imm(&code[0], 0, 1);
    b_cond(&code[4], 0, 8);
    assert(run_helper_check(code, 8) == 0);

    // cmp w0, #0 ; b.lt -- not EQ/NE.
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 11 /* LT */, 8);
    assert(run_helper_check(code, 8) == 0);

    // cmp w0, #0 ; b.gt -- not EQ/NE.
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 12 /* GT */, 8);
    assert(run_helper_check(code, 8) == 0);

    // cmp w0, #0 ; <unrelated> ; b.eq -- intervening instruction
    // expires CMP state.
    cmp_w_imm(&code[0], 0, 0);
    movz_w(&code[4], 5, 1);
    b_cond(&code[8], 0, 8);
    assert(run_helper_check(code, 12) == 0);

    // cmp wzr, #0 ; b.eq -- Rn=31 excluded (always-taken degenerate).
    cmp_w_imm(&code[0], 31, 0);
    b_cond(&code[4], 0, 8);
    assert(run_helper_check(code, 8) == 0);

    // subs w1, w0, #0 (real Rd) ; b.eq -- not a CMP alias, has a side
    // effect (writes w1). Must not fold.
    subs_w_imm(&code[0], 1, 0, 0);
    b_cond(&code[4], 0, 8);
    assert(run_helper_check(code, 8) == 0);

    // b.eq with no preceding cmp -- nothing to fold.
    b_cond(&code[0], 0, 8);
    assert(run_helper_check(code, 4) == 0);

    // Lone cmp without consumer.
    cmp_w_imm(&code[0], 0, 0);
    assert(run_helper_check(code, 4) == 0);

    // Two independent CMP+B.EQ pairs back-to-back.
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 0, 8);
    cmp_x_imm(&code[8], 3, 0);
    b_cond(&code[12], 1, -8);
    assert(run_helper_check(code, 16) == 2);
}

int main(void)
{
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &g_handle) != CS_ERR_OK) {
        fprintf(stderr, "failed to initialize Capstone\n");
        return 1;
    }
    cs_option(g_handle, CS_OPT_DETAIL, CS_OPT_ON);

    test_is_bitmask_immediate_32();
    test_is_bitmask_immediate_64();
    test_movz_movk_sequences();
    test_lsl_fold();
    test_cmp_zero_branch();

    cs_close(&g_handle);
    printf("all tests passed\n");
    return 0;
}
