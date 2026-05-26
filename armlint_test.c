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
        size_t offset = (size_t)insns[i].address;
        for (size_t k = 0; k < armlint_check_registry_count; k++) {
            armlint_finding f;
            if (armlint_check_registry[k](state, &insns[i], offset, &f)) {
                findings++;
            }
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

// Write a 32-bit instruction word as little-endian bytes -- AArch64
// is always little-endian for code. Every encoder below ends with
// this 4-byte split.
static inline void write_le32(uint8_t out[4], uint32_t op)
{
    out[0] = op & 0xff;
    out[1] = (op >> 8) & 0xff;
    out[2] = (op >> 16) & 0xff;
    out[3] = (op >> 24) & 0xff;
}

// MOVZ Wd, #imm16
// sf=0, opc=10, fixed=100101, hw=00, imm16, Rd
// Encoding base: 0x52800000
static void movz_w(uint8_t out[4], unsigned rd, uint16_t imm16)
{
    uint32_t op = 0x52800000u
        | ((uint32_t)(imm16 & 0xffffu) << 5)
        | (rd & 0x1fu);
    write_le32(out, op);
}

// MOVK Wd, #imm16, LSL #(hw*16)
// Encoding base: 0x72800000
static void movk_w(uint8_t out[4], unsigned rd, uint16_t imm16, unsigned hw)
{
    uint32_t op = 0x72800000u
        | ((uint32_t)(hw & 0x3u) << 21)
        | ((uint32_t)(imm16 & 0xffffu) << 5)
        | (rd & 0x1fu);
    write_le32(out, op);
}

// MOVZ Xd, #imm16, LSL #(hw*16). Encoding base: 0xd2800000
static void movz_x(uint8_t out[4], unsigned rd, uint16_t imm16, unsigned hw)
{
    uint32_t op = 0xd2800000u
        | ((uint32_t)(hw & 0x3u) << 21)
        | ((uint32_t)(imm16 & 0xffffu) << 5)
        | (rd & 0x1fu);
    write_le32(out, op);
}

// MOVK Xd. Encoding base: 0xf2800000
static void movk_x(uint8_t out[4], unsigned rd, uint16_t imm16, unsigned hw)
{
    uint32_t op = 0xf2800000u
        | ((uint32_t)(hw & 0x3u) << 21)
        | ((uint32_t)(imm16 & 0xffffu) << 5)
        | (rd & 0x1fu);
    write_le32(out, op);
}

// MOVN Xd. Encoding base: 0x92800000
static void movn_x(uint8_t out[4], unsigned rd, uint16_t imm16, unsigned hw)
{
    uint32_t op = 0x92800000u
        | ((uint32_t)(hw & 0x3u) << 21)
        | ((uint32_t)(imm16 & 0xffffu) << 5)
        | (rd & 0x1fu);
    write_le32(out, op);
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
    write_le32(out, op);
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
    write_le32(out, op);
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
    write_le32(out, op);
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
    write_le32(out, op);
}

#define ADD_W(out, rd, rn, rm)  encode_sr(out, 0x0b000000u, rd, rn, rm)
#define ADDS_W(out, rd, rn, rm) encode_sr(out, 0x2b000000u, rd, rn, rm)
#define SUB_W(out, rd, rn, rm)  encode_sr(out, 0x4b000000u, rd, rn, rm)
#define SUBS_W(out, rd, rn, rm) encode_sr(out, 0x6b000000u, rd, rn, rm)
#define ADD_X(out, rd, rn, rm)  encode_sr(out, 0x8b000000u, rd, rn, rm)
#define SUB_X(out, rd, rn, rm)  encode_sr(out, 0xcb000000u, rd, rn, rm)
#define SUBS_X(out, rd, rn, rm) encode_sr(out, 0xeb000000u, rd, rn, rm)
#define AND_W(out, rd, rn, rm)  encode_sr(out, 0x0a000000u, rd, rn, rm)
#define AND_X(out, rd, rn, rm)  encode_sr(out, 0x8a000000u, rd, rn, rm)
#define ANDS_W(out, rd, rn, rm) encode_sr(out, 0x6a000000u, rd, rn, rm)
#define ANDS_X(out, rd, rn, rm) encode_sr(out, 0xea000000u, rd, rn, rm)
#define BIC_W(out, rd, rn, rm)  encode_sr(out, 0x0a200000u, rd, rn, rm)
#define BICS_W(out, rd, rn, rm) encode_sr(out, 0x6a200000u, rd, rn, rm)
#define ORN_W(out, rd, rn, rm)  encode_sr(out, 0x2a200000u, rd, rn, rm)
#define EON_W(out, rd, rn, rm)  encode_sr(out, 0x4a200000u, rd, rn, rm)
#define BIC_X(out, rd, rn, rm)  encode_sr(out, 0x8a200000u, rd, rn, rm)
#define ORN_X(out, rd, rn, rm)  encode_sr(out, 0xaa200000u, rd, rn, rm)
#define ORR_W(out, rd, rn, rm)  encode_sr(out, 0x2a000000u, rd, rn, rm)
#define ORR_X(out, rd, rn, rm)  encode_sr(out, 0xaa000000u, rd, rn, rm)
#define EOR_W(out, rd, rn, rm)  encode_sr(out, 0x4a000000u, rd, rn, rm)
#define EOR_X(out, rd, rn, rm)  encode_sr(out, 0xca000000u, rd, rn, rm)

// Arithmetic shifted-register with imm6 = 1 (existing shift). Used to
// verify we do NOT fold into a consumer that already has a shift.
static void add_w_lsl1(uint8_t out[4], unsigned rd, unsigned rn, unsigned rm)
{
    uint32_t op = 0x0b000000u
        | ((rm & 0x1fu) << 16)
        | (1u << 10)        // imm6 = 1
        | ((rn & 0x1fu) << 5)
        | (rd & 0x1fu);
    write_le32(out, op);
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
    write_le32(out, op);
}

static void cmp_x_imm(uint8_t out[4], unsigned rn, unsigned imm12)
{
    uint32_t op = 0xf100001fu
        | ((imm12 & 0xfffu) << 10)
        | ((rn & 0x1fu) << 5);
    write_le32(out, op);
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
    write_le32(out, op);
}

// ADD/SUB immediate (non-flag-setting, S=0). bases:
//   ADD Wd: 0x11000000   ADD Xd: 0x91000000
//   SUB Wd: 0x51000000   SUB Xd: 0xD1000000
static void encode_addsub_imm(uint8_t out[4], uint32_t base,
                              unsigned rd, unsigned rn, unsigned imm12)
{
    uint32_t op = base
        | ((imm12 & 0xFFFu) << 10)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}
#define ADD_W_IMM(out, rd, rn, imm) encode_addsub_imm(out, 0x11000000u, rd, rn, imm)
#define SUB_W_IMM(out, rd, rn, imm) encode_addsub_imm(out, 0x51000000u, rd, rn, imm)
#define ADD_X_IMM(out, rd, rn, imm) encode_addsub_imm(out, 0x91000000u, rd, rn, imm)
#define SUB_X_IMM(out, rd, rn, imm) encode_addsub_imm(out, 0xD1000000u, rd, rn, imm)

// ADRP Xd, page_count. immlo in bits 30..29, immhi in bits 23..5.
static void adrp_x(uint8_t out[4], unsigned rd, int imm)
{
    uint32_t op = 0x90000000u
        | (((uint32_t)imm & 0x3u) << 29)
        | ((((uint32_t)imm >> 2) & 0x7FFFFu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// B.cond with relative byte offset (signed, multiple of 4).
static void b_cond(uint8_t out[4], unsigned cond, int32_t byte_offset)
{
    int32_t imm19 = byte_offset / 4;
    uint32_t op = 0x54000000u
        | (((uint32_t)imm19 & 0x7ffffu) << 5)
        | (cond & 0xfu);
    write_le32(out, op);
}

// RET x30 -- the safe-terminator stopper for flag liveness.
static void ret_(uint8_t out[4])
{
    out[0] = 0xC0;
    out[1] = 0x03;
    out[2] = 0x5F;
    out[3] = 0xD6;
}

// BL with byte offset (function call -- LIV_TERM_SAFE).
static void bl_(uint8_t out[4], int32_t byte_offset)
{
    int32_t imm26 = byte_offset / 4;
    uint32_t op = 0x94000000u | ((uint32_t)imm26 & 0x3FFFFFFu);
    write_le32(out, op);
}

// B (unconditional) -- LIV_TERM_UNSAFE.
static void b_(uint8_t out[4], int32_t byte_offset)
{
    int32_t imm26 = byte_offset / 4;
    uint32_t op = 0x14000000u | ((uint32_t)imm26 & 0x3FFFFFFu);
    write_le32(out, op);
}

// ADCS Wd, Wn, Wm -- reads C; LIV_READ.
static void adcs_w(uint8_t out[4], unsigned rd, unsigned rn, unsigned rm)
{
    uint32_t op = 0x3A000000u
        | ((rm & 0x1fu) << 16)
        | ((rn & 0x1fu) << 5)
        | (rd & 0x1fu);
    write_le32(out, op);
}

// CSEL Wd, Wn, Wm, cond -- reads NZCV; LIV_READ.
static void csel_w(uint8_t out[4], unsigned rd, unsigned rn, unsigned rm,
                   unsigned cond)
{
    uint32_t op = 0x1A800000u
        | ((rm & 0x1fu) << 16)
        | ((cond & 0xfu) << 12)
        | ((rn & 0x1fu) << 5)
        | (rd & 0x1fu);
    write_le32(out, op);
}

static void csel_x(uint8_t out[4], unsigned rd, unsigned rn, unsigned rm,
                   unsigned cond)
{
    uint32_t op = 0x9A800000u
        | ((rm & 0x1fu) << 16)
        | ((cond & 0xfu) << 12)
        | ((rn & 0x1fu) << 5)
        | (rd & 0x1fu);
    write_le32(out, op);
}

// CSINC Wd, Wn, Wm, cond -- different from CSEL (op2 = 01 vs 00) and
// NOT a same-operand identity (else branch is Wn + 1).
static void csinc_w(uint8_t out[4], unsigned rd, unsigned rn, unsigned rm,
                    unsigned cond)
{
    uint32_t op = 0x1A800400u
        | ((rm & 0x1fu) << 16)
        | ((cond & 0xfu) << 12)
        | ((rn & 0x1fu) << 5)
        | (rd & 0x1fu);
    write_le32(out, op);
}

// TST Wn, #(1<<k) -- ANDS WZR, Wn, #imm with N=0, imms=0, immr =
// (32 - k) mod 32. k must be in [0, 31].
static void tst_w_bit(uint8_t out[4], unsigned rn, unsigned k)
{
    unsigned immr = (32u - k) % 32u;
    uint32_t op = 0x7200001Fu
        | ((immr & 0x3Fu) << 16)
        | ((rn & 0x1Fu) << 5);
    write_le32(out, op);
}

// TST Xn, #(1<<k) -- ANDS XZR, Xn, #imm with N=1, imms=0, immr =
// (64 - k) mod 64. k must be in [0, 63].
static void tst_x_bit(uint8_t out[4], unsigned rn, unsigned k)
{
    unsigned immr = (64u - k) % 64u;
    uint32_t op = 0xF240001Fu
        | ((immr & 0x3Fu) << 16)
        | ((rn & 0x1Fu) << 5);
    write_le32(out, op);
}

// TST Wn, #imm where imm is NOT a single bit (multi-bit mask) -- used
// to verify the decoder rejects multi-bit immediates. We pass an N=0,
// imms=k (so S=k, S+1 ones) which produces a run of k+1 ones in the
// low bits. For k>=1, this is at least two ones.
static void tst_w_run(uint8_t out[4], unsigned rn, unsigned imms)
{
    uint32_t op = 0x7200001Fu
        | ((imms & 0x3Fu) << 10)
        | ((rn & 0x1Fu) << 5);
    write_le32(out, op);
}

// UXTW Xd, Wn = UBFM Xd, Xn, #0, #31 (sf=1, N=1, immr=0, imms=31).
static void uxtw(uint8_t out[4], unsigned rd, unsigned rn)
{
    uint32_t op = 0xD3407C00u
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// AND Xd, Xn, #0xffffffff (sf=1, opc=00, N=1, immr=0, imms=31).
static void and_x_ff32(uint8_t out[4], unsigned rd, unsigned rn)
{
    uint32_t op = 0x92407C00u
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// UXTH Xd, Wn = UBFM Xd, Xn, #0, #15 (sf=1, N=1, immr=0, imms=15).
// This is now a valid consumer matching to C=16.
static void uxth_x(uint8_t out[4], unsigned rd, unsigned rn)
{
    uint32_t op = 0xD3400000u
        | (15u << 10)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// UXTH Wd, Wn = UBFM Wd, Wn, #0, #15 (sf=0, N=0, immr=0, imms=15).
static void uxth_w(uint8_t out[4], unsigned rd, unsigned rn)
{
    uint32_t op = 0x53000000u
        | (15u << 10)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// UXTB Wd, Wn = UBFM Wd, Wn, #0, #7 (sf=0, N=0, immr=0, imms=7).
static void uxtb_w(uint8_t out[4], unsigned rd, unsigned rn)
{
    uint32_t op = 0x53000000u
        | (7u << 10)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// MOV Xd, Xm = ORR Xd, XZR, Xm, LSL #0. Base 0xAA0003E0.
static void mov_x(uint8_t out[4], unsigned rd, unsigned rm)
{
    uint32_t op = 0xAA0003E0u
        | ((rm & 0x1Fu) << 16)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// MOV Wd, Wm = ORR Wd, WZR, Wm, LSL #0. Base 0x2A0003E0.
static void mov_w_reg(uint8_t out[4], unsigned rd, unsigned rm)
{
    uint32_t op = 0x2A0003E0u
        | ((rm & 0x1Fu) << 16)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// AND Wd, Wn, #0xFF -- sf=0, N=0, immr=0, imms=7.
static void and_w_ff(uint8_t out[4], unsigned rd, unsigned rn)
{
    uint32_t op = 0x12001C00u
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// CMP Rn, Rm (shifted-register form, shift=LSL, imm6=0).
//   sf 1 1 01011 00 0 Rm 000000 Rn 11111
static void cmp_w_reg(uint8_t out[4], unsigned rn, unsigned rm)
{
    uint32_t op = 0x6B00001Fu
        | ((rm & 0x1Fu) << 16)
        | ((rn & 0x1Fu) << 5);
    write_le32(out, op);
}

static void cmp_x_reg(uint8_t out[4], unsigned rn, unsigned rm)
{
    uint32_t op = 0xEB00001Fu
        | ((rm & 0x1Fu) << 16)
        | ((rn & 0x1Fu) << 5);
    write_le32(out, op);
}

// TST Rn, Rm (logical shifted-register form, shift=LSL, N=0, imm6=0).
//   sf 11 01010 00 0 Rm 000000 Rn 11111
static void tst_w_reg(uint8_t out[4], unsigned rn, unsigned rm)
{
    uint32_t op = 0x6A00001Fu
        | ((rm & 0x1Fu) << 16)
        | ((rn & 0x1Fu) << 5);
    write_le32(out, op);
}

static void tst_x_reg(uint8_t out[4], unsigned rn, unsigned rm)
{
    uint32_t op = 0xEA00001Fu
        | ((rm & 0x1Fu) << 16)
        | ((rn & 0x1Fu) << 5);
    write_le32(out, op);
}

// LSR (immediate) Wd, Wn, #b -- UBFM Wd, Wn, #b, #31 (already have
// lsr_w; here too in X form).
static void lsr_x(uint8_t out[4], unsigned rd, unsigned rn, unsigned shift)
{
    uint32_t op = 0xD340FC00u
        | ((shift & 0x3Fu) << 16)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// ASR (immediate) -- SBFM with imms = datasize-1.
static void asr_w(uint8_t out[4], unsigned rd, unsigned rn, unsigned shift)
{
    uint32_t op = 0x13007C00u
        | ((shift & 0x1Fu) << 16)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

static void asr_x(uint8_t out[4], unsigned rd, unsigned rn, unsigned shift)
{
    uint32_t op = 0x9340FC00u
        | ((shift & 0x3Fu) << 16)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// LDR/LDRH/LDRB Wt with unsigned-immediate offset.
//   LDR  Wt: size=10, opc=01 -> base 0xB9400000
//   LDRH Wt: size=01, opc=01 -> base 0x79400000
//   LDRB Wt: size=00, opc=01 -> base 0x39400000
static void encode_ldr_imm(uint8_t out[4], uint32_t base, unsigned rt,
                           unsigned rn, unsigned imm12)
{
    uint32_t op = base
        | ((imm12 & 0xFFFu) << 10)
        | ((rn & 0x1Fu) << 5)
        | (rt & 0x1Fu);
    write_le32(out, op);
}

#define LDR_W(out, rt, rn, imm)  encode_ldr_imm(out, 0xB9400000u, rt, rn, imm)
#define LDR_X(out, rt, rn, imm)  encode_ldr_imm(out, 0xF9400000u, rt, rn, imm)
#define LDRH_W(out, rt, rn, imm) encode_ldr_imm(out, 0x79400000u, rt, rn, imm)
#define LDRB_W(out, rt, rn, imm) encode_ldr_imm(out, 0x39400000u, rt, rn, imm)
#define STR_W(out, rt, rn, imm)  encode_ldr_imm(out, 0xB9000000u, rt, rn, imm)
#define STR_X(out, rt, rn, imm)  encode_ldr_imm(out, 0xF9000000u, rt, rn, imm)

// Sign-extending integer loads, unsigned-immediate-offset form. The
// addressing-mode bit (24) is set; mask in armlint.c leaves it free so
// other addressing modes match the same producer pattern.
//   LDRSB Xt: size=00, opc=10 -> base 0x39800000
//   LDRSB Wt: size=00, opc=11 -> base 0x39C00000
//   LDRSH Xt: size=01, opc=10 -> base 0x79800000
//   LDRSH Wt: size=01, opc=11 -> base 0x79C00000
//   LDRSW Xt: size=10, opc=10 -> base 0xB9800000
#define LDRSB_X(out, rt, rn, imm) encode_ldr_imm(out, 0x39800000u, rt, rn, imm)
#define LDRSB_W(out, rt, rn, imm) encode_ldr_imm(out, 0x39C00000u, rt, rn, imm)
#define LDRSH_X(out, rt, rn, imm) encode_ldr_imm(out, 0x79800000u, rt, rn, imm)
#define LDRSH_W(out, rt, rn, imm) encode_ldr_imm(out, 0x79C00000u, rt, rn, imm)
#define LDRSW_X(out, rt, rn, imm) encode_ldr_imm(out, 0xB9800000u, rt, rn, imm)

// SBFM SXT* aliases. SXTB/SXTH (W- and X-form) and SXTW (X-form only).
//   SXTB Wd, Wn: SBFM Wd, Wn, #0, #7  -> sf=0, N=0, imms=7  -> 0x13001C00
//   SXTH Wd, Wn: SBFM Wd, Wn, #0, #15 -> sf=0, N=0, imms=15 -> 0x13003C00
//   SXTB Xd, Wn: SBFM Xd, Xn, #0, #7  -> sf=1, N=1, imms=7  -> 0x93401C00
//   SXTH Xd, Wn: SBFM Xd, Xn, #0, #15 -> sf=1, N=1, imms=15 -> 0x93403C00
//   SXTW Xd, Wn: SBFM Xd, Xn, #0, #31 -> sf=1, N=1, imms=31 -> 0x93407C00
static void encode_sbfm_zero_immr(uint8_t out[4], uint32_t base,
                                  unsigned rd, unsigned rn)
{
    uint32_t op = base
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

#define SXTB_W(out, rd, rn) encode_sbfm_zero_immr(out, 0x13001C00u, rd, rn)
#define SXTH_W(out, rd, rn) encode_sbfm_zero_immr(out, 0x13003C00u, rd, rn)
#define SXTB_X(out, rd, rn) encode_sbfm_zero_immr(out, 0x93401C00u, rd, rn)
#define SXTH_X(out, rd, rn) encode_sbfm_zero_immr(out, 0x93403C00u, rd, rn)
#define SXTW_X(out, rd, rn) encode_sbfm_zero_immr(out, 0x93407C00u, rd, rn)

static void test_cmp_zero_branch(void)
{
    uint8_t code[32];

    // -- Positive: stopper present, no flag use --

    // cmp w0,#0 ; b.eq +8 ; ret (RET = LIV_TERM_SAFE; fold safe).
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 0, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // cmp x5,#0 ; b.ne -16 ; ret (X register, NE).
    cmp_x_imm(&code[0], 5, 0);
    b_cond(&code[4], 1, -16);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // cmp w7,#0 ; b.eq +1MB ; ret (near-maximum forward branch).
    cmp_w_imm(&code[0], 7, 0);
    b_cond(&code[4], 0, 0x40000);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // cmp w0,#0 ; b.eq L ; bl func (BL = LIV_TERM_SAFE).
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 0, 8);
    bl_(&code[8], 0x100);
    assert(run_helper_check(code, 12) == 1);

    // cmp w0,#0 ; b.eq L ; cmp w1,#0 (next CMP overwrites NZCV; safe).
    // Two findings: the first is fully verified by the second's
    // overwrite; the second is itself a new pending that gets
    // discarded at flush (no stopper after it).
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 0, 8);
    cmp_w_imm(&code[8], 1, 0);
    b_cond(&code[12], 0, 8);
    ret_(&code[16]);
    assert(run_helper_check(code, 20) == 2);

    // Window: 14 UNKNOWN insns (LDR-shaped slots represented by MOV
    // immediates) then RET -- still within the 16-instruction window.
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 0, 8);
    // 14 MOVZ instructions (no flag effect, no terminator):
    {
        uint8_t big[4 + 4 + 14 * 4 + 4];
        cmp_w_imm(&big[0], 0, 0);
        b_cond(&big[4], 0, 8);
        for (int i = 0; i < 14; i++) {
            movz_w(&big[8 + i * 4], 5, (uint16_t)(i + 1));
        }
        ret_(&big[8 + 14 * 4]);
        assert(run_helper_check(big, sizeof(big)) == 1);
    }

    // -- Negative: flag readers immediately after the branch --

    // cmp w0,#0 ; b.eq L ; b.lt M (B.cond reads NZCV; suppress).
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 0, 8);
    b_cond(&code[8], 11 /* LT */, 8);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 0);

    // cmp w0,#0 ; b.eq L ; adcs w1,w2,w3 (reads C; suppress).
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 0, 8);
    adcs_w(&code[8], 1, 2, 3);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 0);

    // cmp w0,#0 ; b.eq L ; csel w1,w2,w3,eq (reads NZCV; suppress).
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 0, 8);
    csel_w(&code[8], 1, 2, 3, 0);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 0);

    // -- Negative: unsafe terminator --

    // cmp w0,#0 ; b.eq L ; b M (unconditional B; target may read NZCV).
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 0, 8);
    b_(&code[8], 0x100);
    assert(run_helper_check(code, 12) == 0);

    // -- Negative: window expiry --

    // cmp w0,#0 ; b.eq L ; 16 MOVZ ; ret -- 16 UNKNOWN insns exceed
    // the window (must see a stopper within LIVENESS_WINDOW=16);
    // pending is discarded.
    {
        uint8_t big[4 + 4 + 16 * 4 + 4];
        cmp_w_imm(&big[0], 0, 0);
        b_cond(&big[4], 0, 8);
        for (int i = 0; i < 16; i++) {
            movz_w(&big[8 + i * 4], 5, (uint16_t)(i + 1));
        }
        ret_(&big[8 + 16 * 4]);
        assert(run_helper_check(big, sizeof(big)) == 0);
    }

    // -- Pre-existing negatives, with a trailing RET so the positive
    //    paths (if any) would have had a stopper. --

    // cmp w0,#1 (non-zero immediate); not a CMP-zero.
    cmp_w_imm(&code[0], 0, 1);
    b_cond(&code[4], 0, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 0);

    // cmp w0,#0 ; b.gt (not EQ/NE).
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 12 /* GT */, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 0);

    // cmp w0,#0 ; movz w5,#1 ; b.eq -- intervening instruction
    // expires CMP state before the B.EQ is seen.
    cmp_w_imm(&code[0], 0, 0);
    movz_w(&code[4], 5, 1);
    b_cond(&code[8], 0, 8);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 0);

    // cmp wzr,#0 ; b.eq -- Rn=31 excluded.
    cmp_w_imm(&code[0], 31, 0);
    b_cond(&code[4], 0, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 0);

    // subs w1,w0,#0 (real Rd); not a CMP alias.
    subs_w_imm(&code[0], 1, 0, 0);
    b_cond(&code[4], 0, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 0);

    // b.eq with no preceding cmp.
    b_cond(&code[0], 0, 8);
    ret_(&code[4]);
    assert(run_helper_check(code, 8) == 0);

    // Lone cmp without consumer.
    cmp_w_imm(&code[0], 0, 0);
    ret_(&code[4]);
    assert(run_helper_check(code, 8) == 0);

    // CMP+B.EQ at end of region with no stopper at all -- pending
    // discarded on flush.
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 0, 8);
    assert(run_helper_check(code, 8) == 0);

    // -- New zero-test idioms: CMP Rn, XZR / TST Rn, Rn. --

    // cmp w0, wzr ; b.eq ; ret -- shifted-reg form folds same as #0.
    cmp_w_reg(&code[0], 0, 31);
    b_cond(&code[4], 0, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // cmp x5, xzr ; b.ne ; ret
    cmp_x_reg(&code[0], 5, 31);
    b_cond(&code[4], 1, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // tst w0, w0 ; b.eq ; ret -- ANDS XZR, w0, w0 form.
    tst_w_reg(&code[0], 0, 0);
    b_cond(&code[4], 0, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // tst x5, x5 ; b.ne ; ret
    tst_x_reg(&code[0], 5, 5);
    b_cond(&code[4], 1, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // tst w0, w1 ; b.eq -- not a self-AND, no fold.
    tst_w_reg(&code[0], 0, 1);
    b_cond(&code[4], 0, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 0);

    // cmp w0, w1 ; b.eq -- Rm != XZR, no fold (it's a register compare).
    cmp_w_reg(&code[0], 0, 1);
    b_cond(&code[4], 0, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 0);

    // tst wzr, wzr ; b.eq -- Rn=31 excluded.
    tst_w_reg(&code[0], 31, 31);
    b_cond(&code[4], 0, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 0);

    // cmp wzr, wzr ; b.eq -- Rn=31 excluded.
    cmp_w_reg(&code[0], 31, 31);
    b_cond(&code[4], 0, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 0);

    // -- Positive: sign-bit branch idioms. CMP/TST + B.LT/GE/MI/PL
    //    folds to TBZ/TBNZ on the sign bit (datasize - 1). --

    // cmp w0, #0 ; b.lt +8 ; ret -- B.LT after CMP-zero is "Rn < 0".
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 11 /* LT */, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // cmp w0, #0 ; b.ge +8 ; ret.
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 10 /* GE */, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // cmp w0, #0 ; b.mi +8 ; ret -- B.MI directly tests N.
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 4 /* MI */, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // cmp w0, #0 ; b.pl +8 ; ret.
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 5 /* PL */, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // cmp x5, #0 (X-form) ; b.lt +8 ; ret -> tbnz x5, #63.
    cmp_x_imm(&code[0], 5, 0);
    b_cond(&code[4], 11 /* LT */, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // tst w0, w0 ; b.lt +8 ; ret -- TST-self also sets N = sign(Rn),
    // V = 0, so the same sign-bit fold applies.
    tst_w_reg(&code[0], 0, 0);
    b_cond(&code[4], 11 /* LT */, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // cmp w0, wzr ; b.ge +8 ; ret.
    cmp_w_reg(&code[0], 0, 31);
    b_cond(&code[4], 10 /* GE */, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // -- Negative: B.GT / B.LE -- read Z in addition to N, V; the
    //    sign-bit-only fold doesn't apply. --

    // cmp w0, #0 ; b.gt +8 ; ret -- B.GT tests "Rn > 0", not just sign.
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 12 /* GT */, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 0);

    // cmp w0, #0 ; b.le +8 ; ret.
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 13 /* LE */, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 0);

    // -- Negative: TBZ range. B.LT at +32 KB (imm19 = 8192) is one
    //    past TBZ's reach. --
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 11 /* LT */, 8192 * 4);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 0);

    // Just in range (imm19 = 8190 -> tbz disp 8191).
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 11 /* LT */, 8190 * 4);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // -- Negative: downstream reads N/C/V -- both CBZ and sign-bit
    //    folds suppressed by the same liveness scan. --

    // cmp w0,#0 ; b.lt L ; adcs (reads C) -- suppress.
    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 11 /* LT */, 8);
    adcs_w(&code[8], 1, 2, 3);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 0);
}

static void test_tst_branch(void)
{
    uint8_t code[16];

    // -- Positive: single-bit TST + B.EQ/NE, in range, with stopper. --

    // tst w0, #1 ; b.eq +8 ; ret -- bit 0, W register.
    tst_w_bit(&code[0], 0, 0);
    b_cond(&code[4], 0, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // tst w0, #(1<<5) ; b.ne +8 ; ret -- mid-range bit, NE.
    tst_w_bit(&code[0], 0, 5);
    b_cond(&code[4], 1, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // tst w0, #(1<<31) ; b.eq -- top bit of W.
    tst_w_bit(&code[0], 0, 31);
    b_cond(&code[4], 0, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // tst x5, #(1<<40) ; b.eq -- X register, bit > 31.
    tst_x_bit(&code[0], 5, 40);
    b_cond(&code[4], 0, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // tst x0, #(1<<63) ; b.ne -- top bit of X.
    tst_x_bit(&code[0], 0, 63);
    b_cond(&code[4], 1, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // -- Negative: multi-bit TST mask -- not a single bit. --

    // tst w0, #3 (imms=1 -> S+1=2 ones at the low end).
    tst_w_run(&code[0], 0, 1);
    b_cond(&code[4], 0, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 0);

    // tst w0, #0xff (8 ones).
    tst_w_run(&code[0], 0, 7);
    b_cond(&code[4], 0, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 0);

    // -- Negative: range -- target too far for TBZ's 14-bit imm. --

    // tst w0, #1 ; b.eq +32 KB (just past TBZ's reach).
    // imm19 = 8192, tbz disp = 8193, out of range [-8192, 8191].
    tst_w_bit(&code[0], 0, 0);
    b_cond(&code[4], 0, 8192 * 4);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 0);

    // tst w0, #1 ; b.eq just within range.
    // imm19 = 8190, tbz disp = 8191, in range.
    tst_w_bit(&code[0], 0, 0);
    b_cond(&code[4], 0, 8190 * 4);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 1);

    // -- Negative: flag liveness same as CMP check. --

    // tst w0, #1 ; b.eq ; adcs reads C -> suppress.
    tst_w_bit(&code[0], 0, 0);
    b_cond(&code[4], 0, 8);
    adcs_w(&code[8], 1, 2, 3);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 0);

    // tst w0, #1 ; b.eq ; b.lt -> suppress.
    tst_w_bit(&code[0], 0, 0);
    b_cond(&code[4], 0, 8);
    b_cond(&code[8], 11 /* LT */, 8);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 0);

    // -- Negative: not EQ/NE. --

    // tst w0, #1 ; b.lt -- wrong cond, no fold.
    tst_w_bit(&code[0], 0, 0);
    b_cond(&code[4], 11 /* LT */, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 0);

    // -- Negative: intervening instruction expires tst_active. --

    // tst w0, #1 ; movz w5, #1 ; b.eq -- TST state cleared.
    tst_w_bit(&code[0], 0, 0);
    movz_w(&code[4], 5, 1);
    b_cond(&code[8], 0, 8);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 0);

    // -- Negative: TST WZR (Rn=31) excluded. --

    tst_w_bit(&code[0], 31, 0);
    b_cond(&code[4], 0, 8);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 0);

    // -- Lone TST without consumer. --

    tst_w_bit(&code[0], 0, 0);
    ret_(&code[4]);
    assert(run_helper_check(code, 8) == 0);

    // -- Interaction: CMP+B.EQ then TST+B.EQ both flag if stopped. --

    cmp_w_imm(&code[0], 0, 0);
    b_cond(&code[4], 0, 8);
    tst_w_bit(&code[8], 1, 3);   // overwrites NZCV (ANDS), emits CMP finding
    b_cond(&code[12], 0, 8);     // closes tst, sets new pending
    // (No stopper after this in the buffer; tst finding will be
    // discarded on flush.)
    assert(run_helper_check(code, 16) == 1);
}

static void test_redundant_zext(void)
{
    uint8_t code[16];

    // -- Positive: W-form producer immediately followed by UXTW/AND. --

    // add w0, w1, w2 ; uxtw x0, w0 -- shifted-register ADD W.
    ADD_W(&code[0], 0, 1, 2);
    uxtw(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // add w0, w1, w2 ; and x0, x0, #0xffffffff.
    ADD_W(&code[0], 0, 1, 2);
    and_x_ff32(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // movz w0, #0x1234 ; uxtw x0, w0 -- move-wide producer.
    movz_w(&code[0], 0, 0x1234);
    uxtw(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // lsl w0, w1, #3 ; uxtw x0, w0 -- bitfield (UBFM) producer.
    lsl_w(&code[0], 0, 1, 3);
    uxtw(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // csel w0, w1, w2, eq ; uxtw x0, w0 -- conditional select producer.
    csel_w(&code[0], 0, 1, 2, 0);
    uxtw(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // subs w0, w1, #1 ; uxtw x0, w0 -- add/sub imm with real Rd.
    subs_w_imm(&code[0], 0, 1, 1);
    uxtw(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // -- Negative: producer is X-form -- bits 63..32 not pre-zeroed.

    ADD_X(&code[0], 0, 1, 2);
    uxtw(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: consumer's Rn doesn't match producer's Rd. --

    ADD_W(&code[0], 0, 1, 2);
    uxtw(&code[4], 0, 5);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: consumer's Rd doesn't match producer's Rd. --

    ADD_W(&code[0], 0, 1, 2);
    uxtw(&code[4], 5, 0);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: intervening instruction expires wzx state. --

    ADD_W(&code[0], 0, 1, 2);
    movz_w(&code[4], 5, 1);
    uxtw(&code[8], 0, 0);
    assert(run_helper_check(code, 12) == 0);

    // -- Negative: lone UXTW with no preceding W-form producer.

    uxtw(&code[0], 0, 0);
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: UXTH (different alias of UBFM, not zero-extend-32). --

    ADD_W(&code[0], 0, 1, 2);
    uxth_x(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: producer with Rd=31 (WZR -- result is discarded). --

    // adds wzr, w1, w2 (flag-only); should not open wzx.
    ADDS_W(&code[0], 31, 1, 2);
    uxtw(&code[4], 31, 31);
    assert(run_helper_check(code, 8) == 0);

    // -- Interaction: LSL+ADD fold AND redundant uxtw -- two findings. --

    // lsl w0, w1, #3 ; add w0, w2, w0 ; uxtw x0, w0.
    lsl_w(&code[0], 0, 1, 3);
    ADD_W(&code[4], 0, 2, 0);
    uxtw(&code[8], 0, 0);
    assert(run_helper_check(code, 12) == 2);

    // -- Load producers: P depends on access width. --

    // ldr w0, [x1] ; uxtw x0, w0 -- LDR W (P=32) + UXTW (C=32).
    LDR_W(&code[0], 0, 1, 0);
    uxtw(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrh w0, [x1] ; uxth w0, w0 -- LDRH (P=16) + UXTH W (C=16).
    LDRH_W(&code[0], 0, 1, 0);
    uxth_w(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrh w0, [x1] ; uxtw x0, w0 -- LDRH (P=16) + UXTW (C=32), still redundant.
    LDRH_W(&code[0], 0, 1, 0);
    uxtw(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrh w0, [x1] ; uxth x0, w0 -- LDRH + UXTH X form (C=16).
    LDRH_W(&code[0], 0, 1, 0);
    uxth_x(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrb w0, [x1] ; uxtb w0, w0 -- LDRB (P=8) + UXTB (C=8).
    LDRB_W(&code[0], 0, 1, 0);
    uxtb_w(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrb w0, [x1] ; uxth w0, w0 -- LDRB (P=8) + UXTH (C=16), still redundant.
    LDRB_W(&code[0], 0, 1, 0);
    uxth_w(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrb w0, [x1] ; and w0, w0, #0xff -- LDRB (P=8) + AND W #0xFF (C=8).
    LDRB_W(&code[0], 0, 1, 0);
    and_w_ff(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrh w0, [x1] ; uxtb w0, w0 -- LDRH (P=16) > UXTB (C=8); NOT redundant.
    LDRH_W(&code[0], 0, 1, 0);
    uxtb_w(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 0);

    // ldr w0, [x1] ; uxth w0, w0 -- LDR W (P=32) > UXTH (C=16); NOT redundant.
    LDR_W(&code[0], 0, 1, 0);
    uxth_w(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 0);

    // add w0, w1, w2 ; uxth w0, w0 -- ADD (P=32) > UXTH (C=16); NOT redundant.
    ADD_W(&code[0], 0, 1, 2);
    uxth_w(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 0);

    // -- W-form MOV-to-self as the consumer. --

    // add w0, w1, w2 ; mov w0, w0 -- W-form ALU (P=32) + ORR Wd,WZR,Wd (C=32).
    ADD_W(&code[0], 0, 1, 2);
    mov_w_reg(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrh w0, [x1] ; mov w0, w0 -- LDRH (P=16) + MOV self (C=32).
    LDRH_W(&code[0], 0, 1, 0);
    mov_w_reg(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrb w0, [x1] ; mov w0, w0 -- LDRB (P=8) + MOV self (C=32).
    LDRB_W(&code[0], 0, 1, 0);
    mov_w_reg(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // -- Negative: MOV w0, w5 -- different source register, not self-MOV.
    //    Producer's wzx state should not match.

    ADD_W(&code[0], 0, 1, 2);
    mov_w_reg(&code[4], 0, 5);
    assert(run_helper_check(code, 8) == 0);
}

// AND Wd, Wn, #imm where imm = (1<<w) - 1. sf=0, N=0, immr=0, imms=w-1.
static void and_w_lowmask(uint8_t out[4], unsigned rd, unsigned rn,
                          unsigned w)
{
    unsigned imms = w - 1u;
    uint32_t op = 0x12000000u
        | ((imms & 0x3Fu) << 10)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// AND Xd, Xn, #imm where imm = (1<<w) - 1. sf=1, N=1, immr=0, imms=w-1.
static void and_x_lowmask(uint8_t out[4], unsigned rd, unsigned rn,
                          unsigned w)
{
    unsigned imms = w - 1u;
    uint32_t op = 0x92400000u
        | ((imms & 0x3Fu) << 10)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// AND Wd, Wn, #~((1<<w)-1). Encoding: sf=0, N=0, immr=32-w,
// imms=31-w. (Note immr = imms + 1.)
static void and_w_highmask(uint8_t out[4], unsigned rd, unsigned rn,
                           unsigned w)
{
    unsigned imms = 31u - w;
    unsigned immr = 32u - w;
    uint32_t op = 0x12000000u
        | ((immr & 0x3Fu) << 16)
        | ((imms & 0x3Fu) << 10)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// AND Xd, Xn, #~((1<<w)-1). sf=1, N=1, immr=64-w, imms=63-w.
static void and_x_highmask(uint8_t out[4], unsigned rd, unsigned rn,
                           unsigned w)
{
    unsigned imms = 63u - w;
    unsigned immr = 64u - w;
    uint32_t op = 0x92400000u
        | ((immr & 0x3Fu) << 16)
        | ((imms & 0x3Fu) << 10)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// AND Wd, Wn, #0x6 (mask 0b110 -- not contiguous-low). Used to verify
// the decoder rejects non-low-run masks.
static void and_w_non_contig_lo(uint8_t out[4], unsigned rd, unsigned rn)
{
    // AND Wd, Wn, #0x6 (mask = 0b110, a 2-bit run rotated up by 1).
    // sf=0, N=0, esize=32: imms=1 (S=1 -> 2 ones), immr=31 (ROR by 31
    // moves the bottom-two-ones run up by 1 bit position).
    uint32_t op = 0x12000000u
        | (31u << 16)   // immr = 31
        | (1u << 10)    // imms = 1
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

static void test_lsl_lsr_to_ubfx(void)
{
    uint8_t code[12];

    // -- Positive: LSL #a + LSR #b with b > a -> UBFX (zero-extending). --

    // lsl w0, w1, #4 ; lsr w0, w0, #12 -> ubfx w0, w1, #8, #20.
    lsl_w(&code[0], 0, 1, 4);
    lsr_w(&code[4], 0, 0, 12);
    assert(run_helper_check(code, 8) == 1);

    // lsl x5, x6, #8 ; lsr x5, x5, #16 -> ubfx x5, x6, #8, #48.
    lsl_x(&code[0], 5, 6, 8);
    lsr_x(&code[4], 5, 5, 16);
    assert(run_helper_check(code, 8) == 1);

    // -- Positive: LSL #a + LSR #a (b == a) -> UBFX with lsb=0 (= AND mask).

    // lsl w0, w1, #8 ; lsr w0, w0, #8 -> ubfx w0, w1, #0, #24.
    lsl_w(&code[0], 0, 1, 8);
    lsr_w(&code[4], 0, 0, 8);
    assert(run_helper_check(code, 8) == 1);

    // -- Positive: LSL + ASR -> SBFX (sign-extending). --

    // lsl w0, w1, #16 ; asr w0, w0, #24 -> sbfx w0, w1, #8, #8.
    lsl_w(&code[0], 0, 1, 16);
    asr_w(&code[4], 0, 0, 24);
    assert(run_helper_check(code, 8) == 1);

    // lsl x0, x1, #40 ; asr x0, x0, #56 -> sbfx x0, x1, #16, #8.
    lsl_x(&code[0], 0, 1, 40);
    asr_x(&code[4], 0, 0, 56);
    assert(run_helper_check(code, 8) == 1);

    // -- Positive: b < a -- UBFIZ/SBFIZ insertion form. --

    // lsl w0, w1, #12 ; lsr w0, w0, #4 -> ubfiz w0, w1, #8, #20.
    lsl_w(&code[0], 0, 1, 12);
    lsr_w(&code[4], 0, 0, 4);
    assert(run_helper_check(code, 8) == 1);

    // lsl x0, x1, #40 ; lsr x0, x0, #8 -> ubfiz x0, x1, #32, #24.
    lsl_x(&code[0], 0, 1, 40);
    lsr_x(&code[4], 0, 0, 8);
    assert(run_helper_check(code, 8) == 1);

    // lsl w0, w1, #20 ; asr w0, w0, #4 -> sbfiz w0, w1, #16, #12.
    lsl_w(&code[0], 0, 1, 20);
    asr_w(&code[4], 0, 0, 4);
    assert(run_helper_check(code, 8) == 1);

    // lsl x0, x1, #56 ; asr x0, x0, #8 -> sbfiz x0, x1, #48, #8.
    lsl_x(&code[0], 0, 1, 56);
    asr_x(&code[4], 0, 0, 8);
    assert(run_helper_check(code, 8) == 1);

    // lsl w0, w1, #31 ; lsr w0, w0, #1 -> ubfiz w0, w1, #30, #1
    // (a=datasize-1; single-bit insert at the top minus one).
    lsl_w(&code[0], 0, 1, 31);
    lsr_w(&code[4], 0, 0, 1);
    assert(run_helper_check(code, 8) == 1);

    // -- Negative: Rd mismatch. --

    // lsl w0, w1, #4 ; lsr w5, w0, #12 -- consumer Rd != bsx_rd.
    lsl_w(&code[0], 0, 1, 4);
    lsr_w(&code[4], 5, 0, 12);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: Rn mismatch (consumer reads a different register). --

    // lsl w0, w1, #4 ; lsr w0, w5, #12 -- consumer Rn != bsx_rd.
    lsl_w(&code[0], 0, 1, 4);
    lsr_w(&code[4], 0, 5, 12);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: width mismatch. --

    // lsl w0, w1, #4 ; lsr x0, x0, #12 -- W LSL then X LSR; widths differ.
    lsl_w(&code[0], 0, 1, 4);
    lsr_x(&code[4], 0, 0, 12);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: intervening instruction expires bsx_active. --

    lsl_w(&code[0], 0, 1, 4);
    movz_w(&code[4], 5, 1);
    lsr_w(&code[8], 0, 0, 12);
    assert(run_helper_check(code, 12) == 0);

    // -- Negative: LSL with no consumer. --

    lsl_w(&code[0], 0, 1, 4);
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: LSR without preceding LSL. --

    lsr_w(&code[0], 0, 0, 12);
    assert(run_helper_check(code, 4) == 0);

    // -- Interaction: LSL+LSR pattern; the LSL fold check doesn't fire
    //    because LSR isn't a shifted-register consumer. Only bsx flags.
    lsl_w(&code[0], 0, 1, 4);
    lsr_w(&code[4], 0, 0, 12);
    assert(run_helper_check(code, 8) == 1);
}

static void test_lsr_and_to_ubfx(void)
{
    uint8_t code[12];

    // -- Positive: LSR + AND with contiguous-low-bit mask -> UBFX. --

    // lsr w0, w1, #4 ; and w0, w0, #0xff -> ubfx w0, w1, #4, #8.
    lsr_w(&code[0], 0, 1, 4);
    and_w_lowmask(&code[4], 0, 0, 8);
    assert(run_helper_check(code, 8) == 1);

    // lsr w0, w1, #8 ; and w0, w0, #0xfffff -> ubfx w0, w1, #8, #20.
    lsr_w(&code[0], 0, 1, 8);
    and_w_lowmask(&code[4], 0, 0, 20);
    assert(run_helper_check(code, 8) == 1);

    // lsr x0, x1, #20 ; and x0, x0, #0xfffff (20 bits) -> ubfx x0, x1, #20, #20.
    lsr_x(&code[0], 0, 1, 20);
    and_x_lowmask(&code[4], 0, 0, 20);
    assert(run_helper_check(code, 8) == 1);

    // -- Positive: AND mask wider than the LSR-fillable bits.
    //    The UBFX width is capped at datasize - shift.

    // lsr w0, w1, #28 ; and w0, w0, #0xffff (16) > 32-28=4.
    // Suggested ubfx w0, w1, #28, #4.
    lsr_w(&code[0], 0, 1, 28);
    and_w_lowmask(&code[4], 0, 0, 16);
    assert(run_helper_check(code, 8) == 1);

    // -- Negative: non-contiguous-low mask (e.g., #0x6). --

    lsr_w(&code[0], 0, 1, 4);
    and_w_non_contig_lo(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: Rd mismatch on consumer. --

    // lsr w0, w1, #4 ; and w5, w0, #0xff -- consumer Rd != lra_rd.
    lsr_w(&code[0], 0, 1, 4);
    and_w_lowmask(&code[4], 5, 0, 8);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: Rn mismatch on consumer. --

    // lsr w0, w1, #4 ; and w0, w5, #0xff -- consumer Rn != lra_rd.
    lsr_w(&code[0], 0, 1, 4);
    and_w_lowmask(&code[4], 0, 5, 8);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: width mismatch (W LSR + X AND). --

    lsr_w(&code[0], 0, 1, 4);
    and_x_lowmask(&code[4], 0, 0, 8);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: intervening instruction expires lra_active. --

    lsr_w(&code[0], 0, 1, 4);
    movz_w(&code[4], 5, 1);
    and_w_lowmask(&code[8], 0, 0, 8);
    assert(run_helper_check(code, 12) == 0);

    // -- Negative: AND without preceding LSR. --

    and_w_lowmask(&code[0], 0, 0, 8);
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: LSR with no consumer. --

    lsr_w(&code[0], 0, 1, 4);
    assert(run_helper_check(code, 4) == 0);
}

static void test_mov_reg_self(void)
{
    uint8_t code[8];

    // -- Positive: MOV Xd, Xd is a literal no-op. --

    mov_x(&code[0], 0, 0);          // mov x0, x0
    assert(run_helper_check(code, 4) == 1);

    mov_x(&code[0], 5, 5);          // mov x5, x5
    assert(run_helper_check(code, 4) == 1);

    mov_x(&code[0], 30, 30);        // mov x30, x30
    assert(run_helper_check(code, 4) == 1);

    // -- Negative: MOV Xd, Xm with d != m -- not a no-op. --

    mov_x(&code[0], 0, 1);          // mov x0, x1
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: MOV X0, XZR -- Rm=31, decoder rejects (Rm != Rd). --

    mov_x(&code[0], 0, 31);         // mov x0, xzr
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: MOV XZR, XZR -- Rd=31 excluded (discarded result). --

    mov_x(&code[0], 31, 31);        // mov xzr, xzr
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: MOV Wd, Wd is NOT this check's pattern -- the W-form
    //    has the zero-extension side effect and is handled by
    //    check_redundant_zext when a preceding producer already zeroed
    //    bits 63..32. A lone MOV Wd, Wd should produce 0 findings: the
    //    W-form opens wzx as a producer, but no consumer follows. --

    mov_w_reg(&code[0], 0, 0);      // mov w0, w0 (alone)
    assert(run_helper_check(code, 4) == 0);

    // -- Two adjacent MOV Xd, Xd: each fires independently. --

    mov_x(&code[0], 0, 0);
    mov_x(&code[4], 1, 1);
    assert(run_helper_check(code, 8) == 2);
}

static void test_redundant_sext(void)
{
    uint8_t code[16];

    // -- Positive: sign-extending load + matching SXT* (same S, same W). --

    // ldrsb w0, [x1] ; sxtb w0, w0 -- S=8, W=32 on both sides.
    LDRSB_W(&code[0], 0, 1, 0);
    SXTB_W(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrsh w0, [x1] ; sxth w0, w0 -- S=16, W=32.
    LDRSH_W(&code[0], 0, 1, 0);
    SXTH_W(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrsb x0, [x1] ; sxtb x0, w0 -- S=8, W=64.
    LDRSB_X(&code[0], 0, 1, 0);
    SXTB_X(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrsh x0, [x1] ; sxth x0, w0 -- S=16, W=64.
    LDRSH_X(&code[0], 0, 1, 0);
    SXTH_X(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrsw x0, [x1] ; sxtw x0, w0 -- S=32, W=64.
    LDRSW_X(&code[0], 0, 1, 0);
    SXTW_X(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // -- Positive: S_p < S_c, same W. The producer's stricter
    //    sign-extension subsumes the consumer's wider one. --

    // ldrsb w0, [x1] ; sxth w0, w0 -- S_p=8 < S_c=16, W=32.
    LDRSB_W(&code[0], 0, 1, 0);
    SXTH_W(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrsb x0, [x1] ; sxth x0, w0 -- S_p=8 < S_c=16, W=64.
    LDRSB_X(&code[0], 0, 1, 0);
    SXTH_X(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrsh x0, [x1] ; sxtw x0, w0 -- S_p=16 < S_c=32, W=64.
    LDRSH_X(&code[0], 0, 1, 0);
    SXTW_X(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // -- Positive: SXT* producer paired with SXT* consumer. --

    // sxtb w0, w1 ; sxtb w0, w0 (same S, same W).
    SXTB_W(&code[0], 0, 1);
    SXTB_W(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // sxtb x0, w1 ; sxtb x0, w0 -- X-form chain.
    SXTB_X(&code[0], 0, 1);
    SXTB_X(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // -- Three adjacent SXT*: each consumer fires against the previous. --

    SXTB_W(&code[0], 0, 1);
    SXTB_W(&code[4], 0, 0);
    SXTB_W(&code[8], 0, 0);
    assert(run_helper_check(code, 12) == 2);

    // -- Negative: width mismatch. --

    // ldrsb w0, [x1] ; sxtb x0, w0 -- W=32 vs W=64.
    LDRSB_W(&code[0], 0, 1, 0);
    SXTB_X(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 0);

    // ldrsb x0, [x1] ; sxtb w0, w0 -- W=64 vs W=32.
    LDRSB_X(&code[0], 0, 1, 0);
    SXTB_W(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: S_p > S_c (producer wider, consumer narrower). --

    // ldrsh w0, [x1] ; sxtb w0, w0 -- S_p=16 > S_c=8.
    LDRSH_W(&code[0], 0, 1, 0);
    SXTB_W(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 0);

    // ldrsw x0, [x1] ; sxth x0, w0 -- S_p=32 > S_c=16.
    LDRSW_X(&code[0], 0, 1, 0);
    SXTH_X(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: zero-extending load is not a sign-ext producer. --

    // ldr w0, [x1] ; sxtb w0, w0 -- LDR W zero-extends, not sign-extends.
    LDR_W(&code[0], 0, 1, 0);
    SXTB_W(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: Rd mismatch on consumer. --

    LDRSB_W(&code[0], 0, 1, 0);
    SXTB_W(&code[4], 5, 0);     // consumer Rd != sxt_rd
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: Rn mismatch on consumer (reads a different reg). --

    LDRSB_W(&code[0], 0, 1, 0);
    SXTB_W(&code[4], 0, 5);     // consumer Rn != sxt_rd
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: intervening instruction expires sxt state. --

    LDRSB_W(&code[0], 0, 1, 0);
    movz_w(&code[4], 5, 1);
    SXTB_W(&code[8], 0, 0);
    assert(run_helper_check(code, 12) == 0);

    // -- Negative: lone SXTB with no preceding sign-ext producer. --

    SXTB_W(&code[0], 0, 0);
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: producer with Rt=31 (LDRSB Wzr). --

    LDRSB_W(&code[0], 31, 1, 0);
    SXTB_W(&code[4], 31, 31);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: SXTB Wzr, Wn (Rd=31 producer skipped). --

    SXTB_W(&code[0], 31, 1);
    SXTB_W(&code[4], 31, 31);
    assert(run_helper_check(code, 8) == 0);

    // -- Interaction: SXT producer also opens zext state, but a UBFM
    //    zero-ext consumer doesn't match SBFM and vice versa. --

    // ldrsb w0, [x1] ; uxtw x0, w0 -- zext (P=32, C=32) fires; sxt
    // does not (UXTW is UBFM, not SBFM).
    LDRSB_W(&code[0], 0, 1, 0);
    uxtw(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrsb x0, [x1] ; sxtb x0, w0 -- sxt fires; zext does not
    // (LDRSB X is not a W-form producer, so wzx not opened).
    LDRSB_X(&code[0], 0, 1, 0);
    SXTB_X(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // -- Two adjacent independent patterns: both flag. --

    LDRSB_W(&code[0], 0, 1, 0);
    SXTB_W(&code[4], 0, 0);
    LDRSH_W(&code[8], 2, 1, 0);
    SXTH_W(&code[12], 2, 2);
    assert(run_helper_check(code, 16) == 2);

    // -- ASR as a sign-extension producer. ASR Rd, Rn, #k yields
    //    S = datasize - k, W = datasize. --

    // asr w0, w1, #24 ; sxtb w0, w0 -- S=8, W=32 on both sides.
    asr_w(&code[0], 0, 1, 24);
    SXTB_W(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // asr w0, w1, #16 ; sxth w0, w0 -- S=16, W=32.
    asr_w(&code[0], 0, 1, 16);
    SXTH_W(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // asr x0, x1, #56 ; sxtb x0, w0 -- S=8, W=64.
    asr_x(&code[0], 0, 1, 56);
    SXTB_X(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // asr x0, x1, #48 ; sxth x0, w0 -- S=16, W=64.
    asr_x(&code[0], 0, 1, 48);
    SXTH_X(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // asr x0, x1, #32 ; sxtw x0, w0 -- S=32, W=64.
    asr_x(&code[0], 0, 1, 32);
    SXTW_X(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // -- Positive: ASR S_p < S_c. asr w0, w1, #25 ; sxtb w0, w0 --
    //    S_p=7 < S_c=8, redundant. --

    asr_w(&code[0], 0, 1, 25);
    SXTB_W(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // asr w0, w1, #24 ; sxth w0, w0 -- S_p=8 < S_c=16, redundant.
    asr_w(&code[0], 0, 1, 24);
    SXTH_W(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // -- Negative: ASR shift too small to cover the SXT width. --

    // asr w0, w1, #8 ; sxtb w0, w0 -- S_p=24 > S_c=8, not redundant.
    asr_w(&code[0], 0, 1, 8);
    SXTB_W(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 0);

    // asr w0, w1, #16 ; sxtb w0, w0 -- S_p=16 > S_c=8, not redundant.
    asr_w(&code[0], 0, 1, 16);
    SXTB_W(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: width mismatch with ASR producer. --

    // asr w0, w1, #24 ; sxtb x0, w0 -- W_p=32 vs W_c=64.
    asr_w(&code[0], 0, 1, 24);
    SXTB_X(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 0);

    // asr x0, x1, #56 ; sxtb w0, w0 -- W_p=64 vs W_c=32.
    asr_x(&code[0], 0, 1, 56);
    SXTB_W(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 0);

    // -- Positive: sign-extension dead because a following zero-ext
    //    consumer masks the sign-extended bits. Fires when C_c <= S_p
    //    (consumer clears at least the producer's sign-extended
    //    region). --

    // sxtb w0, w1 ; uxtb w0, w0 -- S=8, C=8: dead.
    SXTB_W(&code[0], 0, 1);
    uxtb_w(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // sxth w0, w1 ; uxtb w0, w0 -- S=16, C=8: dead.
    SXTH_W(&code[0], 0, 1);
    uxtb_w(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // sxth w0, w1 ; uxth w0, w0 -- S=16, C=16: dead.
    SXTH_W(&code[0], 0, 1);
    uxth_w(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // sxtw x0, w1 ; uxtw x0, w0 -- S=32, C=32: dead (X-form pair).
    SXTW_X(&code[0], 0, 1);
    uxtw(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // sxtb x0, w1 ; uxtb w0, w0 -- X-form producer (S=8, W=64) +
    // W-form consumer (C=8, W=32). W-form auto-zero of X[63:32] clears
    // the high half of the sign-ext; UXTB clears bits 31..8. Dead.
    SXTB_X(&code[0], 0, 1);
    uxtb_w(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrsb w0, [x1] ; uxtb w0, w0 -- dead (could be ldrb w0, [x1]).
    LDRSB_W(&code[0], 0, 1, 0);
    uxtb_w(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldrsw x0, [x1] ; uxtw x0, w0 -- dead (could be ldr w0, [x1]).
    LDRSW_X(&code[0], 0, 1, 0);
    uxtw(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // sxtb w0, w1 ; and w0, w0, #0xff -- dead (AND mask C=8 <= S=8).
    SXTB_W(&code[0], 0, 1);
    and_w_ff(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // sxtw x0, w1 ; mov w0, w0 -- dead (MOV W self C=32 == S=32,
    // and the W-form write clears X[63:32] including sign-ext bits).
    SXTW_X(&code[0], 0, 1);
    mov_w_reg(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // asr w0, w1, #24 ; uxtb w0, w0 -- ASR S=8, UXTB C=8: dead.
    asr_w(&code[0], 0, 1, 24);
    uxtb_w(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // -- Negative: C_c > S_p (sign-extension partially survives). --

    // sxth w0, w1 ; uxtw x0, w0 -- S=16, C=32. UXTW preserves
    // bits 31..16 = sign(bit 15). Sign-ext NOT dead (it actually
    // shows up in the result). But the existing zext check fires
    // (P=32 <= C=32, redundant UXTW). One finding from zext side.
    SXTH_W(&code[0], 0, 1);
    uxtw(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // sxth w0, w1 ; mov w0, w0 -- S=16, MOV W self C=32 > 16.
    // The existing zext check fires (P=32 <= C=32), not my new check.
    SXTH_W(&code[0], 0, 1);
    mov_w_reg(&code[4], 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // -- Negative: Rd mismatch / Rn mismatch on consumer. --

    SXTB_W(&code[0], 0, 1);
    uxtb_w(&code[4], 5, 0);   // consumer Rd != sxt_rd
    assert(run_helper_check(code, 8) == 0);

    SXTB_W(&code[0], 0, 1);
    uxtb_w(&code[4], 0, 5);   // consumer Rn != sxt_rd
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: intervening instruction expires sxt state. --

    SXTB_W(&code[0], 0, 1);
    movz_w(&code[4], 5, 1);
    uxtb_w(&code[8], 0, 0);
    assert(run_helper_check(code, 12) == 0);
}

static void test_redundant_cmp_after_s_variant(void)
{
    uint8_t code[24];

    // -- Positive cases: each fires BOTH the new redundant-CMP finding
    //    AND the existing CMP+B.cond -> CBZ finding, so expect 2. --

    // adds w0, w1, w2 ; cmp w0, #0 ; b.eq +8 ; ret.
    ADDS_W(&code[0], 0, 1, 2);
    cmp_w_imm(&code[4], 0, 0);
    b_cond(&code[8], 0, 8);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 2);

    // subs w0, w1, w2 ; cmp w0, #0 ; b.ne +8 ; ret.
    SUBS_W(&code[0], 0, 1, 2);
    cmp_w_imm(&code[4], 0, 0);
    b_cond(&code[8], 1, 8);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 2);

    // ands w0, w1, w2 ; cmp w0, #0 ; b.eq +8 ; ret.
    ANDS_W(&code[0], 0, 1, 2);
    cmp_w_imm(&code[4], 0, 0);
    b_cond(&code[8], 0, 8);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 2);

    // bics w0, w1, w2 ; cmp w0, #0 ; b.eq +8 ; ret.
    BICS_W(&code[0], 0, 1, 2);
    cmp_w_imm(&code[4], 0, 0);
    b_cond(&code[8], 0, 8);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 2);

    // X-form: subs x5, x1, x2 ; cmp x5, #0 ; b.eq +8 ; ret.
    SUBS_X(&code[0], 5, 1, 2);
    cmp_x_imm(&code[4], 5, 0);
    b_cond(&code[8], 0, 8);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 2);

    // TST form: adds w0, w1, w2 ; tst w0, w0 ; b.eq +8 ; ret.
    ADDS_W(&code[0], 0, 1, 2);
    tst_w_reg(&code[4], 0, 0);
    b_cond(&code[8], 0, 8);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 2);

    // CMP-with-XZR form: adds w0, w1, w2 ; cmp w0, wzr ; b.eq +8 ; ret.
    ADDS_W(&code[0], 0, 1, 2);
    cmp_w_reg(&code[4], 0, 31);
    b_cond(&code[8], 0, 8);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 2);

    // -- Negative: non-S-variant ADD; only existing check fires. --

    // add w0, w1, w2 (no flag set) ; cmp w0, #0 ; b.eq ; ret.
    ADD_W(&code[0], 0, 1, 2);
    cmp_w_imm(&code[4], 0, 0);
    b_cond(&code[8], 0, 8);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 1);

    // -- Negative: CMP of a different register. --

    // adds w0, w1, w2 ; cmp w5, #0 ; b.eq ; ret -- existing fires for
    // CMP w5 + B.EQ; mine doesn't (Rn != sv_rd).
    ADDS_W(&code[0], 0, 1, 2);
    cmp_w_imm(&code[4], 5, 0);
    b_cond(&code[8], 0, 8);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 1);

    // -- Negative: intervening instruction expires sv_active. --

    // adds w0, w1, w2 ; movz w5, #1 ; cmp w0, #0 ; b.eq ; ret -- the
    // intervening MOV breaks the sv chain. Existing CMP+B.EQ still
    // fires (1 finding).
    ADDS_W(&code[0], 0, 1, 2);
    movz_w(&code[4], 5, 1);
    cmp_w_imm(&code[8], 0, 0);
    b_cond(&code[12], 0, 8);
    ret_(&code[16]);
    assert(run_helper_check(code, 20) == 1);

    // -- Negative for redundant-CMP, but positive for sign-bit fold:
    //    adds w0, w1, w2 ; cmp w0, #0 ; b.lt ; ret. The redundant-CMP
    //    check requires B.EQ/B.NE and doesn't fire here (the CMP
    //    legitimately clears V so B.LT tests sign, not signed-overflow).
    //    The CMP-zero+B.LT -> TBNZ-on-sign-bit check DOES fire (the
    //    rewrite is sound: ADDS already set bit 31 = sign of result). --
    ADDS_W(&code[0], 0, 1, 2);
    cmp_w_imm(&code[4], 0, 0);
    b_cond(&code[8], 11 /* LT */, 8);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 1);

    // -- Negative: downstream reads NZCV (adcs after B.eq) -- both
    //    pendings suppressed by liveness scan. --

    // adds w0, w1, w2 ; cmp w0, #0 ; b.eq ; adcs w5, w6, w7.
    ADDS_W(&code[0], 0, 1, 2);
    cmp_w_imm(&code[4], 0, 0);
    b_cond(&code[8], 0, 8);
    adcs_w(&code[12], 5, 6, 7);
    ret_(&code[16]);
    assert(run_helper_check(code, 20) == 0);

    // -- Negative: S-variant writes to XZR (CMN/CMP/TST alias);
    //    sv_active not opened. --

    // adds wzr, w1, w2 ; cmp w0, #0 ; b.eq ; ret -- the first instr
    // is really CMN-like (Rd=31); existing CMP+B.EQ still fires.
    ADDS_W(&code[0], 31, 1, 2);
    cmp_w_imm(&code[4], 0, 0);
    b_cond(&code[8], 0, 8);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 1);

    // -- Negative: width mismatch (W S-variant, X CMP). --

    // adds w0, w1, w2 ; cmp x0, #0 ; b.eq -- mine doesn't fire because
    // CMP's sf differs from ADDS's sf. Existing CMP+B.EQ on X still
    // fires.
    ADDS_W(&code[0], 0, 1, 2);
    cmp_x_imm(&code[4], 0, 0);
    b_cond(&code[8], 0, 8);
    ret_(&code[12]);
    assert(run_helper_check(code, 16) == 1);

    // -- Negative: lone S-variant; CMP without B.cond; etc. --

    // adds w0, w1, w2 ; ret -- nothing follows. No finding from either.
    ADDS_W(&code[0], 0, 1, 2);
    ret_(&code[4]);
    assert(run_helper_check(code, 8) == 0);

    // adds w0, w1, w2 ; cmp w0, #0 ; ret -- CMP not followed by
    // B.EQ/B.NE; sv_cmp_active expires; neither check fires.
    ADDS_W(&code[0], 0, 1, 2);
    cmp_w_imm(&code[4], 0, 0);
    ret_(&code[8]);
    assert(run_helper_check(code, 12) == 0);
}

static void test_add_sub_zero(void)
{
    uint8_t code[12];

    // -- Positive: Rd != Rn, equivalent to MOV. --

    // add w0, w1, #0
    ADD_W_IMM(&code[0], 0, 1, 0);
    assert(run_helper_check(code, 4) == 1);

    // sub w0, w1, #0
    SUB_W_IMM(&code[0], 0, 1, 0);
    assert(run_helper_check(code, 4) == 1);

    // add x5, x6, #0 -- X-form.
    ADD_X_IMM(&code[0], 5, 6, 0);
    assert(run_helper_check(code, 4) == 1);

    // sub x5, x6, #0
    SUB_X_IMM(&code[0], 5, 6, 0);
    assert(run_helper_check(code, 4) == 1);

    // -- Positive: Rd == Rn, completely no-op. --

    // add w0, w0, #0
    ADD_W_IMM(&code[0], 0, 0, 0);
    assert(run_helper_check(code, 4) == 1);

    // sub x3, x3, #0
    SUB_X_IMM(&code[0], 3, 3, 0);
    assert(run_helper_check(code, 4) == 1);

    // -- Negative: imm != 0. --

    // add w0, w1, #1
    ADD_W_IMM(&code[0], 0, 1, 1);
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: Rd = 31 (SP encoding -- MOV-to-SP alias). --

    // add sp, x1, #0
    ADD_X_IMM(&code[0], 31, 1, 0);
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: Rn = 31 (SP encoding -- MOV-from-SP alias). --

    // add x0, sp, #0
    ADD_X_IMM(&code[0], 0, 31, 0);
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: ADDS (S=1, flag-setting) -- intentional zero-test
    //    that also writes Rd. --

    // adds w0, w1, #0
    subs_w_imm(&code[0], 0, 1, 0);   // SUBS form; same logic for ADDS
    // (We don't have an adds_w_imm helper; SUBS form proves the
    // negative case since both S-variants of imm have S=1 set.)
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: shifted-register ADD (not the immediate form). --

    // add w0, w1, w2 -- not flagged by this check.
    ADD_W(&code[0], 0, 1, 2);
    assert(run_helper_check(code, 4) == 0);

    // -- Two adjacent: each fires independently. --

    ADD_W_IMM(&code[0], 0, 1, 0);
    SUB_W_IMM(&code[4], 2, 3, 0);
    assert(run_helper_check(code, 8) == 2);

    // -- Negative: ADRP+ADD #0 page-relative addressing pair (linker
    //    resolved offset to 0); not actionable without re-linking. --

    // adrp x8, 1 ; add x8, x8, #0
    adrp_x(&code[0], 8, 1);
    ADD_X_IMM(&code[4], 8, 8, 0);
    assert(run_helper_check(code, 8) == 0);

    // -- Positive: ADRP+ADD #0 with Rd != Rn -- not the canonical
    //    addressing pair, so still flagged. --

    // adrp x8, 1 ; add x9, x8, #0
    adrp_x(&code[0], 8, 1);
    ADD_X_IMM(&code[4], 9, 8, 0);
    assert(run_helper_check(code, 8) == 1);

    // -- Positive: ADRP+(intervening MOV)+ADD #0 -- strict adjacency
    //    means the ADD is no longer protected by the ADRP. --

    adrp_x(&code[0], 8, 1);
    movz_x(&code[4], 5, 1, 0);   // intervening
    ADD_X_IMM(&code[8], 8, 8, 0);
    assert(run_helper_check(code, 12) == 1);
}

static void test_self_op(void)
{
    uint8_t code[8];

    // -- Positive: identity AND/ORR (Rd != Rn). --

    // and w0, w1, w1 -> mov w0, w1
    AND_W(&code[0], 0, 1, 1);
    assert(run_helper_check(code, 4) == 1);

    // orr w0, w1, w1 -> mov w0, w1
    ORR_W(&code[0], 0, 1, 1);
    assert(run_helper_check(code, 4) == 1);

    // and x5, x6, x6 -> mov x5, x6 (X-form)
    AND_X(&code[0], 5, 6, 6);
    assert(run_helper_check(code, 4) == 1);

    // orr x5, x6, x6
    ORR_X(&code[0], 5, 6, 6);
    assert(run_helper_check(code, 4) == 1);

    // -- Positive: zero result EOR/SUB. --

    // eor w0, w1, w1 -> mov w0, wzr
    EOR_W(&code[0], 0, 1, 1);
    assert(run_helper_check(code, 4) == 1);

    // sub w0, w1, w1 -> mov w0, wzr
    SUB_W(&code[0], 0, 1, 1);
    assert(run_helper_check(code, 4) == 1);

    // eor x5, x6, x6
    EOR_X(&code[0], 5, 6, 6);
    assert(run_helper_check(code, 4) == 1);

    // sub x5, x6, x6
    SUB_X(&code[0], 5, 6, 6);
    assert(run_helper_check(code, 4) == 1);

    // -- Positive: Rd == Rn case still fires. --

    // and w0, w0, w0 (X-form would be a true no-op; W-form also zeros
    // X[63:32] but the canonical idiom is MOV W0, W0).
    AND_W(&code[0], 0, 0, 0);
    assert(run_helper_check(code, 4) == 1);

    // -- Negative: ANDS (flag-setting, intentional). --

    ANDS_W(&code[0], 0, 1, 1);
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: SUBS (flag-setting). --

    subs_w_imm(&code[0], 0, 1, 0);   // SUBS Wd, Wn, #0 (different
    // encoding from shifted-reg SUBS, but verifies that S-variant
    // SUBs aren't flagged by check_self_op).
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: Rn != Rm (not a self-op). --

    AND_W(&code[0], 0, 1, 2);
    assert(run_helper_check(code, 4) == 0);

    // -- Positive: N=1 logical self-ops. --

    // bic w0, w1, w1 -> mov w0, wzr (Rs AND NOT Rs = 0)
    BIC_W(&code[0], 0, 1, 1);
    assert(run_helper_check(code, 4) == 1);

    // orn w0, w1, w1 -> mov w0, #-1 (Rs OR NOT Rs = all-ones)
    ORN_W(&code[0], 0, 1, 1);
    assert(run_helper_check(code, 4) == 1);

    // eon w0, w1, w1 -> mov w0, #-1 (Rs XOR NOT Rs = all-ones)
    EON_W(&code[0], 0, 1, 1);
    assert(run_helper_check(code, 4) == 1);

    // bic x5, x6, x6 (X-form zero)
    BIC_X(&code[0], 5, 6, 6);
    assert(run_helper_check(code, 4) == 1);

    // orn x5, x6, x6 (X-form -1)
    ORN_X(&code[0], 5, 6, 6);
    assert(run_helper_check(code, 4) == 1);

    // -- Negative: BICS (N=1, S=1, flag-set is intentional). --

    BICS_W(&code[0], 0, 1, 1);
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: Rd = 31 (result discarded). --

    AND_W(&code[0], 31, 1, 1);
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: Rn = 31 (ZR operand, not a real self-op). --

    AND_W(&code[0], 0, 31, 31);
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: ADD Rd, Rs, Rs -- not a self-op identity
    //    (doubles Rs). --

    ADD_W(&code[0], 0, 1, 1);
    assert(run_helper_check(code, 4) == 0);

    // -- Two adjacent: each fires independently. --

    AND_W(&code[0], 0, 1, 1);
    EOR_W(&code[4], 2, 3, 3);
    assert(run_helper_check(code, 8) == 2);
}

static void test_csel_self(void)
{
    uint8_t code[8];

    // -- Positive: CSEL Rd, Rn, Rn, cond -- cond irrelevant. --

    // csel w0, w1, w1, eq -> mov w0, w1
    csel_w(&code[0], 0, 1, 1, 0 /* EQ */);
    assert(run_helper_check(code, 4) == 1);

    // csel w0, w1, w1, lt
    csel_w(&code[0], 0, 1, 1, 11 /* LT */);
    assert(run_helper_check(code, 4) == 1);

    // csel x5, x6, x6, ne (X-form)
    csel_x(&code[0], 5, 6, 6, 1 /* NE */);
    assert(run_helper_check(code, 4) == 1);

    // -- Negative: CSEL with Rn != Rm. --

    // csel w0, w1, w2, eq -- distinct operands, genuine select.
    csel_w(&code[0], 0, 1, 2, 0);
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: CSINC with same operands -- not an identity
    //    (else = Rn + 1; this is CINC alias). --

    csinc_w(&code[0], 0, 1, 1, 0);
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: Rd = 31 (result discarded). --

    csel_w(&code[0], 31, 1, 1, 0);
    assert(run_helper_check(code, 4) == 0);

    // -- Negative: Rn = 31 (CSEL Rd, XZR, XZR, cond -- writes 0
    //    always; the rewrite would be MOV Rd, XZR, but we follow
    //    check_self_op's convention of excluding ZR-source). --

    csel_w(&code[0], 0, 31, 31, 0);
    assert(run_helper_check(code, 4) == 0);

    // -- Two adjacent CSEL same-operand: each fires. --

    csel_w(&code[0], 0, 1, 1, 0);
    csel_w(&code[4], 2, 3, 3, 1);
    assert(run_helper_check(code, 8) == 2);
}

static void test_bfxil_synth(void)
{
    uint8_t code[16];

    // -- Positive: canonical order clear -> isolate -> ORR. --

    // and w0, w0, #~0xff ; and w5, w1, #0xff ; orr w0, w0, w5
    // -> bfxil w0, w1, #0, #8
    and_w_highmask(&code[0], 0, 0, 8);
    and_w_lowmask(&code[4], 5, 1, 8);
    ORR_W(&code[8], 0, 0, 5);
    assert(run_helper_check(code, 12) == 1);

    // -- Positive: reverse order (isolate first). --

    // and w5, w1, #0xff ; and w0, w0, #~0xff ; orr w0, w0, w5
    and_w_lowmask(&code[0], 5, 1, 8);
    and_w_highmask(&code[4], 0, 0, 8);
    ORR_W(&code[8], 0, 0, 5);
    assert(run_helper_check(code, 12) == 1);

    // -- Positive: ORR with commuted operands (Rd, Rt, Rd). --

    and_w_highmask(&code[0], 0, 0, 8);
    and_w_lowmask(&code[4], 5, 1, 8);
    ORR_W(&code[8], 0, 5, 0);   // commuted
    assert(run_helper_check(code, 12) == 1);

    // -- Positive: X-form. --

    and_x_highmask(&code[0], 0, 0, 16);
    and_x_lowmask(&code[4], 5, 1, 16);
    ORR_X(&code[8], 0, 0, 5);
    assert(run_helper_check(code, 12) == 1);

    // -- Negative: width mismatch. --

    and_w_highmask(&code[0], 0, 0, 8);
    and_w_lowmask(&code[4], 5, 1, 16);   // different width
    ORR_W(&code[8], 0, 0, 5);
    assert(run_helper_check(code, 12) == 0);

    // -- Negative: ORR Rd doesn't match clear's Rd. --

    and_w_highmask(&code[0], 0, 0, 8);
    and_w_lowmask(&code[4], 5, 1, 8);
    ORR_W(&code[8], 7, 0, 5);   // Rd=7 doesn't match clear's Rd=0
    assert(run_helper_check(code, 12) == 0);

    // -- Negative for BFXIL: aliasing -- Rt == clear.Rd. The ORR
    //    that closes the (broken) BFXIL pattern must be ORR W0, W0,
    //    W0 because both clear.Rd and isolate.Rt are W0; that ORR
    //    is itself a self-op identity and fires check_self_op (1
    //    finding). The BFXIL check correctly rejects via alias_ok,
    //    so the only finding is the self-op one. --
    and_w_highmask(&code[0], 0, 0, 8);
    and_w_lowmask(&code[4], 0, 1, 8);   // Rt == clear.Rd
    ORR_W(&code[8], 0, 0, 0);
    assert(run_helper_check(code, 12) == 1);

    // -- Negative: aliasing -- Rt == Rs (isolate modifies source). --

    and_w_highmask(&code[0], 0, 0, 8);
    and_w_lowmask(&code[4], 1, 1, 8);   // Rt == Rs == w1
    ORR_W(&code[8], 0, 0, 1);
    assert(run_helper_check(code, 12) == 0);

    // -- Negative: aliasing -- Rs == clear.Rd (degenerate). --

    and_w_highmask(&code[0], 0, 0, 8);
    and_w_lowmask(&code[4], 5, 0, 8);   // Rs == clear.Rd
    ORR_W(&code[8], 0, 0, 5);
    assert(run_helper_check(code, 12) == 0);

    // -- Negative: clear is not in-place (Rd != Rn). --

    // and w7, w0, #~0xff -- "clear" but writes to w7, not w0. Not
    // the canonical clear-Rd-in-place pattern.
    uint8_t clear_not_inplace[4];
    {
        unsigned imms = 31u - 8u, immr = 32u - 8u;
        uint32_t op = 0x12000000u | (immr << 16) | (imms << 10)
            | (0u << 5) | 7u;   // Rn=0, Rd=7
        clear_not_inplace[0] = op & 0xff;
        clear_not_inplace[1] = (op >> 8) & 0xff;
        clear_not_inplace[2] = (op >> 16) & 0xff;
        clear_not_inplace[3] = (op >> 24) & 0xff;
    }
    memcpy(&code[0], clear_not_inplace, 4);
    and_w_lowmask(&code[4], 5, 1, 8);
    ORR_W(&code[8], 7, 7, 5);
    assert(run_helper_check(code, 12) == 0);

    // -- Negative: intervening instruction (strict adjacency). --

    and_w_highmask(&code[0], 0, 0, 8);
    movz_w(&code[4], 6, 0x42);
    and_w_lowmask(&code[8], 5, 1, 8);
    ORR_W(&code[12], 0, 0, 5);
    assert(run_helper_check(code, 16) == 0);

    // -- Negative: ORR alone (no preceding ANDs). --

    ORR_W(&code[0], 0, 0, 5);
    assert(run_helper_check(code, 4) == 0);
}

static void test_ldp_stp_coalesce(void)
{
    uint8_t code[24];

    // -- Positive: adjacent loads (W-form). --

    // ldr w0, [x2, #0] ; ldr w1, [x2, #4] -> ldp w0, w1, [x2, #0]
    LDR_W(&code[0], 0, 2, 0);
    LDR_W(&code[4], 1, 2, 1);
    assert(run_helper_check(code, 8) == 1);

    // ldr w0, [x2, #4] ; ldr w1, [x2, #8] -> ldp at byte 4.
    LDR_W(&code[0], 0, 2, 1);
    LDR_W(&code[4], 1, 2, 2);
    assert(run_helper_check(code, 8) == 1);

    // -- Positive: adjacent loads (X-form). --

    // ldr x0, [x2, #0] ; ldr x1, [x2, #8] -> ldp x0, x1, [x2, #0]
    LDR_X(&code[0], 0, 2, 0);
    LDR_X(&code[4], 1, 2, 1);
    assert(run_helper_check(code, 8) == 1);

    // -- Positive: adjacent stores. --

    // str w0, [x2, #0] ; str w1, [x2, #4] -> stp w0, w1, [x2, #0]
    STR_W(&code[0], 0, 2, 0);
    STR_W(&code[4], 1, 2, 1);
    assert(run_helper_check(code, 8) == 1);

    // str x0, [x2, #16] ; str x1, [x2, #24] -> stp x0, x1, [x2, #16]
    STR_X(&code[0], 0, 2, 2);
    STR_X(&code[4], 1, 2, 3);
    assert(run_helper_check(code, 8) == 1);

    // -- Positive: store with first Rt == Rn is OK (no aliasing
    //    concern for stores). --

    STR_W(&code[0], 2, 2, 0);   // STR W2, [X2, #0]
    STR_W(&code[4], 1, 2, 1);
    assert(run_helper_check(code, 8) == 1);

    // -- Positive: 4 consecutive LDRs become 2 LDPs (non-overlapping). --

    LDR_W(&code[0], 0, 2, 0);
    LDR_W(&code[4], 1, 2, 1);
    LDR_W(&code[8], 3, 2, 2);
    LDR_W(&code[12], 4, 2, 3);
    assert(run_helper_check(code, 16) == 2);

    // -- Positive: LDR at the highest in-range offset (imm12 = 63
    //    for W-form -> byte 252). --

    LDR_W(&code[0], 0, 2, 63);
    LDR_W(&code[4], 1, 2, 64);
    assert(run_helper_check(code, 8) == 1);

    // -- Negative: first imm12 > 63 (out of LDP imm7 range). --

    LDR_W(&code[0], 0, 2, 64);
    LDR_W(&code[4], 1, 2, 65);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: different base register. --

    LDR_W(&code[0], 0, 2, 0);
    LDR_W(&code[4], 1, 3, 1);   // Rn = x3, not x2
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: non-adjacent offsets. --

    LDR_W(&code[0], 0, 2, 0);
    LDR_W(&code[4], 1, 2, 2);   // skips imm12=1
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: mixed W and X (size mismatch). --

    LDR_W(&code[0], 0, 2, 0);
    LDR_X(&code[4], 1, 2, 1);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: load + store (direction mismatch). --

    LDR_W(&code[0], 0, 2, 0);
    STR_W(&code[4], 1, 2, 1);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: same Rt for both LDRs (LDP Rt1 != Rt2 required). --

    LDR_W(&code[0], 0, 2, 0);
    LDR_W(&code[4], 0, 2, 1);   // Rt2 == Rt1 == w0
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: load with first Rt == Rn (aliasing). --

    LDR_X(&code[0], 2, 2, 0);   // first LDR clobbers base x2
    LDR_X(&code[4], 1, 2, 1);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: intervening instruction (strict adjacency). --

    LDR_W(&code[0], 0, 2, 0);
    movz_w(&code[4], 5, 1);
    LDR_W(&code[8], 1, 2, 1);
    assert(run_helper_check(code, 12) == 0);

    // -- Negative: lone LDR. --

    LDR_W(&code[0], 0, 2, 0);
    assert(run_helper_check(code, 4) == 0);

    // -- Positive: adjacent LDRSWs become LDPSW. --

    // ldrsw x0, [x2, #0] ; ldrsw x1, [x2, #4] -> ldpsw x0, x1, [x2, #0]
    LDRSW_X(&code[0], 0, 2, 0);
    LDRSW_X(&code[4], 1, 2, 1);
    assert(run_helper_check(code, 8) == 1);

    // -- Positive: LDPSW at the highest in-range offset (imm12 = 63
    //    for word transfer -> byte 252). --

    LDRSW_X(&code[0], 0, 2, 63);
    LDRSW_X(&code[4], 1, 2, 64);
    assert(run_helper_check(code, 8) == 1);

    // -- Negative: first LDRSW imm12 > 63. --

    LDRSW_X(&code[0], 0, 2, 64);
    LDRSW_X(&code[4], 1, 2, 65);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: kind mismatch -- LDR (zext) does not pair with
    //    LDRSW (sext). --

    LDR_W(&code[0], 0, 2, 0);
    LDRSW_X(&code[4], 1, 2, 1);
    assert(run_helper_check(code, 8) == 0);

    LDRSW_X(&code[0], 0, 2, 0);
    LDR_W(&code[4], 1, 2, 1);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: same Rt for both LDRSWs. --

    LDRSW_X(&code[0], 0, 2, 0);
    LDRSW_X(&code[4], 0, 2, 1);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: LDRSW load aliasing (first Rt == Rn). --

    LDRSW_X(&code[0], 2, 2, 0);   // first LDRSW clobbers base x2
    LDRSW_X(&code[4], 1, 2, 1);
    assert(run_helper_check(code, 8) == 0);

    // -- Positive: reverse-order LDRs (higher offset first) fold
    //    into LDP with swapped Rt order. --

    // ldr w1, [x2, #4] ; ldr w0, [x2, #0] -> ldp w0, w1, [x2, #0]
    LDR_W(&code[0], 1, 2, 1);
    LDR_W(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // ldr x1, [x2, #8] ; ldr x0, [x2, #0] -> ldp x0, x1, [x2, #0]
    LDR_X(&code[0], 1, 2, 1);
    LDR_X(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // -- Positive: reverse-order STRs. --

    // str w1, [x2, #4] ; str w0, [x2, #0] -> stp w0, w1, [x2, #0]
    STR_W(&code[0], 1, 2, 1);
    STR_W(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // -- Positive: reverse-order LDRSWs fold into LDPSW. --

    // ldrsw x1, [x2, #4] ; ldrsw x0, [x2, #0] -> ldpsw x0, x1, [x2, #0]
    LDRSW_X(&code[0], 1, 2, 1);
    LDRSW_X(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // -- Positive: reverse-order at boundary (lower imm12 = 63). --

    // ldr w1, [x2, #256] ; ldr w0, [x2, #252] -> ldp at byte 252
    LDR_W(&code[0], 1, 2, 64);
    LDR_W(&code[4], 0, 2, 63);
    assert(run_helper_check(code, 8) == 1);

    // -- Negative: reverse-order with lower imm12 = 64 (out of imm7
    //    range). The HIGHER offset would be encodable, but the LDP
    //    uses the LOWER address as the base + imm7. --

    LDR_W(&code[0], 1, 2, 65);
    LDR_W(&code[4], 0, 2, 64);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: reverse-order load aliasing -- pending (first in
    //    source order, at higher offset) Rt == Rn clobbers base
    //    before second LDR runs. --

    LDR_X(&code[0], 2, 2, 1);   // first LDR clobbers base x2
    LDR_X(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // -- Negative: reverse-order with same Rt. --

    LDR_W(&code[0], 0, 2, 1);
    LDR_W(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // -- Positive: reverse-order store where second STR's Rt == Rn
    //    is fine (stores don't have the aliasing concern). --

    STR_W(&code[0], 1, 2, 1);
    STR_W(&code[4], 2, 2, 0);   // second STR uses Rt = x2 (the base)
    assert(run_helper_check(code, 8) == 1);
}

// MUL Wd, Wn, Wm encoding (MADD with Ra=11111). Base 0x1B007C00.
static void mul_w(uint8_t out[4], unsigned rd, unsigned rn, unsigned rm)
{
    uint32_t op = 0x1B007C00u
        | ((rm & 0x1Fu) << 16)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// MUL Xd, Xn, Xm encoding. Base 0x9B007C00.
static void mul_x(uint8_t out[4], unsigned rd, unsigned rn, unsigned rm)
{
    uint32_t op = 0x9B007C00u
        | ((rm & 0x1Fu) << 16)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// MADD Xd, Xn, Xm, Xa with explicit Xa != XZR. Base 0x9B000000.
static void madd_x(uint8_t out[4], unsigned rd, unsigned rn,
                   unsigned rm, unsigned ra)
{
    uint32_t op = 0x9B000000u
        | ((rm & 0x1Fu) << 16)
        | ((ra & 0x1Fu) << 10)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

static void test_mul_strength_reduce(void)
{
    uint8_t code[16];

    // movz x0, #8 ; mul x3, x2, x0  -> lsl x3, x2, #3  (power of 2).
    movz_x(&code[0], 0, 8, 0);
    mul_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // movz x0, #8 ; mul x3, x0, x2  -> lsl x3, x2, #3  (Rn == mov_rd).
    movz_x(&code[0], 0, 8, 0);
    mul_x(&code[4], 3, 0, 2);
    assert(run_helper_check(code, 8) == 1);

    // W form: movz w0, #4 ; mul w3, w2, w0  -> lsl w3, w2, #2.
    movz_w(&code[0], 0, 4);
    mul_w(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // 2^N + 1: movz x0, #3 ; mul x3, x2, x0  -> add x3, x2, x2, lsl #1.
    movz_x(&code[0], 0, 3, 0);
    mul_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // 2^N + 1: movz x0, #5 ; mul x3, x2, x0  -> add x3, x2, x2, lsl #2.
    movz_x(&code[0], 0, 5, 0);
    mul_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // 2^N + 1: movz x0, #9 ; mul x3, x2, x0  -> add x3, x2, x2, lsl #3.
    movz_x(&code[0], 0, 9, 0);
    mul_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // Large power-of-2: movz x0, #1, lsl #32 ; mul x3, x2, x0
    //                              -> lsl x3, x2, #32.
    movz_x(&code[0], 0, 1, 2);
    mul_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // 2^16 + 1: movz x0, #1, lsl #16 ; movk x0, #1 ; mul x3, x2, x0
    //                              -> add x3, x2, x2, lsl #16.
    // 0x10001 is not a bitmask immediate, so check_movz_movk_bitmask
    // produces no finding; only the MUL strength reduction fires.
    movz_x(&code[0], 0, 1, 1);
    movk_x(&code[4], 0, 1, 0);
    mul_x(&code[8], 3, 2, 0);
    assert(run_helper_check(code, 12) == 1);

    // Both operands from MOV (Rn == Rm == mov_rd): valid LSL rewrite.
    // movz x0, #8 ; mul x3, x0, x0  -> lsl x3, x0, #3
    // (semantically: x3 = 64; rewrite recomputes x0 << 3 = 64).
    movz_x(&code[0], 0, 8, 0);
    mul_x(&code[4], 3, 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // Negative: 2^N - 1 case (7) is intentionally not folded.
    movz_x(&code[0], 0, 7, 0);
    mul_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: arbitrary non-pow2 / non-(2^N+1) constant.
    movz_x(&code[0], 0, 10, 0);
    mul_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: identity (C == 1).
    movz_x(&code[0], 0, 1, 0);
    mul_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: zero (C == 0).
    movz_x(&code[0], 0, 0, 0);
    mul_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: width mismatch -- 64-bit MOV, 32-bit MUL.
    movz_x(&code[0], 0, 8, 0);
    mul_w(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: width mismatch -- 32-bit MOV, 64-bit MUL.
    movz_w(&code[0], 0, 8);
    mul_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: MUL does not read the MOV destination.
    movz_x(&code[0], 0, 8, 0);
    mul_x(&code[4], 3, 2, 1);
    assert(run_helper_check(code, 8) == 0);

    // Negative: an intervening non-MOV closes the chain.
    movz_x(&code[0], 0, 8, 0);
    ADD_X(&code[4], 5, 5, 6);  // arbitrary unrelated insn
    mul_x(&code[8], 3, 2, 0);
    assert(run_helper_check(code, 12) == 0);

    // Negative: MUL with Rd = XZR discards the result.
    movz_x(&code[0], 0, 8, 0);
    mul_x(&code[4], 31, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: MADD with explicit Ra != XZR (not the MUL alias).
    movz_x(&code[0], 0, 8, 0);
    madd_x(&code[4], 3, 2, 0, 4);  // Ra = X4
    assert(run_helper_check(code, 8) == 0);

    // Bare MUL with no preceding MOV: no finding.
    mul_x(&code[0], 3, 2, 0);
    assert(run_helper_check(code, 4) == 0);
}

// MNEG Xd, Xn, Xm encoding (MSUB with Ra=11111). Base 0x9B00FC00.
static void mneg_x(uint8_t out[4], unsigned rd, unsigned rn, unsigned rm)
{
    uint32_t op = 0x9B00FC00u
        | ((rm & 0x1Fu) << 16)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// MNEG Wd, Wn, Wm. Base 0x1B00FC00.
static void mneg_w(uint8_t out[4], unsigned rd, unsigned rn, unsigned rm)
{
    uint32_t op = 0x1B00FC00u
        | ((rm & 0x1Fu) << 16)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// MSUB Xd, Xn, Xm, Xa with explicit Xa != XZR. Base 0x9B008000.
static void msub_x(uint8_t out[4], unsigned rd, unsigned rn,
                   unsigned rm, unsigned ra)
{
    uint32_t op = 0x9B008000u
        | ((rm & 0x1Fu) << 16)
        | ((ra & 0x1Fu) << 10)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

static void test_mneg_strength_reduce(void)
{
    uint8_t code[16];

    // C = 1: movz x0, #1 ; mneg x3, x2, x0  -> neg x3, x2.
    movz_x(&code[0], 0, 1, 0);
    mneg_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // C = 2^N (power of 2): movz x0, #8 ; mneg x3, x2, x0
    //                              -> neg x3, x2, lsl #3.
    movz_x(&code[0], 0, 8, 0);
    mneg_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // Commutativity (Rn == mov_rd): movz x0, #2 ; mneg x3, x0, x2
    //                              -> neg x3, x2, lsl #1.
    movz_x(&code[0], 0, 2, 0);
    mneg_x(&code[4], 3, 0, 2);
    assert(run_helper_check(code, 8) == 1);

    // W form: movz w0, #4 ; mneg w3, w2, w0  -> neg w3, w2, lsl #2.
    movz_w(&code[0], 0, 4);
    mneg_w(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // C = 2^N - 1: movz x0, #3 ; mneg x3, x2, x0
    //                              -> sub x3, x2, x2, lsl #2.
    movz_x(&code[0], 0, 3, 0);
    mneg_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // C = 2^N - 1: movz x0, #7 ; mneg x3, x2, x0
    //                              -> sub x3, x2, x2, lsl #3.
    movz_x(&code[0], 0, 7, 0);
    mneg_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // C = 2^N - 1: movz x0, #15 ; mneg x3, x2, x0
    //                              -> sub x3, x2, x2, lsl #4.
    movz_x(&code[0], 0, 15, 0);
    mneg_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // Large power-of-2 via shifted MOVZ: 2^32.
    movz_x(&code[0], 0, 1, 2);
    mneg_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // Negative: 2^N + 1 (5) is intentionally not folded for MNEG.
    movz_x(&code[0], 0, 5, 0);
    mneg_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: 2^N + 1 (9).
    movz_x(&code[0], 0, 9, 0);
    mneg_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: arbitrary constant (10).
    movz_x(&code[0], 0, 10, 0);
    mneg_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: C = 0.
    movz_x(&code[0], 0, 0, 0);
    mneg_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: width mismatch.
    movz_w(&code[0], 0, 8);
    mneg_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: MNEG does not read the MOV destination.
    movz_x(&code[0], 0, 8, 0);
    mneg_x(&code[4], 3, 2, 1);
    assert(run_helper_check(code, 8) == 0);

    // Negative: intervening unrelated instruction closes the chain.
    movz_x(&code[0], 0, 8, 0);
    ADD_X(&code[4], 5, 5, 6);
    mneg_x(&code[8], 3, 2, 0);
    assert(run_helper_check(code, 12) == 0);

    // Negative: MSUB with explicit Ra != XZR (not the MNEG alias).
    movz_x(&code[0], 0, 8, 0);
    msub_x(&code[4], 3, 2, 0, 4);  // Ra = X4
    assert(run_helper_check(code, 8) == 0);

    // Sanity: an MUL pattern (bit 15 = 0) does NOT fire as MNEG.
    // movz x0, #8 ; mul x3, x2, x0 -- should fire as MUL strength
    // reduction (1 finding), but NOT as MNEG. Total findings == 1.
    movz_x(&code[0], 0, 8, 0);
    mul_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);
}

// UDIV Xd, Xn, Xm encoding. Base 0x9AC00800.
static void udiv_x(uint8_t out[4], unsigned rd, unsigned rn, unsigned rm)
{
    uint32_t op = 0x9AC00800u
        | ((rm & 0x1Fu) << 16)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// UDIV Wd, Wn, Wm encoding. Base 0x1AC00800.
static void udiv_w(uint8_t out[4], unsigned rd, unsigned rn, unsigned rm)
{
    uint32_t op = 0x1AC00800u
        | ((rm & 0x1Fu) << 16)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// SDIV Xd, Xn, Xm encoding. Base 0x9AC00C00 (opcode2 = 000011).
// Used only to verify SDIV does NOT match check_udiv_strength_reduce.
static void sdiv_x(uint8_t out[4], unsigned rd, unsigned rn, unsigned rm)
{
    uint32_t op = 0x9AC00C00u
        | ((rm & 0x1Fu) << 16)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

static void test_udiv_strength_reduce(void)
{
    uint8_t code[16];

    // movz x0, #8 ; udiv x3, x2, x0  -> lsr x3, x2, #3.
    movz_x(&code[0], 0, 8, 0);
    udiv_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // W form: movz w0, #4 ; udiv w3, w2, w0  -> lsr w3, w2, #2.
    movz_w(&code[0], 0, 4);
    udiv_w(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // Larger power-of-2: movz x0, #1024 ; udiv x3, x2, x0
    //                              -> lsr x3, x2, #10.
    movz_x(&code[0], 0, 1024, 0);
    udiv_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // Large power-of-2 via shifted MOVZ: movz x0, #1, lsl #32 ; ...
    movz_x(&code[0], 0, 1, 2);
    udiv_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // 0x10000 (pow2 in upper half) via a single shifted MOVZ.
    // movz x0, #1, lsl #16 ; udiv x3, x2, x0  -> lsr x3, x2, #16.
    movz_x(&code[0], 0, 1, 1);
    udiv_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // Rd == mov_rd is fine: rewrite clobbers x0 with a value still
    // derived from x0 the divisor.
    // movz x0, #8 ; udiv x0, x2, x0  -> lsr x0, x2, #3.
    movz_x(&code[0], 0, 8, 0);
    udiv_x(&code[4], 0, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // Rn == mov_rd is also fine (dividend reuses the constant register).
    // movz x0, #8 ; udiv x3, x0, x0  -> lsr x3, x0, #3.
    movz_x(&code[0], 0, 8, 0);
    udiv_x(&code[4], 3, 0, 0);
    assert(run_helper_check(code, 8) == 1);

    // Negative: non-power-of-2 (C = 3).
    movz_x(&code[0], 0, 3, 0);
    udiv_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: non-power-of-2 (C = 10).
    movz_x(&code[0], 0, 10, 0);
    udiv_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: 2^N - 1 (C = 7).
    movz_x(&code[0], 0, 7, 0);
    udiv_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: identity (C = 1).
    movz_x(&code[0], 0, 1, 0);
    udiv_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: zero divisor (C = 0).
    movz_x(&code[0], 0, 0, 0);
    udiv_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: UDIV is not commutative. mov_rd == Rn (dividend) is
    // NOT a foldable pattern -- the constant would need a reciprocal.
    // movz x0, #8 ; udiv x3, x0, x2 -- x2 unrelated.
    movz_x(&code[0], 0, 8, 0);
    udiv_x(&code[4], 3, 0, 2);
    assert(run_helper_check(code, 8) == 0);

    // Negative: UDIV does not read the MOV destination at all.
    movz_x(&code[0], 0, 8, 0);
    udiv_x(&code[4], 3, 2, 1);
    assert(run_helper_check(code, 8) == 0);

    // Negative: width mismatch -- 64-bit MOV, 32-bit UDIV.
    movz_x(&code[0], 0, 8, 0);
    udiv_w(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: width mismatch -- 32-bit MOV, 64-bit UDIV.
    movz_w(&code[0], 0, 8);
    udiv_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: an intervening non-MOV closes the chain.
    movz_x(&code[0], 0, 8, 0);
    ADD_X(&code[4], 5, 5, 6);
    udiv_x(&code[8], 3, 2, 0);
    assert(run_helper_check(code, 12) == 0);

    // Negative: Rd = XZR discards the result.
    movz_x(&code[0], 0, 8, 0);
    udiv_x(&code[4], 31, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: Rn = XZR makes the dividend always zero.
    movz_x(&code[0], 0, 8, 0);
    udiv_x(&code[4], 3, 31, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: SDIV by 2^N is NOT equivalent to ASR (wrong rounding
    // on negative dividends). Same encoding block, opcode2 = 000011.
    movz_x(&code[0], 0, 8, 0);
    sdiv_x(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Bare UDIV with no preceding MOV: no finding.
    udiv_x(&code[0], 3, 2, 0);
    assert(run_helper_check(code, 4) == 0);
}

// CMP Xn, Xm (shifted-register form: SUBS XZR, Xn, Xm, LSL #0).
// Base 0xEB00001F (sf=1, op=1=SUB, S=1, shift=00, bit21=0, Rd=11111).
static void cmp_x_reg_sr(uint8_t out[4], unsigned rn, unsigned rm)
{
    uint32_t op = 0xEB00001Fu
        | ((rm & 0x1Fu) << 16)
        | ((rn & 0x1Fu) << 5);
    write_le32(out, op);
}

// CMN Xn, Xm (ADDS XZR, Xn, Xm, LSL #0). Base 0xAB00001F.
static void cmn_x_reg_sr(uint8_t out[4], unsigned rn, unsigned rm)
{
    uint32_t op = 0xAB00001Fu
        | ((rm & 0x1Fu) << 16)
        | ((rn & 0x1Fu) << 5);
    write_le32(out, op);
}

static void test_mov_add_sub_imm_fold(void)
{
    uint8_t code[16];

    // movz x0, #100 ; add x3, x2, x0  -> add x3, x2, #100.
    movz_x(&code[0], 0, 100, 0);
    ADD_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // Commutativity: movz x0, #100 ; add x3, x0, x2.
    movz_x(&code[0], 0, 100, 0);
    ADD_X(&code[4], 3, 0, 2);
    assert(run_helper_check(code, 8) == 1);

    // W form: movz w0, #50 ; add w3, w2, w0.
    movz_w(&code[0], 0, 50);
    ADD_W(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // ADDS variant: movz x0, #100 ; adds x3, x2, x0  -> adds x3, x2, #100.
    movz_x(&code[0], 0, 100, 0);
    encode_sr(&code[4], 0xAB000000u, 3, 2, 0);  // ADDS X3, X2, X0
    assert(run_helper_check(code, 8) == 1);

    // SUB: movz x0, #100 ; sub x3, x2, x0  -> sub x3, x2, #100.
    movz_x(&code[0], 0, 100, 0);
    SUB_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // SUBS: movz x0, #100 ; subs x3, x2, x0  -> subs x3, x2, #100.
    movz_x(&code[0], 0, 100, 0);
    SUBS_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // CMP (SUBS XZR, ...): movz x0, #100 ; cmp x2, x0  -> cmp x2, #100.
    movz_x(&code[0], 0, 100, 0);
    cmp_x_reg_sr(&code[4], 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // CMN (ADDS XZR, ...): movz x0, #100 ; cmn x2, x0  -> cmn x2, #100.
    movz_x(&code[0], 0, 100, 0);
    cmn_x_reg_sr(&code[4], 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // imm12 boundary: C = 0xFFF (= 4095) fits without shift.
    movz_x(&code[0], 0, 0xFFF, 0);
    ADD_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // imm12 << 12: C = 0x1000 fits with sh=1.
    movz_x(&code[0], 0, 0x1000, 0);
    ADD_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // imm12 << 12 boundary: C = 0xFFF000 fits with sh=1.
    movz_x(&code[0], 0, 0xFFF, 1);  // imm = 0xFFF << 16 = 0xFFF0000 -- no wait.
    // Use a different encoding: imm16=0xFFF, shift=0 gives 0xFFF.
    // To get 0xFFF000, we need MOVZ X0, #0xFFF, LSL #16? No that's 0xFFF0000.
    // 0xFFF000 = 0xFFF * 4096 = 0xFFF * 0x1000 ... hmm, not directly via MOVZ.
    // MOVZ X0, #0xFFF000 won't fit in 16-bit imm. Skip this case.

    // Negative: C = 4097 doesn't fit (not <= 4095, not a multiple of 4096).
    movz_x(&code[0], 0, 0x1001, 0);
    ADD_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: SUB with Rn from MOV (would need reverse-subtract).
    movz_x(&code[0], 0, 100, 0);
    SUB_X(&code[4], 3, 0, 2);  // SUB X3, X0, X2 -- Rn = X0 (from MOV)
    assert(run_helper_check(code, 8) == 0);

    // C = 0 is intentionally not folded by check_mov_add_sub_imm_fold
    // (the rewrite "ADD Rd, Rn, #0" is the MOV-or-no-op case). But
    // check_mov_zero_to_xzr DOES fire on this pattern with a different
    // rewrite suggestion ("use XZR for the second operand"), so the
    // overall finding count is 1.
    movz_x(&code[0], 0, 0, 0);
    ADD_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // Negative: width mismatch (MOV W, ADD X).
    movz_w(&code[0], 0, 100);
    ADD_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: width mismatch (MOV X, ADD W).
    movz_x(&code[0], 0, 100, 0);
    ADD_W(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: ADD does not read the MOV destination.
    movz_x(&code[0], 0, 100, 0);
    ADD_X(&code[4], 3, 2, 1);  // X1 instead of X0
    assert(run_helper_check(code, 8) == 0);

    // Negative: intervening instruction closes the chain.
    movz_x(&code[0], 0, 100, 0);
    ADD_X(&code[4], 5, 5, 6);  // unrelated insn
    ADD_X(&code[8], 3, 2, 0);
    assert(run_helper_check(code, 12) == 0);

    // Negative: non-S ADD with Rd = XZR (dead code, skip).
    movz_x(&code[0], 0, 100, 0);
    ADD_X(&code[4], 31, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: shifted ADD (imm6 != 0) doesn't fold.
    // ADD X3, X2, X0, LSL #2 -- imm6=2.
    movz_x(&code[0], 0, 100, 0);
    uint32_t op_lsl2 = 0x8B000000u | (0u << 16) | (2u << 10) | (2u << 5) | 3u;
    code[4] = op_lsl2 & 0xff;
    code[5] = (op_lsl2 >> 8) & 0xff;
    code[6] = (op_lsl2 >> 16) & 0xff;
    code[7] = (op_lsl2 >> 24) & 0xff;
    assert(run_helper_check(code, 8) == 0);
}

static void test_mov_logic_imm_fold(void)
{
    uint8_t code[16];

    // AND: movz x0, #0xff ; and x3, x2, x0  -> and x3, x2, #0xff.
    movz_x(&code[0], 0, 0xFF, 0);
    AND_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // Commutativity (Rn from MOV).
    movz_x(&code[0], 0, 0xFF, 0);
    AND_X(&code[4], 3, 0, 2);
    assert(run_helper_check(code, 8) == 1);

    // W form.
    movz_w(&code[0], 0, 0xFF);
    AND_W(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // ORR.
    movz_x(&code[0], 0, 0xFF, 0);
    ORR_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // EOR.
    movz_x(&code[0], 0, 0xFF, 0);
    EOR_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // ANDS.
    movz_x(&code[0], 0, 0xFF, 0);
    ANDS_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // TST alias (ANDS with Rd = XZR).
    movz_x(&code[0], 0, 0xFF, 0);
    ANDS_X(&code[4], 31, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // 16-bit bitmask: movz x0, #0xffff ; and x3, x2, x0.
    movz_x(&code[0], 0, 0xFFFF, 0);
    AND_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // Two-MOV chain producing 0xffff0000ffff0000 (esize=32 bitmask).
    // 0xFFFF0000 in 64-bit also has a bitmask encoding (rotated run).
    // First check via a single MOVZ at shift 16 giving 0xFFFF0000.
    movz_x(&code[0], 0, 0xFFFF, 1);
    AND_X(&code[4], 3, 2, 0);
    // This is a single MOVZ + AND -- 1 finding from our check;
    // check_movz_movk_bitmask requires chain >= 2 so it doesn't fire.
    assert(run_helper_check(code, 8) == 1);

    // Negative: C = 5 (binary 101) is not a bitmask immediate
    // (non-contiguous bits, no replicated-run encoding).
    movz_x(&code[0], 0, 5, 0);
    AND_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // C = 0 is not a bitmask immediate so check_mov_logic_imm_fold
    // skips, but check_mov_zero_to_xzr fires on it (suggesting "use
    // XZR for the second AND operand"), so the overall count is 1.
    movz_x(&code[0], 0, 0, 0);
    AND_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // Negative: BIC (N = 1 in the encoding) has no immediate form.
    movz_x(&code[0], 0, 0xFF, 0);
    BIC_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: ORN (N = 1).
    movz_x(&code[0], 0, 0xFF, 0);
    ORN_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: width mismatch.
    movz_w(&code[0], 0, 0xFF);
    AND_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: MOV does not feed the AND.
    movz_x(&code[0], 0, 0xFF, 0);
    AND_X(&code[4], 3, 2, 1);
    assert(run_helper_check(code, 8) == 0);

    // Negative: intervening instruction closes the chain.
    movz_x(&code[0], 0, 0xFF, 0);
    ADD_X(&code[4], 5, 5, 6);
    AND_X(&code[8], 3, 2, 0);
    assert(run_helper_check(code, 12) == 0);

    // Negative: non-ANDS write to ZR (dead code).
    movz_x(&code[0], 0, 0xFF, 0);
    AND_X(&code[4], 31, 2, 0);
    assert(run_helper_check(code, 8) == 0);

    // Negative: shifted AND (imm6 != 0).
    movz_x(&code[0], 0, 0xFF, 0);
    uint32_t op_and_lsl2 = 0x8A000000u
        | (0u << 16) | (2u << 10) | (2u << 5) | 3u;
    code[4] = op_and_lsl2 & 0xff;
    code[5] = (op_and_lsl2 >> 8) & 0xff;
    code[6] = (op_and_lsl2 >> 16) & 0xff;
    code[7] = (op_and_lsl2 >> 24) & 0xff;
    assert(run_helper_check(code, 8) == 0);
}

// Encode STR Xt, [Xn, #imm] (X-form, unsigned offset, imm in 8-byte
// units). Base 0xF9000000.
static void str_x_uimm(uint8_t out[4], unsigned rt, unsigned rn, unsigned imm)
{
    uint32_t op = 0xF9000000u
        | ((imm & 0xFFFu) << 10)
        | ((rn & 0x1Fu) << 5)
        | (rt & 0x1Fu);
    write_le32(out, op);
}

// Encode STRB Wt, [Xn, #imm] (byte store). Base 0x39000000.
static void strb_w_uimm(uint8_t out[4], unsigned rt, unsigned rn,
                        unsigned imm)
{
    uint32_t op = 0x39000000u
        | ((imm & 0xFFFu) << 10)
        | ((rn & 0x1Fu) << 5)
        | (rt & 0x1Fu);
    write_le32(out, op);
}

// Encode STRH Wt, [Xn, #imm] (halfword store). Base 0x79000000.
static void strh_w_uimm(uint8_t out[4], unsigned rt, unsigned rn,
                        unsigned imm)
{
    uint32_t op = 0x79000000u
        | ((imm & 0xFFFu) << 10)
        | ((rn & 0x1Fu) << 5)
        | (rt & 0x1Fu);
    write_le32(out, op);
}

// Encode LDR Xt, [Xn, #imm] (X-form load, unsigned offset). For
// negative-test: LDR should NOT fire because the consumer family is
// loads, not stores. Base 0xF9400000.
static void ldr_x_uimm_for_test(uint8_t out[4], unsigned rt, unsigned rn,
                                unsigned imm)
{
    uint32_t op = 0xF9400000u
        | ((imm & 0xFFFu) << 10)
        | ((rn & 0x1Fu) << 5)
        | (rt & 0x1Fu);
    write_le32(out, op);
}

static void test_mov_zero_to_xzr(void)
{
    uint8_t code[16];

    // (a) STR family:
    // STR X form.
    movz_x(&code[0], 0, 0, 0);
    str_x_uimm(&code[4], 0, 1, 0);
    assert(run_helper_check(code, 8) == 1);

    // STR W form.
    movz_w(&code[0], 0, 0);
    STR_W(&code[4], 0, 1, 0);
    assert(run_helper_check(code, 8) == 1);

    // STRB.
    movz_w(&code[0], 0, 0);
    strb_w_uimm(&code[4], 0, 1, 0);
    assert(run_helper_check(code, 8) == 1);

    // STRH.
    movz_w(&code[0], 0, 0);
    strh_w_uimm(&code[4], 0, 1, 0);
    assert(run_helper_check(code, 8) == 1);

    // STR with non-zero offset.
    movz_x(&code[0], 0, 0, 0);
    str_x_uimm(&code[4], 0, 1, 16);  // offset = 16*8 = 128 bytes
    assert(run_helper_check(code, 8) == 1);

    // STR with SP as base.
    movz_x(&code[0], 0, 0, 0);
    str_x_uimm(&code[4], 0, 31, 0);  // [sp]
    assert(run_helper_check(code, 8) == 1);

    // Width skew: X-form MOV, STR W (low bits of 0 are 0).
    movz_x(&code[0], 0, 0, 0);
    STR_W(&code[4], 0, 1, 0);
    assert(run_helper_check(code, 8) == 1);

    // (b) ADD/SUB shifted-LSL0:
    // ADD with Rm = mov_rd -> use XZR.
    movz_x(&code[0], 0, 0, 0);
    ADD_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // ADD with Rn = mov_rd (commutativity).
    movz_x(&code[0], 0, 0, 0);
    ADD_X(&code[4], 3, 0, 2);
    assert(run_helper_check(code, 8) == 1);

    // SUB with Rm = mov_rd (-> MOV Rd, Rn).
    movz_x(&code[0], 0, 0, 0);
    SUB_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // SUB with Rn = mov_rd (-> NEG Rd, Rm). The "SUB-from-zero" form.
    movz_x(&code[0], 0, 0, 0);
    SUB_X(&code[4], 3, 0, 2);
    assert(run_helper_check(code, 8) == 1);

    // CMP (SUBS XZR, Rn, Rm) with Rm = mov_rd -> "cmp xn, xzr".
    movz_x(&code[0], 0, 0, 0);
    cmp_x_reg_sr(&code[4], 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // CMN (ADDS XZR, Rn, Rm).
    movz_x(&code[0], 0, 0, 0);
    cmn_x_reg_sr(&code[4], 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // (c) AND/ORR/EOR shifted-LSL0:
    // AND with Rm = mov_rd.
    movz_x(&code[0], 0, 0, 0);
    AND_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // ORR with Rm = mov_rd -> MOV Rd, Rn (the canonical MOV
    // register form is ORR Rd, XZR, Rm; this is the mirror).
    movz_x(&code[0], 0, 0, 0);
    ORR_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // EOR with Rm = mov_rd -> MOV Rd, Rn (XOR identity).
    movz_x(&code[0], 0, 0, 0);
    EOR_X(&code[4], 3, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // TST (ANDS XZR, ...).
    movz_x(&code[0], 0, 0, 0);
    ANDS_X(&code[4], 31, 2, 0);
    assert(run_helper_check(code, 8) == 1);

    // Negatives:
    // Mov value not zero.
    movz_x(&code[0], 0, 1, 0);
    str_x_uimm(&code[4], 0, 1, 0);
    assert(run_helper_check(code, 8) == 0);

    // STR Rt != mov_rd.
    movz_x(&code[0], 0, 0, 0);
    str_x_uimm(&code[4], 2, 1, 0);  // Rt = X2, not X0
    assert(run_helper_check(code, 8) == 0);

    // STR base = mov_rd (Rn slot): replacing Rn with ZR would mean SP,
    // not XZR -- changes semantics. We don't fold this case.
    movz_x(&code[0], 0, 0, 0);
    str_x_uimm(&code[4], 2, 0, 0);  // STR X2, [X0]; Rt=X2, Rn=X0=mov_rd
    assert(run_helper_check(code, 8) == 0);

    // LDR (not a store) -> not a STR fold case. The consumer reads
    // mov_rd via Rn (base), which is SP if 31. Even Rt could match
    // mov_rd here (loading INTO the MOV destination, overwriting it
    // -- a different pattern, the "dead MOV" case).
    movz_x(&code[0], 0, 0, 0);
    ldr_x_uimm_for_test(&code[4], 2, 1, 0);  // LDR X2, [X1] -- no read of X0
    assert(run_helper_check(code, 8) == 0);

    // Intervening instruction closes the chain.
    movz_x(&code[0], 0, 0, 0);
    ADD_X(&code[4], 5, 5, 6);
    str_x_uimm(&code[8], 0, 1, 0);
    assert(run_helper_check(code, 12) == 0);

    // ALU op where neither operand is mov_rd.
    movz_x(&code[0], 0, 0, 0);
    ADD_X(&code[4], 3, 1, 2);  // ADD X3, X1, X2 -- no X0
    assert(run_helper_check(code, 8) == 0);
}

static void test_mul_add_sub_fold(void)
{
    uint8_t code[16];

    // mul x3, x1, x2 ; add x3, x3, x4  -> madd x3, x1, x2, x4.
    mul_x(&code[0], 3, 1, 2);
    ADD_X(&code[4], 3, 3, 4);
    assert(run_helper_check(code, 8) == 1);

    // Commutativity: mul x3, x1, x2 ; add x3, x4, x3.
    mul_x(&code[0], 3, 1, 2);
    ADD_X(&code[4], 3, 4, 3);
    assert(run_helper_check(code, 8) == 1);

    // W form.
    mul_w(&code[0], 3, 1, 2);
    ADD_W(&code[4], 3, 3, 4);
    assert(run_helper_check(code, 8) == 1);

    // SUB with Rm = mul_rd (xd = xc - xt) -> MSUB.
    mul_x(&code[0], 3, 1, 2);
    SUB_X(&code[4], 3, 4, 3);
    assert(run_helper_check(code, 8) == 1);

    // Negative: SUB with Rn = mul_rd (xd = xt - xc) -- NOT foldable
    // because MSUB computes Ra - Rn*Rm, not Rn*Rm - Ra.
    mul_x(&code[0], 3, 1, 2);
    SUB_X(&code[4], 3, 3, 4);
    assert(run_helper_check(code, 8) == 0);

    // Negative: ADDS (S-variant) -- no flag-setting MADD.
    mul_x(&code[0], 3, 1, 2);
    encode_sr(&code[4], 0xAB000000u, 3, 3, 4);  // ADDS X3, X3, X4
    assert(run_helper_check(code, 8) == 0);

    // Negative: SUBS (S-variant).
    mul_x(&code[0], 3, 1, 2);
    SUBS_X(&code[4], 3, 4, 3);
    assert(run_helper_check(code, 8) == 0);

    // Negative: Rd != Rt (the MUL result is alive after the ADD).
    mul_x(&code[0], 3, 1, 2);
    ADD_X(&code[4], 5, 3, 4);  // writes X5, not X3
    assert(run_helper_check(code, 8) == 0);

    // Negative: accumulator == mul_rd (xc == xt aliasing).
    // mul x3, x1, x2 ; add x3, x3, x3.
    mul_x(&code[0], 3, 1, 2);
    ADD_X(&code[4], 3, 3, 3);
    assert(run_helper_check(code, 8) == 0);

    // Negative: width mismatch (MUL W, ADD X).
    mul_w(&code[0], 3, 1, 2);
    ADD_X(&code[4], 3, 3, 4);
    assert(run_helper_check(code, 8) == 0);

    // Negative: ADD does not consume mul_rd.
    mul_x(&code[0], 3, 1, 2);
    ADD_X(&code[4], 6, 4, 5);  // X6 = X4 + X5; no read of X3
    assert(run_helper_check(code, 8) == 0);

    // Negative: shifted ADD (imm6 != 0).
    mul_x(&code[0], 3, 1, 2);
    uint32_t op_lsl1 = 0x8B000000u | (3u << 16) | (1u << 10) | (3u << 5) | 3u;
    code[4] = op_lsl1 & 0xff;
    code[5] = (op_lsl1 >> 8) & 0xff;
    code[6] = (op_lsl1 >> 16) & 0xff;
    code[7] = (op_lsl1 >> 24) & 0xff;
    assert(run_helper_check(code, 8) == 0);

    // Negative: intervening instruction breaks adjacency.
    mul_x(&code[0], 3, 1, 2);
    ADD_X(&code[4], 5, 5, 6);  // unrelated
    ADD_X(&code[8], 3, 3, 4);
    assert(run_helper_check(code, 12) == 0);

    // Negative: MUL writing XZR (Rd=31) does not open pending.
    mul_x(&code[0], 31, 1, 2);
    ADD_X(&code[4], 31, 31, 4);  // arbitrary ADD
    assert(run_helper_check(code, 8) == 0);

    // Aliasing of MUL operands with each other: mul x3, x3, x2 (MUL's
    // Rd == Rn == x3). The MADD rewrite reads x3 (pre-MUL value), so
    // sound provided Rd == Rt and xc != Rt.
    mul_x(&code[0], 3, 3, 2);
    ADD_X(&code[4], 3, 3, 4);
    assert(run_helper_check(code, 8) == 1);

    // MUL with Rn = Rm (square): mul x3, x1, x1 ; add x3, x3, x4
    //                            -> madd x3, x1, x1, x4.
    mul_x(&code[0], 3, 1, 1);
    ADD_X(&code[4], 3, 3, 4);
    assert(run_helper_check(code, 8) == 1);
}

// Encode X-form ADD (shifted-register, LSL #shift). Base 0x8B000000
// carries sf=1, op=0 (ADD), S=0, shifted-register opcode and shift
// type = LSL.
static void add_x_lsl(uint8_t out[4], unsigned rd, unsigned rn,
                      unsigned rm, unsigned shift)
{
    uint32_t op = 0x8B000000u
        | ((rm & 0x1Fu) << 16)
        | ((shift & 0x3Fu) << 10)
        | ((rn & 0x1Fu) << 5)
        | (rd & 0x1Fu);
    write_le32(out, op);
}

// Encode LDR Xt, [Xn] (unsigned-offset, imm12=0). Base 0xF9400000.
static void ldr_x_uimm0(uint8_t out[4], unsigned rt, unsigned rn)
{
    uint32_t op = 0xF9400000u
        | ((rn & 0x1Fu) << 5)
        | (rt & 0x1Fu);
    write_le32(out, op);
}

// Encode LDR Wt, [Xn] (W-form, unsigned-offset, imm12=0). Base 0xB9400000.
static void ldr_w_uimm0(uint8_t out[4], unsigned rt, unsigned rn)
{
    uint32_t op = 0xB9400000u
        | ((rn & 0x1Fu) << 5)
        | (rt & 0x1Fu);
    write_le32(out, op);
}

// Encode LDRB Wt, [Xn] (byte load, unsigned-offset, imm12=0). Base 0x39400000.
static void ldrb_w_uimm0(uint8_t out[4], unsigned rt, unsigned rn)
{
    uint32_t op = 0x39400000u
        | ((rn & 0x1Fu) << 5)
        | (rt & 0x1Fu);
    write_le32(out, op);
}

// Encode LDRH Wt, [Xn] (halfword load, unsigned-offset, imm12=0). Base 0x79400000.
static void ldrh_w_uimm0(uint8_t out[4], unsigned rt, unsigned rn)
{
    uint32_t op = 0x79400000u
        | ((rn & 0x1Fu) << 5)
        | (rt & 0x1Fu);
    write_le32(out, op);
}

// Encode LDR Xt, [Xn, #imm] (X-form, unsigned-offset, scaled imm). Base 0xF9400000.
static void ldr_x_uimm_with(uint8_t out[4], unsigned rt, unsigned rn,
                            unsigned imm12)
{
    uint32_t op = 0xF9400000u
        | ((imm12 & 0xFFFu) << 10)
        | ((rn & 0x1Fu) << 5)
        | (rt & 0x1Fu);
    write_le32(out, op);
}

static void test_add_ldr_register_offset(void)
{
    uint8_t code[16];

    // Canonical X-form: add x3, x1, x2 ; ldr x3, [x3]
    //                   -> ldr x3, [x1, x2].
    add_x_lsl(&code[0], 3, 1, 2, 0);
    ldr_x_uimm0(&code[4], 3, 3);
    assert(run_helper_check(code, 8) == 1);

    // X-form with LSL #3 (matches X access scale): add x3, x1, x2, lsl #3
    //                                              ; ldr x3, [x3]
    //                                              -> ldr x3, [x1, x2, lsl #3].
    add_x_lsl(&code[0], 3, 1, 2, 3);
    ldr_x_uimm0(&code[4], 3, 3);
    assert(run_helper_check(code, 8) == 1);

    // W-form LDR: add x3, x1, x2 ; ldr w3, [x3] -> ldr w3, [x1, x2].
    add_x_lsl(&code[0], 3, 1, 2, 0);
    ldr_w_uimm0(&code[4], 3, 3);
    assert(run_helper_check(code, 8) == 1);

    // W-form LDR with LSL #2 (matches W access scale):
    // add x3, x1, x2, lsl #2 ; ldr w3, [x3]
    //                        -> ldr w3, [x1, x2, lsl #2].
    add_x_lsl(&code[0], 3, 1, 2, 2);
    ldr_w_uimm0(&code[4], 3, 3);
    assert(run_helper_check(code, 8) == 1);

    // LDRB: shift=0 OK.
    add_x_lsl(&code[0], 3, 1, 2, 0);
    ldrb_w_uimm0(&code[4], 3, 3);
    assert(run_helper_check(code, 8) == 1);

    // LDRH with LSL #1 (matches H access scale).
    add_x_lsl(&code[0], 3, 1, 2, 1);
    ldrh_w_uimm0(&code[4], 3, 3);
    assert(run_helper_check(code, 8) == 1);

    // Negative: LSL #2 with X access (scale 3) does NOT match.
    add_x_lsl(&code[0], 3, 1, 2, 2);
    ldr_x_uimm0(&code[4], 3, 3);
    assert(run_helper_check(code, 8) == 0);

    // Negative: LSL #1 with W access (scale 2) does NOT match.
    add_x_lsl(&code[0], 3, 1, 2, 1);
    ldr_w_uimm0(&code[4], 3, 3);
    assert(run_helper_check(code, 8) == 0);

    // Negative: LSL #3 with B access (scale 0, only 0 allowed) -- not match.
    add_x_lsl(&code[0], 3, 1, 2, 3);
    ldrb_w_uimm0(&code[4], 3, 3);
    assert(run_helper_check(code, 8) == 0);

    // Negative: LDR base != ADD's Rd.
    add_x_lsl(&code[0], 3, 1, 2, 0);
    ldr_x_uimm0(&code[4], 3, 5);  // base x5 != x3
    assert(run_helper_check(code, 8) == 0);

    // Negative: LDR's Rt != ADD's Rd (would leave Xt alive).
    add_x_lsl(&code[0], 3, 1, 2, 0);
    ldr_x_uimm0(&code[4], 7, 3);  // load into x7, not x3
    assert(run_helper_check(code, 8) == 0);

    // Negative: LDR with non-zero immediate offset.
    add_x_lsl(&code[0], 3, 1, 2, 0);
    ldr_x_uimm_with(&code[4], 3, 3, 1);
    assert(run_helper_check(code, 8) == 0);

    // Negative: SUB instead of ADD (semantics differ -- not a fold).
    SUB_X(&code[0], 3, 1, 2);
    ldr_x_uimm0(&code[4], 3, 3);
    assert(run_helper_check(code, 8) == 0);

    // Negative: ADDS (S-variant -- writes flags, not pure ADD).
    encode_sr(&code[0], 0xAB000000u, 3, 1, 2);  // ADDS X3, X1, X2
    ldr_x_uimm0(&code[4], 3, 3);
    assert(run_helper_check(code, 8) == 0);

    // Negative: W-form ADD (sf=0) -- base register must be X.
    ADD_W(&code[0], 3, 1, 2);
    ldr_x_uimm0(&code[4], 3, 3);
    assert(run_helper_check(code, 8) == 0);

    // Negative: ADD with Rn = XZR (Rn=31 means XZR in shifted-register
    // ADD; folding would change to SP semantics in the LDR).
    add_x_lsl(&code[0], 3, 31, 2, 0);
    ldr_x_uimm0(&code[4], 3, 3);
    assert(run_helper_check(code, 8) == 0);

    // Negative: ADD with Rm = XZR (degenerate; not folded).
    add_x_lsl(&code[0], 3, 1, 31, 0);
    ldr_x_uimm0(&code[4], 3, 3);
    assert(run_helper_check(code, 8) == 0);

    // Negative: ADD writing XZR (Rd=31, dead code).
    add_x_lsl(&code[0], 31, 1, 2, 0);
    ldr_x_uimm0(&code[4], 31, 31);
    assert(run_helper_check(code, 8) == 0);

    // Negative: intervening instruction breaks adjacency.
    add_x_lsl(&code[0], 3, 1, 2, 0);
    ADD_X(&code[4], 5, 5, 6);  // unrelated
    ldr_x_uimm0(&code[8], 3, 3);
    assert(run_helper_check(code, 12) == 0);

    // Negative: LSL #4 (above max useful scale).
    add_x_lsl(&code[0], 3, 1, 2, 4);
    ldr_x_uimm0(&code[4], 3, 3);
    assert(run_helper_check(code, 8) == 0);

    // Negative: trailing ADD with no following LDR (strict adjacency,
    // not flagged at flush -- the pending state simply expires).
    add_x_lsl(&code[0], 3, 1, 2, 0);
    assert(run_helper_check(code, 4) == 0);

    // Aliasing positive: add x3, x3, x2 ; ldr x3, [x3]
    //   ADD's Rd == Rn. The fold ldr x3, [x3, x2] reads x3's
    //   pre-ADD value as base, matching the original semantics
    //   (the LDR overwrites x3 immediately).
    add_x_lsl(&code[0], 3, 3, 2, 0);
    ldr_x_uimm0(&code[4], 3, 3);
    assert(run_helper_check(code, 8) == 1);

    // Aliasing positive: add x3, x1, x3 (Rd == Rm). Same reasoning.
    add_x_lsl(&code[0], 3, 1, 3, 0);
    ldr_x_uimm0(&code[4], 3, 3);
    assert(run_helper_check(code, 8) == 1);
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
    test_tst_branch();
    test_redundant_zext();
    test_lsl_lsr_to_ubfx();
    test_lsr_and_to_ubfx();
    test_mov_reg_self();
    test_redundant_sext();
    test_redundant_cmp_after_s_variant();
    test_add_sub_zero();
    test_self_op();
    test_csel_self();
    test_bfxil_synth();
    test_ldp_stp_coalesce();
    test_mul_strength_reduce();
    test_mneg_strength_reduce();
    test_udiv_strength_reduce();
    test_mov_add_sub_imm_fold();
    test_mov_logic_imm_fold();
    test_mov_zero_to_xzr();
    test_mul_add_sub_fold();
    test_add_ldr_register_offset();

    cs_close(&g_handle);
    printf("all tests passed\n");
    return 0;
}
