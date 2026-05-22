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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "armlint.h"

struct armlint_state {
    bool active;
    unsigned rd;
    bool is_64bit;
    uint64_t value;
    size_t start_offset;
    unsigned insn_count;
};

armlint_state *armlint_state_create(void)
{
    armlint_state *s = calloc(1, sizeof(*s));
    return s;
}

void armlint_state_destroy(armlint_state *state)
{
    free(state);
}

void armlint_state_reset(armlint_state *state)
{
    memset(state, 0, sizeof(*state));
}

static uint64_t width_mask(unsigned reg_width)
{
    return reg_width == 64 ? ~(uint64_t)0 : ((uint64_t)1 << reg_width) - 1;
}

bool is_bitmask_immediate(uint64_t imm, unsigned reg_width)
{
    if (reg_width != 32 && reg_width != 64) {
        return false;
    }

    uint64_t mask_w = width_mask(reg_width);
    imm &= mask_w;
    if (imm == 0 || imm == mask_w) {
        return false;
    }

    // Smallest esize for which imm replicates determines encodability:
    // at any larger esize the chunk has at least as many cyclic 1-runs,
    // so if the smallest replicating size is not a rotated single run,
    // no other size can rescue it.
    for (unsigned esize = 2; esize <= reg_width; esize *= 2) {
        uint64_t mask_e = esize == 64 ? ~(uint64_t)0 : ((uint64_t)1 << esize) - 1;
        uint64_t chunk = imm & mask_e;

        bool replicates = true;
        for (unsigned pos = esize; pos < reg_width; pos += esize) {
            if (((imm >> pos) & mask_e) != chunk) {
                replicates = false;
                break;
            }
        }
        if (!replicates) {
            continue;
        }

        for (unsigned r = 0; r < esize; r++) {
            uint64_t rot;
            if (r == 0) {
                rot = chunk;
            } else {
                rot = ((chunk >> r) | (chunk << (esize - r))) & mask_e;
            }
            // rot is (2^n - 1) for some 1 <= n <= esize-1 iff
            // rot != 0 and (rot & (rot + 1)) == 0. n != 0 because
            // chunk != 0 at the smallest replicating esize; n != esize
            // because chunk != mask_e.
            if (rot != 0 && (rot & (rot + 1)) == 0) {
                return true;
            }
        }
        return false;
    }
    return false;
}

static bool close_sequence(armlint_state *state, armlint_finding *out)
{
    if (!state->active) {
        return false;
    }

    bool produced = false;
    if (state->insn_count >= 2) {
        unsigned reg_width = state->is_64bit ? 64 : 32;
        if (is_bitmask_immediate(state->value, reg_width)) {
            out->name = "suboptimal MOVZ/MOVK sequence";
            out->start_offset = state->start_offset;
            out->insn_count = state->insn_count;
            out->value = state->value;
            out->reg_width = reg_width;
            out->rd = state->rd;
            produced = true;
        }
    }

    state->active = false;
    return produced;
}

bool armlint_flush(armlint_state *state, armlint_finding *out)
{
    return close_sequence(state, out);
}

// Decode the move-wide-immediate fields directly from the 4-byte
// little-endian encoding. Going through the raw bits avoids ambiguity
// from Capstone's alias selection (MOVZ/MOVN/ORR-bitmask-imm all share
// the MOV mnemonic).
bool check_movz_movk_bitmask(armlint_state *state, const cs_insn *insn,
                             size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        return close_sequence(state, out);
    }

    uint32_t op = (uint32_t)insn->bytes[0]
        | ((uint32_t)insn->bytes[1] << 8)
        | ((uint32_t)insn->bytes[2] << 16)
        | ((uint32_t)insn->bytes[3] << 24);

    bool is_move_wide = (op & 0x1f800000u) == 0x12800000u;
    if (!is_move_wide) {
        return close_sequence(state, out);
    }

    unsigned opc = (op >> 29) & 0x3u;
    unsigned sf = (op >> 31) & 0x1u;
    unsigned hw = (op >> 21) & 0x3u;
    unsigned imm16 = (op >> 5) & 0xffffu;
    unsigned rd = op & 0x1fu;

    // opc=01 is unallocated in this encoding class; rd=31 is XZR (not
    // SP for these aliases) and discards the constant. Treat both as
    // sequence-breakers.
    if (opc == 1 || rd == 31) {
        return close_sequence(state, out);
    }

    unsigned reg_width = sf ? 64 : 32;
    unsigned shift = hw * 16;
    uint64_t mask_w = width_mask(reg_width);

    if (opc == 3) {
        // MOVK extends an active sequence only if rd and width match.
        if (state->active && state->rd == rd
                && state->is_64bit == (reg_width == 64)) {
            uint64_t clear = ~((uint64_t)0xffffu << shift);
            state->value = (state->value & clear) | ((uint64_t)imm16 << shift);
            state->value &= mask_w;
            state->insn_count++;
            return false;
        }
        return close_sequence(state, out);
    }

    // opc == 0 (MOVN) or opc == 2 (MOVZ): start a new sequence,
    // closing any previous one first.
    bool produced = close_sequence(state, out);

    state->active = true;
    state->rd = rd;
    state->is_64bit = reg_width == 64;
    state->start_offset = offset;
    state->insn_count = 1;
    if (opc == 2) {
        state->value = ((uint64_t)imm16 << shift) & mask_w;
    } else {
        state->value = (~((uint64_t)imm16 << shift)) & mask_w;
    }

    return produced;
}

static void report_finding(const armlint_finding *finding,
                           const cs_insn *insns, size_t count,
                           uint64_t base_addr)
{
    printf("%s at offset: 0x%zx: %c%u = 0x%" PRIx64 " (%u instructions)\n",
        finding->name, finding->start_offset,
        finding->reg_width == 32 ? 'w' : 'x',
        finding->rd, finding->value, finding->insn_count);

    size_t end_offset = finding->start_offset + (size_t)finding->insn_count * 4;
    for (size_t i = 0; i < count; i++) {
        size_t off = (size_t)(insns[i].address - base_addr);
        if (off >= finding->start_offset && off < end_offset) {
            printf("  %s %s\n", insns[i].mnemonic, insns[i].op_str);
        }
    }
    printf("\n");
}

int check_instructions(csh handle, const uint8_t *inst, size_t len,
                       uint64_t base_addr)
{
    cs_insn *insns = NULL;
    size_t count = cs_disasm(handle, inst, len, base_addr, 0, &insns);
    if (count == 0) {
        cs_err err = cs_errno(handle);
        if (err != CS_ERR_OK) {
            fprintf(stderr, "Capstone error: %s\n", cs_strerror(err));
            return -1;
        }
        return 0;
    }

    armlint_state *state = armlint_state_create();
    if (state == NULL) {
        cs_free(insns, count);
        return -1;
    }

    int errors = 0;
    for (size_t i = 0; i < count; i++) {
        armlint_finding finding;
        size_t offset = (size_t)(insns[i].address - base_addr);
        if (check_movz_movk_bitmask(state, &insns[i], offset, &finding)) {
            report_finding(&finding, insns, count, base_addr);
            errors++;
        }
    }

    armlint_finding finding;
    if (armlint_flush(state, &finding)) {
        report_finding(&finding, insns, count, base_addr);
        errors++;
    }

    armlint_state_destroy(state);
    cs_free(insns, count);
    return errors;
}
