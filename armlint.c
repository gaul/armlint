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
    armlint_mov_entry entries[ARMLINT_MOV_MAX];
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
            memcpy(out->entries, state->entries, sizeof(out->entries));
            produced = true;
        }
    }

    state->active = false;
    return produced;
}

static void record_entry(armlint_state *state, unsigned opc,
                         unsigned imm16, unsigned hw)
{
    if (state->insn_count > ARMLINT_MOV_MAX) {
        // The longest legal chain is MOVZ + 3 MOVKs in 64-bit. We could
        // overflow if a malformed sequence (e.g. multiple MOVKs at the
        // same shift) lands in the same destination beyond that bound;
        // drop the entry rather than write past the array.
        return;
    }
    unsigned slot = state->insn_count - 1;
    if (slot >= ARMLINT_MOV_MAX) {
        return;
    }
    state->entries[slot].opc = (uint8_t)opc;
    state->entries[slot].imm16 = (uint16_t)imm16;
    state->entries[slot].shift_div_16 = (uint8_t)hw;
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
            record_entry(state, opc, imm16, hw);
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
    record_entry(state, opc, imm16, hw);

    return produced;
}

static void report_finding(const armlint_finding *finding)
{
    printf("%s at offset: 0x%zx: %c%u = 0x%" PRIx64 " (%u instructions)\n",
        finding->name, finding->start_offset,
        finding->reg_width == 32 ? 'w' : 'x',
        finding->rd, finding->value, finding->insn_count);

    char w_or_x = finding->reg_width == 32 ? 'w' : 'x';
    unsigned n = finding->insn_count;
    if (n > ARMLINT_MOV_MAX) {
        n = ARMLINT_MOV_MAX;
    }
    for (unsigned i = 0; i < n; i++) {
        const armlint_mov_entry *e = &finding->entries[i];
        const char *mnem = e->opc == 2 ? "movz"
                       : (e->opc == 0 ? "movn" : "movk");
        unsigned shift = (unsigned)e->shift_div_16 * 16;
        if (shift == 0) {
            printf("  %s %c%u, #0x%x\n", mnem, w_or_x, finding->rd, e->imm16);
        } else {
            printf("  %s %c%u, #0x%x, lsl #%u\n",
                mnem, w_or_x, finding->rd, e->imm16, shift);
        }
    }
    printf("\n");
}

// Stream the byte buffer one instruction at a time. cs_disasm would
// require allocating a cs_insn for every instruction up front (5+ GB on
// a 100 MB text section) and silently stops at the first undecodable
// 4-byte slot. cs_disasm_iter recycles a single cs_insn and lets us
// skip past data-in-text by hand.
int check_instructions(csh handle, const uint8_t *inst, size_t len,
                       uint64_t base_addr)
{
    armlint_state *state = armlint_state_create();
    if (state == NULL) {
        return -1;
    }
    cs_insn *insn = cs_malloc(handle);
    if (insn == NULL) {
        armlint_state_destroy(state);
        return -1;
    }

    int errors = 0;
    const uint8_t *code = inst;
    size_t size = len;
    uint64_t address = base_addr;

    while (size >= 4) {
        uint64_t insn_addr = address;
        if (cs_disasm_iter(handle, &code, &size, &address, insn)) {
            armlint_finding finding;
            size_t offset = (size_t)(insn_addr - base_addr);
            if (check_movz_movk_bitmask(state, insn, offset, &finding)) {
                report_finding(&finding);
                errors++;
            }
        } else {
            // Treat the slot as opaque data and skip a single A64
            // word. Flush first so an in-progress MOV sequence cannot
            // straddle the gap.
            armlint_finding finding;
            if (armlint_flush(state, &finding)) {
                report_finding(&finding);
                errors++;
            }
            code += 4;
            size -= 4;
            address += 4;
        }
    }

    armlint_finding finding;
    if (armlint_flush(state, &finding)) {
        report_finding(&finding);
        errors++;
    }

    cs_free(insn, 1);
    armlint_state_destroy(state);
    return errors;
}
