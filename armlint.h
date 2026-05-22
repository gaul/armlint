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

#ifndef ARMLINT_H
#define ARMLINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <capstone/capstone.h>

// Pure predicate: true iff imm is encodable as an AArch64 logical
// (bitmask) immediate at the given register width (32 or 64).
//
// Exposed for direct testing. The encoding excludes 0 and the
// all-ones value at the given width.
bool is_bitmask_immediate(uint64_t imm, unsigned reg_width);

// State carried across instructions for sequence-based checks. Owned by
// the caller; created once per scan and reset between non-contiguous
// regions (e.g. between executable sections).
typedef struct armlint_state armlint_state;

armlint_state *armlint_state_create(void);
void armlint_state_destroy(armlint_state *state);
void armlint_state_reset(armlint_state *state);

// A single MOVZ / MOVN / MOVK in a recorded sequence. We carry these
// in findings so reporting does not depend on the cs_insn array still
// being alive when the finding is emitted (cs_disasm_iter recycles a
// single cs_insn slot).
#define ARMLINT_MOV_MAX 4

typedef struct {
    uint16_t imm16;
    uint8_t  shift_div_16;     // 0..3 (shift = 0/16/32/48)
    uint8_t  opc;              // 0=MOVN, 2=MOVZ, 3=MOVK
} armlint_mov_entry;

// Findings reported by check functions. start_offset is the offset of
// the first instruction of the suboptimal run; insn_count is its length.
typedef struct {
    const char *name;
    size_t start_offset;
    unsigned insn_count;
    uint64_t value;
    unsigned reg_width;
    unsigned rd;
    armlint_mov_entry entries[ARMLINT_MOV_MAX];
} armlint_finding;

// Examine insn (already decoded by Capstone) in the context of recent
// instructions. Returns true if a finding is produced (in *out); false
// otherwise. May produce a finding when a non-matching instruction
// closes a previously open sequence, so callers must invoke
// armlint_flush after the last instruction of a region to catch a
// trailing sequence.
bool check_movz_movk_bitmask(armlint_state *state, const cs_insn *insn,
                             size_t offset, armlint_finding *out);

// Close any open sequence at end-of-region. Returns true and fills *out
// if the closed sequence is reportable.
bool armlint_flush(armlint_state *state, armlint_finding *out);

// Top-level driver: disassemble inst[0..len) at base_addr, run all
// checks, print findings to stdout, return the number of findings (or
// -1 on a decoding error).
int check_instructions(csh handle, const uint8_t *inst, size_t len,
                       uint64_t base_addr);

#endif
