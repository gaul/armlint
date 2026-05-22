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

// Findings reported by check functions. start_offset is the offset of
// the first instruction of the suboptimal run; insn_count is its length.
// detail is a short summary (e.g. the constructed constant, or the
// suggested folded instruction) shown in the header. lines[] holds the
// disassembled offending instructions, one per line; unused slots are
// empty strings.
//
// Checks own the formatting of their detail and lines so that reporting
// does not need to retain the original cs_insn array (cs_disasm_iter
// recycles a single cs_insn slot).
#define ARMLINT_FINDING_LINES      4
#define ARMLINT_FINDING_LINE_LEN   96
#define ARMLINT_FINDING_DETAIL_LEN 128

typedef struct {
    const char *name;
    size_t start_offset;
    unsigned insn_count;
    char detail[ARMLINT_FINDING_DETAIL_LEN];
    char lines[ARMLINT_FINDING_LINES][ARMLINT_FINDING_LINE_LEN];
} armlint_finding;

// Examine insn (already decoded by Capstone) in the context of recent
// instructions. Returns true if a finding is produced (in *out); false
// otherwise. May produce a finding when a non-matching instruction
// closes a previously open sequence, so callers must invoke
// armlint_flush after the last instruction of a region to catch a
// trailing sequence.
bool check_movz_movk_bitmask(armlint_state *state, const cs_insn *insn,
                             size_t offset, armlint_finding *out);

// Detect an LSL (immediate) immediately followed by an arithmetic or
// logical shifted-register op that consumes the LSL's destination as
// its Rm, with the consumer overwriting that register. The pair can be
// replaced by a single shifted-register form.
bool check_lsl_fold(armlint_state *state, const cs_insn *insn,
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
