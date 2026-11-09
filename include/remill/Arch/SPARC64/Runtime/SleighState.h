/*
 * Copyright (c) 2026 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

// Machine state for the Sleigh-based 64-bit SPARC (SPARC V9) architecture
// (`kArchSparc64_SLEIGH`). The registers mirror the register space of
// Ghidra's `SparcV9_64.sla`: every register that the Sleigh specification
// names (upper-cased, see `SleighLifter`) has a field here, and is listed in
// `SPARC64Arch::PopulateRegisterTable`. Registers that are not listed (the
// register-window backing store `w010`...`w737`, `s_*`, hypervisor state)
// become function-local values in the lifted code.
//
// Each register is preceded by `volatile` padding, as in the other remill
// states, so that the optimizer never merges accesses to adjacent registers.

#pragma clang diagnostic push
#pragma clang diagnostic fatal "-Wpadded"

#include "remill/Arch/Runtime/State.h"
#include "remill/Arch/Runtime/Types.h"

struct SPARC64Reg final {
  volatile uint64_t _pad;
  uint64_t qword;
} __attribute__((packed));

static_assert(16 == sizeof(SPARC64Reg), "Invalid packing of `SPARC64Reg`.");

// General purpose registers, in the order of Ghidra's register space.
struct SPARC64GPR final {
  SPARC64Reg g0, g1, g2, g3, g4, g5, g6, g7;
  SPARC64Reg o0, o1, o2, o3, o4, o5, sp, o7;
  SPARC64Reg l0, l1, l2, l3, l4, l5, l6, l7;
  SPARC64Reg i0, i1, i2, i3, i4, i5, fp, i7;
} __attribute__((packed));

static_assert(32 * 16 == sizeof(SPARC64GPR),
              "Invalid packing of `SPARC64GPR`.");

// Ancillary state registers (Ghidra's 0x1000 bank, except PC and nPC).
struct SPARC64ASR final {
  SPARC64Reg tick, y, ccr, pcr, pic, gsr, softint_set, softint_clr, softint,
      tick_cmpr, stick, stick_cmpr;
} __attribute__((packed));

// Privileged registers (Ghidra's 0x6000 bank).
struct SPARC64PrivRegs final {
  SPARC64Reg tpc1, tpc2, tpc3, tpc4;
  SPARC64Reg tnpc1, tnpc2, tnpc3, tnpc4;
  SPARC64Reg tstate1, tstate2, tstate3, tstate4;
  SPARC64Reg tt1, tt2, tt3, tt4;
  SPARC64Reg tck, tba, pstate, tl, pil, cwp, cansave, canrestore, cleanwin,
      otherwin, wstate, fq, ver, gl;
} __attribute__((packed));

// Integer and extended condition codes, the floating-point condition codes
// and other one-byte registers.
struct SPARC64Flags final {
  volatile uint8_t _0;
  uint8_t x_nf;
  volatile uint8_t _1;
  uint8_t x_zf;
  volatile uint8_t _2;
  uint8_t x_vf;
  volatile uint8_t _3;
  uint8_t x_cf;
  volatile uint8_t _4;
  uint8_t i_nf;
  volatile uint8_t _5;
  uint8_t i_zf;
  volatile uint8_t _6;
  uint8_t i_vf;
  volatile uint8_t _7;
  uint8_t i_cf;
  volatile uint8_t _8;
  uint8_t fcc0;
  volatile uint8_t _9;
  uint8_t fcc1;
  volatile uint8_t _10;
  uint8_t fcc2;
  volatile uint8_t _11;
  uint8_t fcc3;
  volatile uint8_t _12;
  uint8_t asi;
  volatile uint8_t _13;
  uint8_t fprs;
  volatile uint8_t _14;
  uint8_t didrestore;      // Fake register of the Sleigh specification.
  volatile uint8_t _15;
  uint8_t decompile_mode;  // Fake register of the Sleigh specification.
} __attribute__((packed));

static_assert(32 == sizeof(SPARC64Flags), "Invalid packing of `SPARC64Flags`.");

// Floating-point registers: `fs0`-`fs31` overlay `fq0`-`fq28`, `fd0`-`fd62`
// overlay `fq0`-`fq60` (big-endian register numbering, so `fs0` is the high
// half of `fd0`; see `SPARC64Arch::PopulateRegisterTable`).
struct alignas(16) SPARC64FPURegs final {
  vec128_t v[16];
} __attribute__((packed));

static_assert(256 == sizeof(SPARC64FPURegs),
              "Invalid packing of `SPARC64FPURegs`.");

struct alignas(16) SPARC64SleighState : public ArchState {
  SPARC64FPURegs fpreg;  // 256 bytes.
  SPARC64GPR gpr;  // 512 bytes.
  SPARC64Reg pc;
  SPARC64Reg npc;
  SPARC64ASR asr;
  SPARC64Reg fsr;
  SPARC64PrivRegs priv;
  SPARC64Flags flags;
  volatile uint64_t _0;
  volatile uint64_t _1;
};

struct State : public SPARC64SleighState {};

#pragma clang diagnostic pop
