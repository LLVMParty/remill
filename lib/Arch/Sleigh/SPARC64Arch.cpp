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

#include "SPARC64Arch.h"

#include <glog/logging.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/InstructionLifter.h>
#include <remill/BC/Util.h>

// clang-format off
#include <remill/Arch/SPARC64/Runtime/SleighState.h>
// clang-format on

namespace remill {

// `DECOMPILE_MODE` is a fake register of Ghidra's SPARC specification. When
// it is 1 (its value in `SparcV9.pspec`), `save` and `restore` only move the
// in/out registers instead of also spilling and filling the register-window
// backing store through computed register-space addresses (which remill would
// lift as memory accesses). It is therefore provided as a decoding-context
// value of 1 rather than as a `State` register.
static constexpr const char *kDecompileModeReg = "DECOMPILE_MODE";

SleighSPARC64Decoder::SleighSPARC64Decoder(const remill::Arch &arch)
    : SleighDecoder(arch, "SparcV9_64.sla", "SparcV9.pspec",
                    sleigh::ContextRegMappings(
                        {{kDecompileModeReg, kDecompileModeReg}},
                        {{kDecompileModeReg, 1}}),
                    {}) {}

void SleighSPARC64Decoder::InitializeSleighContext(
    uint64_t, remill::sleigh::SingleInstructionSleighContext &,
    const ContextValues &) const {}

llvm::Value *SleighSPARC64Decoder::LiftPcFromCurrPc(
    llvm::IRBuilder<> &bldr, llvm::Value *curr_pc, size_t,
    const DecodingContext &) const {

  // Ghidra's SPARC specification reads `inst_start` for the PC.
  return curr_pc;
}

SPARC64Arch::SPARC64Arch(llvm::LLVMContext *context_, OSName os_name_,
                         ArchName arch_name_)
    : ArchBase(context_, os_name_, arch_name_),
      decoder(*this) {}

SPARC64Arch::~SPARC64Arch(void) {}

std::string_view SPARC64Arch::StackPointerRegisterName(void) const {
  return "SP";
}

std::string_view SPARC64Arch::ProgramCounterRegisterName(void) const {
  return "PC";
}

uint64_t SPARC64Arch::MinInstructionAlign(const DecodingContext &) const {
  return 4;
}

uint64_t SPARC64Arch::MinInstructionSize(const DecodingContext &) const {
  return 4;
}

// A delayed control transfer is decoded together with its delay slot.
uint64_t SPARC64Arch::MaxInstructionSize(const DecodingContext &,
                                         bool) const {
  return 8;
}

llvm::CallingConv::ID SPARC64Arch::DefaultCallingConv(void) const {
  return llvm::CallingConv::C;
}

llvm::Triple SPARC64Arch::Triple(void) const {
  auto triple = BasicTriple();
  triple.setArch(llvm::Triple::sparcv9);
  return triple;
}

llvm::DataLayout SPARC64Arch::DataLayout(void) const {
  return llvm::DataLayout("E-m:e-i64:64-n32:64-S128");
}

bool SPARC64Arch::MemoryAccessIsLittleEndian(void) const {
  return false;
}

bool SPARC64Arch::MayHaveDelaySlot(const Instruction &) const {
  return false;
}

bool SPARC64Arch::NextInstructionIsDelayed(const Instruction &,
                                           const Instruction &, bool) const {
  return false;
}

// Populate the table of register information. The names are the upper-cased
// names of Ghidra's `SparcV9_64.sla` registers.
void SPARC64Arch::PopulateRegisterTable(void) const {
  reg_by_offset.resize(sizeof(SPARC64SleighState));

  auto u8 = llvm::Type::getInt8Ty(*context);
  auto u64 = llvm::Type::getInt64Ty(*context);
  auto u128 = llvm::Type::getInt128Ty(*context);
  auto f32 = llvm::Type::getFloatTy(*context);
  auto f64 = llvm::Type::getDoubleTy(*context);

  SPARC64SleighState state;

#define OFFSET_OF(access) \
  (reinterpret_cast<uintptr_t>(&state.access) - \
   reinterpret_cast<uintptr_t>(&state))

#define REG(name, access, type) \
  AddRegister(#name, type, OFFSET_OF(access), nullptr)

#define SUB_REG(name, access, type, parent_reg_name) \
  AddRegister(#name, type, OFFSET_OF(access), #parent_reg_name)

  REG(PC, pc.qword, u64);
  REG(NPC, npc.qword, u64);
  REG(G0, gpr.g0.qword, u64);
  REG(G1, gpr.g1.qword, u64);
  REG(G2, gpr.g2.qword, u64);
  REG(G3, gpr.g3.qword, u64);
  REG(G4, gpr.g4.qword, u64);
  REG(G5, gpr.g5.qword, u64);
  REG(G6, gpr.g6.qword, u64);
  REG(G7, gpr.g7.qword, u64);
  REG(O0, gpr.o0.qword, u64);
  REG(O1, gpr.o1.qword, u64);
  REG(O2, gpr.o2.qword, u64);
  REG(O3, gpr.o3.qword, u64);
  REG(O4, gpr.o4.qword, u64);
  REG(O5, gpr.o5.qword, u64);
  REG(SP, gpr.sp.qword, u64);
  REG(O7, gpr.o7.qword, u64);
  REG(L0, gpr.l0.qword, u64);
  REG(L1, gpr.l1.qword, u64);
  REG(L2, gpr.l2.qword, u64);
  REG(L3, gpr.l3.qword, u64);
  REG(L4, gpr.l4.qword, u64);
  REG(L5, gpr.l5.qword, u64);
  REG(L6, gpr.l6.qword, u64);
  REG(L7, gpr.l7.qword, u64);
  REG(I0, gpr.i0.qword, u64);
  REG(I1, gpr.i1.qword, u64);
  REG(I2, gpr.i2.qword, u64);
  REG(I3, gpr.i3.qword, u64);
  REG(I4, gpr.i4.qword, u64);
  REG(I5, gpr.i5.qword, u64);
  REG(FP, gpr.fp.qword, u64);
  REG(I7, gpr.i7.qword, u64);
  REG(TICK, asr.tick.qword, u64);
  REG(Y, asr.y.qword, u64);
  REG(CCR, asr.ccr.qword, u64);
  REG(PCR, asr.pcr.qword, u64);
  REG(PIC, asr.pic.qword, u64);
  REG(GSR, asr.gsr.qword, u64);
  REG(SOFTINT_SET, asr.softint_set.qword, u64);
  REG(SOFTINT_CLR, asr.softint_clr.qword, u64);
  REG(SOFTINT, asr.softint.qword, u64);
  REG(TICK_CMPR, asr.tick_cmpr.qword, u64);
  REG(STICK, asr.stick.qword, u64);
  REG(STICK_CMPR, asr.stick_cmpr.qword, u64);
  REG(FSR, fsr.qword, u64);
  REG(TPC1, priv.tpc1.qword, u64);
  REG(TPC2, priv.tpc2.qword, u64);
  REG(TPC3, priv.tpc3.qword, u64);
  REG(TPC4, priv.tpc4.qword, u64);
  REG(TNPC1, priv.tnpc1.qword, u64);
  REG(TNPC2, priv.tnpc2.qword, u64);
  REG(TNPC3, priv.tnpc3.qword, u64);
  REG(TNPC4, priv.tnpc4.qword, u64);
  REG(TSTATE1, priv.tstate1.qword, u64);
  REG(TSTATE2, priv.tstate2.qword, u64);
  REG(TSTATE3, priv.tstate3.qword, u64);
  REG(TSTATE4, priv.tstate4.qword, u64);
  REG(TT1, priv.tt1.qword, u64);
  REG(TT2, priv.tt2.qword, u64);
  REG(TT3, priv.tt3.qword, u64);
  REG(TT4, priv.tt4.qword, u64);
  REG(TCK, priv.tck.qword, u64);
  REG(TBA, priv.tba.qword, u64);
  REG(PSTATE, priv.pstate.qword, u64);
  REG(TL, priv.tl.qword, u64);
  REG(PIL, priv.pil.qword, u64);
  REG(CWP, priv.cwp.qword, u64);
  REG(CANSAVE, priv.cansave.qword, u64);
  REG(CANRESTORE, priv.canrestore.qword, u64);
  REG(CLEANWIN, priv.cleanwin.qword, u64);
  REG(OTHERWIN, priv.otherwin.qword, u64);
  REG(WSTATE, priv.wstate.qword, u64);
  REG(FQ, priv.fq.qword, u64);
  REG(VER, priv.ver.qword, u64);
  REG(GL, priv.gl.qword, u64);
  REG(X_NF, flags.x_nf, u8);
  REG(X_ZF, flags.x_zf, u8);
  REG(X_VF, flags.x_vf, u8);
  REG(X_CF, flags.x_cf, u8);
  REG(I_NF, flags.i_nf, u8);
  REG(I_ZF, flags.i_zf, u8);
  REG(I_VF, flags.i_vf, u8);
  REG(I_CF, flags.i_cf, u8);
  REG(FCC0, flags.fcc0, u8);
  REG(FCC1, flags.fcc1, u8);
  REG(FCC2, flags.fcc2, u8);
  REG(FCC3, flags.fcc3, u8);
  REG(ASI, flags.asi, u8);
  REG(FPRS, flags.fprs, u8);
  REG(DIDRESTORE, flags.didrestore, u8);
  REG(FQ0, fpreg.v[0], u128);
  REG(FQ4, fpreg.v[1], u128);
  REG(FQ8, fpreg.v[2], u128);
  REG(FQ12, fpreg.v[3], u128);
  REG(FQ16, fpreg.v[4], u128);
  REG(FQ20, fpreg.v[5], u128);
  REG(FQ24, fpreg.v[6], u128);
  REG(FQ28, fpreg.v[7], u128);
  REG(FQ32, fpreg.v[8], u128);
  REG(FQ36, fpreg.v[9], u128);
  REG(FQ40, fpreg.v[10], u128);
  REG(FQ44, fpreg.v[11], u128);
  REG(FQ48, fpreg.v[12], u128);
  REG(FQ52, fpreg.v[13], u128);
  REG(FQ56, fpreg.v[14], u128);
  REG(FQ60, fpreg.v[15], u128);
  SUB_REG(FD0, fpreg.v[0].doubles.elems[1], f64, FQ0);
  SUB_REG(FD2, fpreg.v[0].doubles.elems[0], f64, FQ0);
  SUB_REG(FD4, fpreg.v[1].doubles.elems[1], f64, FQ4);
  SUB_REG(FD6, fpreg.v[1].doubles.elems[0], f64, FQ4);
  SUB_REG(FD8, fpreg.v[2].doubles.elems[1], f64, FQ8);
  SUB_REG(FD10, fpreg.v[2].doubles.elems[0], f64, FQ8);
  SUB_REG(FD12, fpreg.v[3].doubles.elems[1], f64, FQ12);
  SUB_REG(FD14, fpreg.v[3].doubles.elems[0], f64, FQ12);
  SUB_REG(FD16, fpreg.v[4].doubles.elems[1], f64, FQ16);
  SUB_REG(FD18, fpreg.v[4].doubles.elems[0], f64, FQ16);
  SUB_REG(FD20, fpreg.v[5].doubles.elems[1], f64, FQ20);
  SUB_REG(FD22, fpreg.v[5].doubles.elems[0], f64, FQ20);
  SUB_REG(FD24, fpreg.v[6].doubles.elems[1], f64, FQ24);
  SUB_REG(FD26, fpreg.v[6].doubles.elems[0], f64, FQ24);
  SUB_REG(FD28, fpreg.v[7].doubles.elems[1], f64, FQ28);
  SUB_REG(FD30, fpreg.v[7].doubles.elems[0], f64, FQ28);
  SUB_REG(FD32, fpreg.v[8].doubles.elems[1], f64, FQ32);
  SUB_REG(FD34, fpreg.v[8].doubles.elems[0], f64, FQ32);
  SUB_REG(FD36, fpreg.v[9].doubles.elems[1], f64, FQ36);
  SUB_REG(FD38, fpreg.v[9].doubles.elems[0], f64, FQ36);
  SUB_REG(FD40, fpreg.v[10].doubles.elems[1], f64, FQ40);
  SUB_REG(FD42, fpreg.v[10].doubles.elems[0], f64, FQ40);
  SUB_REG(FD44, fpreg.v[11].doubles.elems[1], f64, FQ44);
  SUB_REG(FD46, fpreg.v[11].doubles.elems[0], f64, FQ44);
  SUB_REG(FD48, fpreg.v[12].doubles.elems[1], f64, FQ48);
  SUB_REG(FD50, fpreg.v[12].doubles.elems[0], f64, FQ48);
  SUB_REG(FD52, fpreg.v[13].doubles.elems[1], f64, FQ52);
  SUB_REG(FD54, fpreg.v[13].doubles.elems[0], f64, FQ52);
  SUB_REG(FD56, fpreg.v[14].doubles.elems[1], f64, FQ56);
  SUB_REG(FD58, fpreg.v[14].doubles.elems[0], f64, FQ56);
  SUB_REG(FD60, fpreg.v[15].doubles.elems[1], f64, FQ60);
  SUB_REG(FD62, fpreg.v[15].doubles.elems[0], f64, FQ60);
  SUB_REG(FS0, fpreg.v[0].floats.elems[3], f32, FD0);
  SUB_REG(FS1, fpreg.v[0].floats.elems[2], f32, FD0);
  SUB_REG(FS2, fpreg.v[0].floats.elems[1], f32, FD2);
  SUB_REG(FS3, fpreg.v[0].floats.elems[0], f32, FD2);
  SUB_REG(FS4, fpreg.v[1].floats.elems[3], f32, FD4);
  SUB_REG(FS5, fpreg.v[1].floats.elems[2], f32, FD4);
  SUB_REG(FS6, fpreg.v[1].floats.elems[1], f32, FD6);
  SUB_REG(FS7, fpreg.v[1].floats.elems[0], f32, FD6);
  SUB_REG(FS8, fpreg.v[2].floats.elems[3], f32, FD8);
  SUB_REG(FS9, fpreg.v[2].floats.elems[2], f32, FD8);
  SUB_REG(FS10, fpreg.v[2].floats.elems[1], f32, FD10);
  SUB_REG(FS11, fpreg.v[2].floats.elems[0], f32, FD10);
  SUB_REG(FS12, fpreg.v[3].floats.elems[3], f32, FD12);
  SUB_REG(FS13, fpreg.v[3].floats.elems[2], f32, FD12);
  SUB_REG(FS14, fpreg.v[3].floats.elems[1], f32, FD14);
  SUB_REG(FS15, fpreg.v[3].floats.elems[0], f32, FD14);
  SUB_REG(FS16, fpreg.v[4].floats.elems[3], f32, FD16);
  SUB_REG(FS17, fpreg.v[4].floats.elems[2], f32, FD16);
  SUB_REG(FS18, fpreg.v[4].floats.elems[1], f32, FD18);
  SUB_REG(FS19, fpreg.v[4].floats.elems[0], f32, FD18);
  SUB_REG(FS20, fpreg.v[5].floats.elems[3], f32, FD20);
  SUB_REG(FS21, fpreg.v[5].floats.elems[2], f32, FD20);
  SUB_REG(FS22, fpreg.v[5].floats.elems[1], f32, FD22);
  SUB_REG(FS23, fpreg.v[5].floats.elems[0], f32, FD22);
  SUB_REG(FS24, fpreg.v[6].floats.elems[3], f32, FD24);
  SUB_REG(FS25, fpreg.v[6].floats.elems[2], f32, FD24);
  SUB_REG(FS26, fpreg.v[6].floats.elems[1], f32, FD26);
  SUB_REG(FS27, fpreg.v[6].floats.elems[0], f32, FD26);
  SUB_REG(FS28, fpreg.v[7].floats.elems[3], f32, FD28);
  SUB_REG(FS29, fpreg.v[7].floats.elems[2], f32, FD28);
  SUB_REG(FS30, fpreg.v[7].floats.elems[1], f32, FD30);
  SUB_REG(FS31, fpreg.v[7].floats.elems[0], f32, FD30);

#undef SUB_REG
#undef REG
#undef OFFSET_OF
}

// Populate a just-initialized lifted function function with architecture-
// specific variables.
void SPARC64Arch::FinishLiftedFunctionInitialization(
    llvm::Module *module, llvm::Function *bb_func) const {
  auto &context = module->getContext();
  auto addr = llvm::Type::getIntNTy(context, address_size);

  const auto entry_block = &bb_func->getEntryBlock();
  llvm::IRBuilder<> ir(entry_block);

  const auto pc_arg = NthArgument(bb_func, kPCArgNum);
  const auto state_ptr_arg = NthArgument(bb_func, kStatePointerArgNum);

  ir.CreateStore(pc_arg,
                 ir.CreateAlloca(addr, nullptr, kNextPCVariableName.data()));
  ir.CreateStore(
      pc_arg, ir.CreateAlloca(addr, nullptr, kIgnoreNextPCVariableName.data()));

  ir.CreateStore(pc_arg,
                 RegisterByName(kPCVariableName)->AddressOf(state_ptr_arg, ir),
                 false);
}

DecodingContext SPARC64Arch::CreateInitialContext(void) const {
  return DecodingContext({{kDecompileModeReg, 1u}});
}

OperandLifter::OpLifterPtr SPARC64Arch::DefaultLifter(
    const remill::IntrinsicTable &intrinsics_table) const {
  return std::make_shared<InstructionLifter>(this, intrinsics_table);
}

bool SPARC64Arch::DecodeInstruction(uint64_t address,
                                    std::string_view inst_bytes,
                                    Instruction &inst,
                                    DecodingContext context) const {
  inst.pc = address;
  inst.next_pc = address + inst_bytes.size();  // Default fall-through.
  inst.branch_taken_pc = 0;
  inst.branch_not_taken_pc = 0;
  inst.has_branch_taken_delay_slot = false;
  inst.has_branch_not_taken_delay_slot = false;
  inst.arch_name = arch_name;
  inst.sub_arch_name = arch_name;
  inst.branch_taken_arch_name = arch_name;
  inst.arch = this;
  inst.category = Instruction::kCategoryInvalid;
  inst.operands.clear();
  inst.flows = Instruction::InvalidInsn();

  return this->decoder.DecodeInstruction(address, inst_bytes, inst, context);
}

Arch::ArchPtr Arch::GetSPARC64Sleigh(llvm::LLVMContext *context_,
                                     OSName os_name_, ArchName arch_name_) {
  return std::make_unique<SPARC64Arch>(context_, os_name_, arch_name_);
}

}  // namespace remill
