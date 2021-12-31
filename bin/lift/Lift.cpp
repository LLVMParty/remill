/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <httplib.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Lifter.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>
#include <remill/Version/Version.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <system_error>

DECLARE_string(arch);
DECLARE_string(os);

DEFINE_uint64(address, 0,
              "Address at which we should assume the bytes are"
              "located in virtual memory.");

DEFINE_uint64(entry_address, 0,
              "Address of instruction that should be "
              "considered the entrypoint of this code. "
              "Defaults to the value of --address.");

DEFINE_string(bytes, "", "Hex-encoded byte string to lift.");
DEFINE_string(bytes_server, "", "HTTP Server that can provide bytes.");

DEFINE_string(ir_out, "", "Path to file where the LLVM IR should be saved.");
DEFINE_string(bc_out, "",
              "Path to file where the LLVM bitcode should be "
              "saved.");

DEFINE_string(slice_inputs, "",
              "Comma-separated list of registers to treat as inputs.");
DEFINE_string(slice_outputs, "",
              "Comma-separated list of registers to treat as outputs.");

struct MemoryReader {
  virtual ~MemoryReader() = default;

  virtual bool Read(uint64_t address, void *data, size_t size,
                    size_t &read) = 0;
};

struct ServerMemoryReader : MemoryReader {
  explicit ServerMemoryReader(const char *host_port) {
    m_client = std::make_unique<httplib::Client>(host_port);
  }

  ServerMemoryReader(const ServerMemoryReader &) = delete;

  bool Read(uint64_t address, void *dst, size_t size, size_t &read) override {
    httplib::Headers headers;
    httplib::Params params = {
        {"address", std::to_string(address)},
        {"size", std::to_string(size)},
    };
    auto res = m_client->Get("/memory", params, headers);
    if (res->status != 200)
      return false;
    read = std::min(size, res->body.size());
    memcpy(dst, res->body.data(), read);
    return size == read;
  }

 private:
  std::unique_ptr<httplib::Client> m_client;
};

struct BufferMemoryReader : MemoryReader {
  BufferMemoryReader(uint64_t address, std::vector<uint8_t> data)
      : m_address(address),
        m_data(std::move(data)) {}

  bool Read(uint64_t address, void *data, size_t size, size_t &read) override {
    // TODO: this can be done smarter
    read = 0;
    auto ptr = (char *) data;
    for (size_t i = 0; i < size; ++i) {
      auto read_address = address + i;
      if (read_address >= m_address &&
          read_address < m_address + m_data.size()) {
        ptr[i] = m_data.at(m_address - read_address);
        read++;
      }
    }
    return read == size;
  }

 private:
  uint64_t m_address = 0;
  std::vector<uint8_t> m_data;
};

// Unhexlify the data passed to `--bytes`, and fill in `memory` with each
// such byte.
static std::unique_ptr<MemoryReader> UnhexlifyInputBytes(uint64_t addr_mask) {
  std::vector<uint8_t> data;
  data.reserve(FLAGS_bytes.size() / 2);

  for (size_t i = 0; i < FLAGS_bytes.size(); i += 2) {
    char nibbles[] = {FLAGS_bytes[i], FLAGS_bytes[i + 1], '\0'};
    char *parsed_to = nullptr;
    auto byte_val = strtol(nibbles, &parsed_to, 16);

    if (parsed_to != &(nibbles[2])) {
      std::cerr << "Invalid hex byte value '" << nibbles
                << "' specified in --bytes." << std::endl;
      exit(EXIT_FAILURE);
    }

    auto byte_addr = FLAGS_address + (i / 2);
    auto masked_addr = byte_addr & addr_mask;

    // Make sure that if a really big number is specified for `--address`,
    // that we don't accidentally wrap around and start filling out low
    // byte addresses.
    if (masked_addr < byte_addr) {
      std::cerr << "Too many bytes specified to --bytes, would result "
                << "in a 32-bit overflow.";
      exit(EXIT_FAILURE);

    } else if (masked_addr < FLAGS_address) {
      std::cerr << "Too many bytes specified to --bytes, would result "
                << "in a 64-bit overflow.";
      exit(EXIT_FAILURE);
    }

    data.push_back(static_cast<uint8_t>(byte_val));
  }

  return std::make_unique<BufferMemoryReader>(FLAGS_address, data);
}

struct MemoryCache {
  explicit MemoryCache(MemoryReader &reader) : m_reader(reader) {}

  bool ReadByte(uint64_t address, uint8_t &byte) {
    auto page_address = address & ~(PAGE_SIZE - 1);
    auto itr = m_cache.find(page_address);
    if (itr == m_cache.end()) {
      Page page;
      memset(page.data(), 0xCC, page.size());
      size_t read = 0;
      if (!m_reader.Read(page_address, page.data(), page.size(), read) &&
          read == 0)
        return false;
      itr = m_cache.emplace(page_address, page).first;
    }
    byte = itr->second[address - page_address];
    return true;
  }

 private:
  static constexpr uint64_t PAGE_SIZE = 0x1000;
  MemoryReader &m_reader;
  using Page = std::array<uint8_t, PAGE_SIZE>;
  std::unordered_map<uint64_t, Page> m_cache;
};

struct ScopeTimer {
  [[nodiscard]] ScopeTimer(std::string description)
      : m_description(std::move(description)) {
    m_begin = std::chrono::steady_clock::now();
  }

  ~ScopeTimer() {
    auto end = std::chrono::steady_clock::now();
    auto ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - m_begin);
    std::cout << m_description << ": " << ms.count() << "ms" << std::endl;
  }

  ScopeTimer(const ScopeTimer &) = delete;

 private:
  std::string m_description;
  std::chrono::steady_clock::time_point m_begin;
};

class SimpleTraceManager : public remill::TraceManager {
 public:
  explicit SimpleTraceManager(MemoryReader &memory_) : memory(memory_) {}

 protected:
  // Called when we have lifted, i.e. defined the contents, of a new trace.
  // The derived class is expected to do something useful with this.
  void SetLiftedTraceDefinition(uint64_t addr,
                                llvm::Function *lifted_func) override {
    traces[addr] = lifted_func;
  }

  // Get a declaration for a lifted trace. The idea here is that a derived
  // class might have additional global info available to them that lets
  // them declare traces ahead of time. In order to distinguish between
  // stuff we've lifted, and stuff we haven't lifted, we allow the lifter
  // to access "defined" vs. "declared" traces.
  //
  // NOTE: This is permitted to return a function from an arbitrary module.
  llvm::Function *GetLiftedTraceDeclaration(uint64_t addr) override {
    auto trace_it = traces.find(addr);
    if (trace_it != traces.end()) {
      return trace_it->second;
    } else {
      return nullptr;
    }
  }

  // Get a definition for a lifted trace.
  //
  // NOTE: This is permitted to return a function from an arbitrary module.
  llvm::Function *GetLiftedTraceDefinition(uint64_t addr) override {
    return GetLiftedTraceDeclaration(addr);
  }

  // Try to read an executable byte of memory. Returns `true` of the byte
  // at address `addr` is executable and readable, and updates the byte
  // pointed to by `byte` with the read value.
  bool TryReadExecutableByte(uint64_t addr, uint8_t *byte) override {
    //ScopeTimer t("Read 1 byte");
    return memory.ReadByte(addr, *byte);
  }

 public:
  MemoryCache memory;
  std::unordered_map<uint64_t, llvm::Function *> traces;
};

// Looks for calls to a function like `__remill_function_return`, and
// replace its state pointer with a null pointer so that the state
// pointer never escapes.
static void MuteStateEscape(llvm::Module *module, const char *func_name) {
  auto func = module->getFunction(func_name);
  if (!func) {
    return;
  }

  for (auto user : func->users()) {
    if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(user)) {
      auto arg_op = call_inst->getArgOperand(remill::kStatePointerArgNum);
      call_inst->setArgOperand(remill::kStatePointerArgNum,
                               llvm::UndefValue::get(arg_op->getType()));
    }
  }
}

static void SetVersion(void) {
  std::stringstream ss;
  auto vs = remill::version::GetVersionString();
  if (0 == vs.size()) {
    vs = "unknown";
  }
  ss << vs << "\n";
  if (!remill::version::HasVersionData()) {
    ss << "No extended version information found!\n";
  } else {
    ss << "Commit Hash: " << remill::version::GetCommitHash() << "\n";
    ss << "Commit Date: " << remill::version::GetCommitDate() << "\n";
    ss << "Last commit by: " << remill::version::GetAuthorName() << " ["
       << remill::version::GetAuthorEmail() << "]\n";
    ss << "Commit Subject: [" << remill::version::GetCommitSubject() << "]\n";
    ss << "\n";
    if (remill::version::HasUncommittedChanges()) {
      ss << "Uncommitted changes were present during build.\n";
    } else {
      ss << "All changes were committed prior to building.\n";
    }
  }
  google::SetVersionString(ss.str());
}

int main(int argc, char *argv[]) {
  SetVersion();
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  if (!FLAGS_bytes_server.empty()) {
    httplib::Client client(FLAGS_bytes_server.c_str());
    auto pong = client.Get("/ping");
    if (pong->status != 200) {
      std::cerr << "Failed to GET " << FLAGS_bytes_server
                << "/ping, please specify a working bytes server.\n";
      return EXIT_FAILURE;
    }
    std::cout << "Using bytes server " << FLAGS_bytes_server << " ("
              << pong->body << ")\n";
  } else if (FLAGS_bytes.empty()) {
    std::cerr
        << "Please specify a sequence of hex bytes to --bytes or use --bytes_server.\n";
    return EXIT_FAILURE;
  }

  if (FLAGS_bytes.size() % 2) {
    std::cerr << "Please specify an even number of nibbles to --bytes."
              << std::endl;
    return EXIT_FAILURE;
  }

  if (!FLAGS_entry_address) {
    FLAGS_entry_address = FLAGS_address;
  }

  // Make sure `--address` and `--entry_address` are in-bounds for the target
  // architecture's address size.
  llvm::LLVMContext context;
  auto arch = remill::Arch::Get(context, FLAGS_os, FLAGS_arch);
  const uint64_t addr_mask = ~0ULL >> (64UL - arch->address_size);
  if (FLAGS_address != (FLAGS_address & addr_mask)) {
    std::cerr << "Value " << std::hex << FLAGS_address
              << " passed to --address does not fit into 32-bits. Did mean"
              << " to specify a 64-bit architecture to --arch?" << std::endl;
    return EXIT_FAILURE;
  }

  if (FLAGS_entry_address != (FLAGS_entry_address & addr_mask)) {
    std::cerr
        << "Value " << std::hex << FLAGS_entry_address
        << " passed to --entry_address does not fit into 32-bits. Did mean"
        << " to specify a 64-bit architecture to --arch?" << std::endl;
    return EXIT_FAILURE;
  }

  std::unique_ptr<llvm::Module> module(remill::LoadArchSemantics(arch));

  const auto state_ptr_type = arch->StatePointerType();
  const auto mem_ptr_type = arch->MemoryPointerType();

  std::unique_ptr<MemoryReader> memory;
  if (!FLAGS_bytes_server.empty())
    memory = std::make_unique<ServerMemoryReader>(FLAGS_bytes_server.c_str());
  else
    memory = UnhexlifyInputBytes(addr_mask);

  SimpleTraceManager manager(*memory);
  remill::IntrinsicTable intrinsics(module);
  remill::InstructionLifter inst_lifter(arch, intrinsics);
  remill::TraceLifter trace_lifter(inst_lifter, manager);

  // Lift all discoverable traces starting from `--entry_address` into
  // `module`.
  trace_lifter.Lift(FLAGS_entry_address);

  // Optimize the module, but with a particular focus on only the functions
  // that we actually lifted.
  remill::OptimizationGuide guide = {};
  guide.eliminate_dead_stores = true;
  remill::OptimizeModule(arch, module, manager.traces, guide);

  // Create a new module in which we will move all the lifted functions. Prepare
  // the module for code of this architecture, i.e. set the data layout, triple,
  // etc.
  llvm::Module dest_module("lifted_code", context);
  arch->PrepareModuleDataLayout(&dest_module);

  llvm::Function *entry_trace = nullptr;
  const auto make_slice =
      !FLAGS_slice_inputs.empty() || !FLAGS_slice_outputs.empty();

  // Move the lifted code into a new module. This module will be much smaller
  // because it won't be bogged down with all of the semantics definitions.
  // This is a good JITing strategy: optimize the lifted code in the semantics
  // module, move it to a new module, instrument it there, then JIT compile it.
  for (auto &lifted_entry : manager.traces) {
    if (lifted_entry.first == FLAGS_entry_address) {
      entry_trace = lifted_entry.second;
    }
    remill::MoveFunctionIntoModule(lifted_entry.second, &dest_module);

    // If we are providing a prototype, then we'll be re-optimizing the new
    // module, and we want everything to get inlined.
    if (make_slice) {
      lifted_entry.second->setLinkage(llvm::GlobalValue::InternalLinkage);
      lifted_entry.second->removeFnAttr(llvm::Attribute::NoInline);
      lifted_entry.second->addFnAttr(llvm::Attribute::InlineHint);
      lifted_entry.second->addFnAttr(llvm::Attribute::AlwaysInline);
    }
  }

  // We have a prototype, so go create a function that will call our entrypoint.
  if (make_slice) {
    CHECK_NOTNULL(entry_trace);

    llvm::SmallVector<llvm::StringRef, 4> input_reg_names;
    llvm::SmallVector<llvm::StringRef, 4> output_reg_names;
    llvm::StringRef(FLAGS_slice_inputs)
        .split(input_reg_names, ',', -1, false /* KeepEmpty */);
    llvm::StringRef(FLAGS_slice_outputs)
        .split(output_reg_names, ',', -1, false /* KeepEmpty */);

    CHECK(!(input_reg_names.empty() && output_reg_names.empty()))
        << "Empty lists passed to both --slice_inputs and --slice_outputs";

    // Use the registers to build a function prototype.
    llvm::SmallVector<llvm::Type *, 8> arg_types;
    arg_types.push_back(mem_ptr_type);

    for (auto &reg_name : input_reg_names) {
      const auto reg = arch->RegisterByName(reg_name.str());
      CHECK(reg != nullptr)
          << "Invalid register name '" << reg_name.str()
          << "' used in input slice list '" << FLAGS_slice_inputs << "'";

      arg_types.push_back(reg->type);
    }

    const auto first_output_reg_index = arg_types.size();

    // Outputs are "returned" by pointer through arguments.
    for (auto &reg_name : output_reg_names) {
      const auto reg = arch->RegisterByName(reg_name.str());
      CHECK(reg != nullptr)
          << "Invalid register name '" << reg_name.str()
          << "' used in output slice list '" << FLAGS_slice_outputs << "'";

      arg_types.push_back(llvm::PointerType::get(reg->type, 0));
    }

    const auto state_type = state_ptr_type->getPointerElementType();
    const auto func_type =
        llvm::FunctionType::get(mem_ptr_type, arg_types, false);
    const auto func = llvm::Function::Create(
        func_type, llvm::GlobalValue::ExternalLinkage, "slice", &dest_module);

    // Store all of the function arguments (corresponding with specific registers)
    // into the stack-allocated `State` structure.
    auto entry = llvm::BasicBlock::Create(context, "", func);
    llvm::IRBuilder<> ir(entry);

    const auto state_ptr = ir.CreateAlloca(state_type);

    const remill::Register *pc_reg =
        arch->RegisterByName(arch->ProgramCounterRegisterName());

    CHECK(pc_reg != nullptr)
        << "Could not find the register in the state structure "
        << "associated with the program counter.";

    // Store the program counter into the state.
    const auto pc_reg_ptr = pc_reg->AddressOf(state_ptr, entry);
    const auto trace_pc =
        llvm::ConstantInt::get(pc_reg->type, FLAGS_entry_address, false);
    ir.SetInsertPoint(entry);
    ir.CreateStore(trace_pc, pc_reg_ptr);

    auto args_it = func->arg_begin();
    for (auto &reg_name : input_reg_names) {
      const auto reg = arch->RegisterByName(reg_name.str());
      auto &arg = *++args_it;  // Pre-increment, as first arg is memory pointer.
      arg.setName(reg_name);
      CHECK_EQ(arg.getType(), reg->type);
      auto reg_ptr = reg->AddressOf(state_ptr, entry);
      ir.SetInsertPoint(entry);
      ir.CreateStore(&arg, reg_ptr);
    }

    llvm::Value *mem_ptr = &*func->arg_begin();

    llvm::Value *trace_args[remill::kNumBlockArgs] = {};
    trace_args[remill::kStatePointerArgNum] = state_ptr;
    trace_args[remill::kMemoryPointerArgNum] = mem_ptr;
    trace_args[remill::kPCArgNum] = trace_pc;

    mem_ptr = ir.CreateCall(entry_trace, trace_args);

    // Go read all output registers out of the state and store them
    // into the output parameters.
    args_it = func->arg_begin();
    for (size_t i = 0, j = 0; i < func->arg_size(); ++i, ++args_it) {
      if (i < first_output_reg_index) {
        continue;
      }

      const auto &reg_name = output_reg_names[j++];
      const auto reg = arch->RegisterByName(reg_name.str());
      auto &arg = *args_it;
      arg.setName(reg_name + "_output");

      auto reg_ptr = reg->AddressOf(state_ptr, entry);
      ir.SetInsertPoint(entry);
      ir.CreateStore(ir.CreateLoad(reg_ptr), &arg);
    }

    // Return the memory pointer, so that all memory accesses are
    // preserved.
    ir.CreateRet(mem_ptr);

    // We want the stack-allocated `State` to be subject to scalarization
    // and mem2reg, but to "encourage" that, we need to prevent the
    // `alloca`d `State` from escaping.
    MuteStateEscape(&dest_module, "__remill_error");
    MuteStateEscape(&dest_module, "__remill_function_call");
    MuteStateEscape(&dest_module, "__remill_function_return");
    MuteStateEscape(&dest_module, "__remill_jump");
    MuteStateEscape(&dest_module, "__remill_missing_block");

    guide.slp_vectorize = true;
    guide.loop_vectorize = true;
    guide.eliminate_dead_stores = false;
    remill::OptimizeBareModule(&dest_module, guide);
  }

  int ret = EXIT_SUCCESS;

  if (!FLAGS_ir_out.empty()) {
    if (!remill::StoreModuleIRToFile(&dest_module, FLAGS_ir_out, true)) {
      LOG(ERROR) << "Could not save LLVM IR to " << FLAGS_ir_out;
      ret = EXIT_FAILURE;
    }
  }
  if (!FLAGS_bc_out.empty()) {
    if (!remill::StoreModuleToFile(&dest_module, FLAGS_bc_out, true)) {
      LOG(ERROR) << "Could not save LLVM bitcode to " << FLAGS_bc_out;
      ret = EXIT_FAILURE;
    }
  }

  return ret;
}
