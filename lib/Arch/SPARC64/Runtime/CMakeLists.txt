# Copyright (c) 2019 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.21)
project(sparc64_runtime)

# Runtime (semantics module) of the Sleigh-based 64-bit SPARC architecture,
# `sparc64_sleigh`: it only needs to provide the `State` type, the intrinsics
# and the fallback instruction handlers, since instruction semantics come
# from Ghidra's `SparcV9_64.sla`. (The hand-written `sparc64` semantics in
# `../Semantics` depend on SPARC32 semantics files that no longer exist.)
set(SPARC64SLEIGHRUNTIME_SOURCEFILES
  SleighInstructions.cpp
  SleighBasicBlock.cpp

  "${REMILL_LIB_DIR}/Arch/Runtime/Intrinsics.cpp"
)

set_source_files_properties(SleighInstructions.cpp PROPERTIES COMPILE_FLAGS "-O3 -g0")
set_source_files_properties(SleighBasicBlock.cpp PROPERTIES COMPILE_FLAGS "-O0 -g3")

if (REMILL_BARRIER_AS_NOP)
  set(EXTRA_BC_FLAGS "-DREMILL_BARRIER_AS_NOP")
endif(REMILL_BARRIER_AS_NOP)

add_runtime(sparc64_sleigh
  SOURCES ${SPARC64SLEIGHRUNTIME_SOURCEFILES}
  ADDRESS_SIZE 64
  DEFINITIONS "LITTLE_ENDIAN=0"
  BCFLAGS "${EXTRA_BC_FLAGS}"
  INCLUDEDIRECTORIES "${REMILL_INCLUDE_DIR}" "${REMILL_SOURCE_DIR}"
  INSTALLDESTINATION "${REMILL_INSTALL_SEMANTICS_DIR}"
  ARCH sparc64

  DEPENDENCIES
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Intrinsics.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/HyperCall.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Definitions.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/SPARC64/Runtime/SleighState.h"
)
