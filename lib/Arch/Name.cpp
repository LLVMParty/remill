/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"

namespace remill {

ArchName GetArchName(const llvm::Triple &triple) {
  switch (triple.getArch()) {
    case llvm::Triple::ArchType::x86: return ArchName::kArchX86;
    case llvm::Triple::ArchType::x86_64: return ArchName::kArchAMD64;
    case llvm::Triple::ArchType::aarch64: return ArchName::kArchAArch64LittleEndian;
    case llvm::Triple::ArchType::arm: return ArchName::kArchAArch32LittleEndian;
    case llvm::Triple::ArchType::thumb: return ArchName::kArchThumb2LittleEndian;
    case llvm::Triple::sparc: return ArchName::kArchSparc32;
    case llvm::Triple::sparcv9: return ArchName::kArchSparc64;
    case llvm::Triple::ppc: return ArchName::kArchPPC;
    default: return ArchName::kArchInvalid;
  }
}

ArchName GetArchName(std::string_view arch_name) {
  if (arch_name == "x86") {
    return ArchName::kArchX86;

  } else if (arch_name == "x86_avx") {
    return ArchName::kArchX86_AVX;

  } else if (arch_name == "x86_avx512") {
    return ArchName::kArchX86_AVX512;

  } else if (arch_name == "x86_sleigh") {
    return ArchName::kArchX86_SLEIGH;

  } else if (arch_name == "amd64") {
    return ArchName::kArchAMD64;

  } else if (arch_name == "amd64_avx") {
    return ArchName::kArchAMD64_AVX;

  } else if (arch_name == "amd64_avx512") {
    return ArchName::kArchAMD64_AVX512;

  } else if (arch_name == "amd64_sleigh") {
    return ArchName::kArchAMD64_SLEIGH;

  } else if (arch_name == "aarch32") {
    return ArchName::kArchAArch32LittleEndian;

  } else if (arch_name == "thumb2") {
    return ArchName::kArchThumb2LittleEndian;
  } else if (arch_name == "aarch64") {
    return ArchName::kArchAArch64LittleEndian;

  } else if (arch_name == "sparc32") {
    return ArchName::kArchSparc32;

  } else if (arch_name == "sparc64") {
    return ArchName::kArchSparc64;

  } else if (arch_name == "sparc32_sleigh") {
    return ArchName::kArchSparc32_SLEIGH;

  } else if (arch_name == "ppc") {
    return ArchName::kArchPPC;

  } else if (arch_name == "aarch64_sleigh") {
    return ArchName::kArchAArch64LittleEndian_SLEIGH;
  } else {
    return ArchName::kArchInvalid;
  }
}

namespace {

static const std::string_view ArchName::kArchNames[] = {
    [static_cast<int>(ArchName::kArchInvalid)] = "invalid",
    [static_cast<int>(ArchName::kArchX86)] = "x86",
    [static_cast<int>(ArchName::kArchX86_AVX)] = "x86_avx",
    [static_cast<int>(ArchName::kArchX86_AVX512)] = "x86_avx512",
    [static_cast<int>(ArchName::kArchX86_SLEIGH)] = "x86_sleigh",
    [static_cast<int>(ArchName::kArchAMD64)] = "amd64",
    [static_cast<int>(ArchName::kArchAMD64_AVX)] = "amd64_avx",
    [static_cast<int>(ArchName::kArchAMD64_AVX512)] = "amd64_avx512",
    [static_cast<int>(ArchName::kArchAMD64_SLEIGH)] = "amd64_sleigh",
    [static_cast<int>(ArchName::kArchAArch32LittleEndian)] = "aarch32",
    [static_cast<int>(ArchName::kArchAArch64LittleEndian)] = "aarch64",
    [static_cast<int>(ArchName::kArchAArch64LittleEndian_SLEIGH)] = "aarch64_sleigh",
    [static_cast<int>(ArchName::kArchSparc32)] = "sparc32",
    [static_cast<int>(ArchName::kArchSparc64)] = "sparc64",
    [static_cast<int>(ArchName::kArchSparc32_SLEIGH)] = "sparc32_sleigh",
    [static_cast<int>(ArchName::kArchThumb2LittleEndian)] = "thumb2",
    [static_cast<int>(ArchName::kArchPPC)] = "ppc",
};

}  // namespace

std::string_view GetArchName(ArchName arch_name) {
  return ArchName::kArchNames[static_cast<int>(arch_name)];
}

}  // namespace remill
