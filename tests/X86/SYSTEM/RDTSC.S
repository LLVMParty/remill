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

TEST_BEGIN(RDTSCbasic, 1)
TEST_INPUTS(
    0,
    1,
    0x12345678,
    0xFFFFFFFF)

    rdtsc
    mov RET_32, ARG1_32
    mov edx, ARG1_32
TEST_END

TEST_BEGIN_64(RDTSCzeroExt_64, 1)
TEST_IGNORE_FLAGS(OF SF ZF AF PF CF)
TEST_INPUTS(
    0,
    1,
    0x12345678,
    0xFFFFFFFF)

    mov rax, 0xFFFFFFFFFFFFFFFF
    mov rdx, 0xFFFFFFFFFFFFFFFF
    rdtsc
    shr rax, 32
    shr rdx, 32
    mov RET_64, rax
TEST_END_64
