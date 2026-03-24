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

TEST_BEGIN(SHLXr32r32, 2)
TEST_INPUTS(
    0x1, 0,
    0x1, 1,
    0x1, 8,
    0x1, 40,
    0x12345678, 4,
    0x80000000, 1)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000100
    jz shlx_nop1

    mov eax, ARG1_32
    mov ebx, ARG2_32
    shlx edx, eax, ebx

shlx_nop1: nop
TEST_END

TEST_BEGIN_MEM(SHLXr32m32, 2)
TEST_INPUTS(
    0x1, 0,
    0x1, 1,
    0x1, 8,
    0x1, 40,
    0x12345678, 4,
    0x80000000, 1)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000100
    jz shlx_nop2

    mov DWORD PTR [rsp - 8], ARG1_32
    mov ebx, ARG2_32
    shlx edx, DWORD PTR [rsp - 8], ebx

shlx_nop2: nop
TEST_END_MEM

TEST_BEGIN_64(SHLXr64r64, 2)
TEST_INPUTS(
    0x1, 0,
    0x1, 1,
    0x1, 8,
    0x1, 72,
    0x123456789ABCDEF0, 4,
    0x8000000000000000, 1)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000100
    jz shlx_nop3

    mov rax, ARG1_64
    mov rbx, ARG2_64
    shlx rdx, rax, rbx

shlx_nop3: nop
TEST_END_64

TEST_BEGIN_MEM_64(SHLXr64m64, 2)
TEST_INPUTS(
    0x1, 0,
    0x1, 1,
    0x1, 8,
    0x1, 72,
    0x123456789ABCDEF0, 4,
    0x8000000000000000, 1)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000100
    jz shlx_nop4

    mov QWORD PTR [rsp - 8], ARG1_64
    mov rbx, ARG2_64
    shlx rdx, QWORD PTR [rsp - 8], rbx

shlx_nop4: nop
TEST_END_MEM_64
