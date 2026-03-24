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

TEST_BEGIN(PEXTr32r32, 2)
TEST_INPUTS(
    0, 0,
    1, 0xFFFFFFFF,
    0x12345678, 0x0F0F0F0F,
    0xFFFFFFFF, 0x55555555,
    0xAAAAAAAA, 0x33333333,
    0xDEADBEEF, 0x80000001)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000100
    jz pext_nop1

    mov eax, ARG1_32
    mov ebx, ARG2_32
    pext edx, eax, ebx

pext_nop1: nop
TEST_END

TEST_BEGIN_MEM(PEXTr32m32, 2)
TEST_INPUTS(
    0, 0,
    1, 0xFFFFFFFF,
    0x12345678, 0x0F0F0F0F,
    0xFFFFFFFF, 0x55555555,
    0xAAAAAAAA, 0x33333333,
    0xDEADBEEF, 0x80000001)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000100
    jz pext_nop2

    mov eax, ARG1_32
    mov DWORD PTR [rsp - 8], ARG2_32
    pext edx, eax, DWORD PTR [rsp - 8]

pext_nop2: nop
TEST_END_MEM

TEST_BEGIN_64(PEXTr64r64, 2)
TEST_INPUTS(
    0, 0,
    1, 0xFFFFFFFFFFFFFFFF,
    0x123456789ABCDEF0, 0x0F0F0F0F0F0F0F0F,
    0xFFFFFFFFFFFFFFFF, 0x5555555555555555,
    0xAAAAAAAAAAAAAAAA, 0x3333333333333333,
    0xDEADBEEFCAFEBABE, 0x8000000000000001)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000100
    jz pext_nop3

    mov rax, ARG1_64
    mov rbx, ARG2_64
    pext rdx, rax, rbx

pext_nop3: nop
TEST_END_64

TEST_BEGIN_MEM_64(PEXTr64m64, 2)
TEST_INPUTS(
    0, 0,
    1, 0xFFFFFFFFFFFFFFFF,
    0x123456789ABCDEF0, 0x0F0F0F0F0F0F0F0F,
    0xFFFFFFFFFFFFFFFF, 0x5555555555555555,
    0xAAAAAAAAAAAAAAAA, 0x3333333333333333,
    0xDEADBEEFCAFEBABE, 0x8000000000000001)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000100
    jz pext_nop4

    mov rax, ARG1_64
    mov QWORD PTR [rsp - 8], ARG2_64
    pext rdx, rax, QWORD PTR [rsp - 8]

pext_nop4: nop
TEST_END_MEM_64
