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

TEST_BEGIN(BEXTRr32r32, 2)
TEST_IGNORE_FLAGS(AF PF SF)
TEST_INPUTS(
    0x12345678, 0x0000,
    0x12345678, 0x0804,
    0x12345678, 0x0408,
    0xFFFFFFFF, 0x2000,
    0x80000000, 0x2000,
    0x0000FFFF, 0x1008,
    0xDEADBEEF, 0x4000)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000008
    jz bextr_nop1

    mov eax, ARG1_32
    mov ebx, ARG2_32
    bextr edx, eax, ebx

bextr_nop1: nop
TEST_END

TEST_BEGIN_MEM(BEXTRr32m32, 2)
TEST_IGNORE_FLAGS(AF PF SF)
TEST_INPUTS(
    0x12345678, 0x0000,
    0x12345678, 0x0804,
    0x12345678, 0x0408,
    0xFFFFFFFF, 0x2000,
    0x80000000, 0x2000,
    0x0000FFFF, 0x1008,
    0xDEADBEEF, 0x4000)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000008
    jz bextr_nop2

    mov DWORD PTR [rsp - 8], ARG1_32
    mov ebx, ARG2_32
    bextr edx, DWORD PTR [rsp - 8], ebx

bextr_nop2: nop
TEST_END_MEM

TEST_BEGIN_64(BEXTRr64r64, 2)
TEST_IGNORE_FLAGS(AF PF SF)
TEST_INPUTS(
    0x123456789ABCDEF0, 0x0000,
    0x123456789ABCDEF0, 0x0804,
    0x123456789ABCDEF0, 0x1010,
    0xFFFFFFFFFFFFFFFF, 0x4000,
    0x8000000000000000, 0x4000,
    0x00000000FFFFFFFF, 0x2010,
    0xDEADBEEFCAFEBABE, 0x8000)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000008
    jz bextr_nop3

    mov rax, ARG1_64
    mov rbx, ARG2_64
    bextr rdx, rax, rbx

bextr_nop3: nop
TEST_END_64

TEST_BEGIN_MEM_64(BEXTRr64m64, 2)
TEST_IGNORE_FLAGS(AF PF SF)
TEST_INPUTS(
    0x123456789ABCDEF0, 0x0000,
    0x123456789ABCDEF0, 0x0804,
    0x123456789ABCDEF0, 0x1010,
    0xFFFFFFFFFFFFFFFF, 0x4000,
    0x8000000000000000, 0x4000,
    0x00000000FFFFFFFF, 0x2010,
    0xDEADBEEFCAFEBABE, 0x8000)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000008
    jz bextr_nop4

    mov QWORD PTR [rsp - 8], ARG1_64
    mov rbx, ARG2_64
    bextr rdx, QWORD PTR [rsp - 8], rbx

bextr_nop4: nop
TEST_END_MEM_64
