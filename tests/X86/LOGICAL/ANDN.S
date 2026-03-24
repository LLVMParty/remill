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

TEST_BEGIN(ANDNr32r32, 2)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0, 0,
    0xFFFFFFFF, 0,
    0, 0xFFFFFFFF,
    0x12345678, 0x0F0F0F0F,
    0x80000000, 0xFFFFFFFF,
    0xAAAAAAAA, 0x55555555)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000008
    jz andn_nop1

    mov eax, ARG1_32
    mov ebx, ARG2_32
    andn edx, eax, ebx

andn_nop1: nop
TEST_END

TEST_BEGIN_MEM(ANDNr32m32, 2)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0, 0,
    0xFFFFFFFF, 0,
    0, 0xFFFFFFFF,
    0x12345678, 0x0F0F0F0F,
    0x80000000, 0xFFFFFFFF,
    0xAAAAAAAA, 0x55555555)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000008
    jz andn_nop2

    mov eax, ARG1_32
    mov DWORD PTR [rsp - 8], ARG2_32
    andn edx, eax, DWORD PTR [rsp - 8]

andn_nop2: nop
TEST_END_MEM

TEST_BEGIN_64(ANDNr64r64, 2)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0, 0,
    0xFFFFFFFFFFFFFFFF, 0,
    0, 0xFFFFFFFFFFFFFFFF,
    0x123456789ABCDEF0, 0x0F0F0F0F0F0F0F0F,
    0x8000000000000000, 0xFFFFFFFFFFFFFFFF,
    0xAAAAAAAAAAAAAAAA, 0x5555555555555555)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000008
    jz andn_nop3

    mov rax, ARG1_64
    mov rbx, ARG2_64
    andn rdx, rax, rbx

andn_nop3: nop
TEST_END_64

TEST_BEGIN_MEM_64(ANDNr64m64, 2)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0, 0,
    0xFFFFFFFFFFFFFFFF, 0,
    0, 0xFFFFFFFFFFFFFFFF,
    0x123456789ABCDEF0, 0x0F0F0F0F0F0F0F0F,
    0x8000000000000000, 0xFFFFFFFFFFFFFFFF,
    0xAAAAAAAAAAAAAAAA, 0x5555555555555555)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000008
    jz andn_nop4

    mov rax, ARG1_64
    mov QWORD PTR [rsp - 8], ARG2_64
    andn rdx, rax, QWORD PTR [rsp - 8]

andn_nop4: nop
TEST_END_MEM_64
