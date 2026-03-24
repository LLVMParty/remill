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

TEST_BEGIN(BZHIr32r32, 2)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0x12345678, 0,
    0x12345678, 4,
    0x12345678, 8,
    0x12345678, 31,
    0x12345678, 32,
    0x12345678, 40,
    0x12345678, 256,
    0xFFFFFFFF, 1,
    0x80000000, 31)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000100
    jz bzhi_nop1

    mov eax, ARG1_32
    mov ebx, ARG2_32
    bzhi edx, eax, ebx

bzhi_nop1: nop
TEST_END

TEST_BEGIN_MEM(BZHIr32m32, 2)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0x12345678, 0,
    0x12345678, 4,
    0x12345678, 8,
    0x12345678, 31,
    0x12345678, 32,
    0x12345678, 40,
    0x12345678, 256,
    0xFFFFFFFF, 1,
    0x80000000, 31)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000100
    jz bzhi_nop2

    mov DWORD PTR [rsp - 8], ARG1_32
    mov ebx, ARG2_32
    bzhi edx, DWORD PTR [rsp - 8], ebx

bzhi_nop2: nop
TEST_END_MEM

TEST_BEGIN_64(BZHIr64r64, 2)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0x123456789ABCDEF0, 0,
    0x123456789ABCDEF0, 4,
    0x123456789ABCDEF0, 8,
    0x123456789ABCDEF0, 63,
    0x123456789ABCDEF0, 64,
    0x123456789ABCDEF0, 72,
    0x123456789ABCDEF0, 256,
    0xFFFFFFFFFFFFFFFF, 1,
    0x8000000000000000, 63)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000100
    jz bzhi_nop3

    mov rax, ARG1_64
    mov rbx, ARG2_64
    bzhi rdx, rax, rbx

bzhi_nop3: nop
TEST_END_64

TEST_BEGIN_MEM_64(BZHIr64m64, 2)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0x123456789ABCDEF0, 0,
    0x123456789ABCDEF0, 4,
    0x123456789ABCDEF0, 8,
    0x123456789ABCDEF0, 63,
    0x123456789ABCDEF0, 64,
    0x123456789ABCDEF0, 72,
    0x123456789ABCDEF0, 256,
    0xFFFFFFFFFFFFFFFF, 1,
    0x8000000000000000, 63)

    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    test ebx, 0x00000100
    jz bzhi_nop4

    mov QWORD PTR [rsp - 8], ARG1_64
    mov rbx, ARG2_64
    bzhi rdx, QWORD PTR [rsp - 8], rbx

bzhi_nop4: nop
TEST_END_MEM_64
