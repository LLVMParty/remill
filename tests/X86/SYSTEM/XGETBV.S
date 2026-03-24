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

TEST_BEGIN(XGETBVxcr0, 1)
TEST_INPUTS(0)

    mov eax, 0x00000001
    cpuid
    mov ebx, ecx
    and ebx, 0x0C000000
    cmp ebx, 0x0C000000
    jne xgetbv_nop1

    xor ecx, ecx
    xgetbv

xgetbv_nop1: nop
TEST_END
