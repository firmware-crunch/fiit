/*

 Copyright 2022-2025 Vincent Dary

 This file is part of fiit.

 fiit is free software: you can redistribute it and/or modify it under the
 terms of the GNU Affero General Public License as published by the Free
 Software Foundation, either version 3 of the License, or (at your option) any
 later version.

 fiit is distributed in the hope that it will be useful, but WITHOUT ANY
 WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 details.

 You should have received a copy of the GNU Affero General Public License along
 with fiit. If not, see <https://www.gnu.org/licenses/>.

*/

.global __main__

.equ emu_start, __main__

__main__:
    mov r0, #32
    mov r3, #0

block_2:
    ldr r2, [r0]
    str r2, [r0]
    add r3, r3, #1
    mov r4, #10
    cmp r3, r4
    bne block_2

emu_end:
    mov r0, r0
