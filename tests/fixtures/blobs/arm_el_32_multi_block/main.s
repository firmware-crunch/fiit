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
    mov r0, #1
    mov r1, #1
    cmp r0, r1
    bne .

block_2:
    mov r0, #2
    mov r1, #2
    cmp r0, r1
    bne .

block_3:
    mov r0, #3
    mov r1, #3
    cmp r0, r1
    bne .

block_4:
    mov r0, #4
    mov r1, #4
    cmp r0, r1
    bne .

block_5:
    mov r0, #5
    mov r1, #5
    cmp r0, r1
    bne .

emu_end:
    mov r0, r0
