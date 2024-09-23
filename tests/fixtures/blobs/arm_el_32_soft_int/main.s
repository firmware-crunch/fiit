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

.global __INTERRUPT_VECTOR_TABLE__
.global __reset_handler__
.global __irq_handler__

.equ emu_start, __INTERRUPT_VECTOR_TABLE__

.equ NO_INT,   0xc0

.equ MODE_USR, 0x10
.equ MODE_FIQ, 0x11
.equ MODE_IRQ, 0x12
.equ MODE_SVC, 0x13
.equ MODE_ABT, 0x17
.equ MODE_UND, 0x1b
.equ MODE_SYS, 0x1f

.equ STACK_SVC, 0x200
.equ STACK_USR, 0x300


__INTERRUPT_VECTOR_TABLE__:
    b __reset_handler__   /* Reset */
    b .                   /* Undefined */
    b __swi_handler__     /* SWI */
    b .                   /* Prefetch Abort */
    b .                   /* Data Abort */
    b .                   /* reserved */
    b .                   /* IRQ */
    b .                   /* FIQ */


__reset_handler__:
    mov r2, #NO_INT|MODE_SVC
    ldr sp, =STACK_SVC
    msr cpsr_c, r2

    mov r2, #NO_INT|MODE_USR
    ldr sp, =STACK_USR
    msr cpsr_c, r2

    b __entry__


__swi_handler__:
    stmfd sp!,{r0-r12,r14}
    mov r0, r0
    ldmfd r13!,{r0-r12,pc}^


__entry__:
    mov r0, r0
    swi 0
    mov r0, r0
emu_end:
    mov r0, r0
