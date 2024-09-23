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
.global cc_call_test_wrapper

.equ emu_start, __INTERRUPT_VECTOR_TABLE__


.equ  stack_init,                   0x4000
.equ  cc_call_test_stack_canary,    0xbeefbabe


__INTERRUPT_VECTOR_TABLE__:
b __reset_handler__   /* Reset */
b .                   /* Undefined */
b .                   /* SWI */
b .                   /* Prefetch Abort */
b .                   /* Data Abort */
b .                   /* reserved */
b .                   /* IRQ */
b .                   /* FIQ */


__reset_handler__:
  bic r0, r0, #0x80
  msr cpsr_cf, r0
  ldr sp, =stack_init
  bl __entry__
emu_end:
  mov r0, r0
  b .


cc_call_test_wrapper:
  stmfd sp!,{r4-r12, lr}
  ldr r4, =cc_call_test_stack_canary
  str r4, [sp, #-4]!
  mov r0, r0
  mov r0, r0
cc_call_test_call_site:
  mov r0, r0
  mov r0, r0
  mov r0, r0
  ldr r0, [sp], #4
  ldmfd sp!, {r4-r12, pc}
