################################################################################
#
# Copyright 2022-2025 Vincent Dary
#
# This file is part of fiit.
#
# fiit is free software: you can redistribute it and/or modify it under the
# terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# fiit is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License along
# with fiit. If not, see <https://www.gnu.org/licenses/>.
#
################################################################################

from ..meta_bin_blob import MetaBinBlob

meta_blob_cc_aapcs32_armel_v6_soft_float_fp16_ieee = \
  {'arch_unicorn': 'arm:el:32:1176',
   'arch_info': {'cpu_float_flag': 'FLOAT_SOFT',
                 'tag_cpu_arch': 'v6KZ',
                 'tag_cpu_name': 'ARM1176JZF-S',
                 'tag_fp_arch': None,
                 'tag_abi_fp_16bit_format': 'IEEE754'},
   'compiler': 'GCC: (Arch Repository) 13.1.0\x00',
   'producer': 'GNU C17 13.1.0 -mthumb-interwork -mcpu=arm1176jzf-s '
               '-mlittle-endian -mfloat-abi=soft -mfp16-format=ieee -marm '
               '-march=armv6kz -g -O0',
   'emu_start': 0,
   'emu_end': 48,
   'mem_map': [{'name': 'rom', 'perm': 'rx', 'base_address': 0, 'size': 20480}],
   'disassembly': '\n'
                  'out.elf:     file format elf32-littlearm\n'
                  '\n'
                  '\n'
                  'Disassembly of section .text:\n'
                  '\n'
                  '00000000 <__INTERRUPT_VECTOR_TABLE__>:\n'
                  '   0:  ea000006   b  20 <__reset_handler__>\n'
                  '   4:  eafffffe   b  4 <PERM_W>\n'
                  '   8:  eafffffe   b  8 <PERM_X>\n'
                  '   c:  eafffffe   b  c <__mem_map_area_rom+0x2>\n'
                  '  10:  eafffffe   b  10 <__mem_map_area_rom+0x6>\n'
                  '  14:  eafffffe   b  14 <__mem_map_area_rom+0xa>\n'
                  '  18:  eafffffe   b  18 <__mem_map_area_rom+0xe>\n'
                  '  1c:  eafffffe   b  1c <__mem_map_area_rom+0x12>\n'
                  '\n'
                  '00000020 <__reset_handler__>:\n'
                  '  20:  e3c00080   bic  r0, r0, #128  @ 0x80\n'
                  '  24:  e129f000   msr  CPSR_fc, r0\n'
                  '  28:  e3a0d901   mov  sp, #16384  @ 0x4000\n'
                  '  2c:  eb000106   bl  44c <__entry__>\n'
                  '\n'
                  '00000030 <emu_end>:\n'
                  '  30:  e1a00000   nop      @ (mov r0, r0)\n'
                  '  34:  eafffffe   b  34 <emu_end+0x4>\n'
                  '\n'
                  '00000038 <cc_call_test_wrapper>:\n'
                  '  38:  e92d5ff0   push  {r4, r5, r6, r7, r8, r9, sl, fp, '
                  'ip, lr}\n'
                  '  3c:  e59f401c   ldr  r4, [pc, #28]  @ 60 '
                  '<cc_call_test_call_site+0x14>\n'
                  '  40:  e52d4004   push  {r4}    @ (str r4, [sp, #-4]!)\n'
                  '  44:  e1a00000   nop      @ (mov r0, r0)\n'
                  '  48:  e1a00000   nop      @ (mov r0, r0)\n'
                  '\n'
                  '0000004c <cc_call_test_call_site>:\n'
                  '  4c:  e1a00000   nop      @ (mov r0, r0)\n'
                  '  50:  e1a00000   nop      @ (mov r0, r0)\n'
                  '  54:  e1a00000   nop      @ (mov r0, r0)\n'
                  '  58:  e49d0004   pop  {r0}    @ (ldr r0, [sp], #4)\n'
                  '  5c:  e8bd9ff0   pop  {r4, r5, r6, r7, r8, r9, sl, fp, ip, '
                  'pc}\n'
                  '  60:  beefbabe   .word  0xbeefbabe\n'
                  '  64:  00000000   .word  0x00000000\n'
                  '\n'
                  '00000068 <foo_01>:\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'unsigned int foo_01(unsigned int a, unsigned int b, '
                  'unsigned int c,\n'
                  '                    unsigned int d)\n'
                  '{\n'
                  '  68:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  '  6c:  e28db000   add  fp, sp, #0\n'
                  '  70:  e24dd014   sub  sp, sp, #20\n'
                  '  74:  e50b0008   str  r0, [fp, #-8]\n'
                  '  78:  e50b100c   str  r1, [fp, #-12]\n'
                  '  7c:  e50b2010   str  r2, [fp, #-16]\n'
                  '  80:  e50b3014   str  r3, [fp, #-20]  @ 0xffffffec\n'
                  '  return 0x01020304;\n'
                  '  84:  e59f300c   ldr  r3, [pc, #12]  @ 98 <foo_01+0x30>\n'
                  '}\n'
                  '  88:  e1a00003   mov  r0, r3\n'
                  '  8c:  e28bd000   add  sp, fp, #0\n'
                  '  90:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  '  94:  e12fff1e   bx  lr\n'
                  '  98:  01020304   .word  0x01020304\n'
                  '\n'
                  '0000009c <foo_02>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'unsigned long long foo_02(unsigned int a, unsigned long '
                  'long b)\n'
                  '{\n'
                  '  9c:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  '  a0:  e28db000   add  fp, sp, #0\n'
                  '  a4:  e24dd014   sub  sp, sp, #20\n'
                  '  a8:  e50b0008   str  r0, [fp, #-8]\n'
                  '  ac:  e14b21f4   strd  r2, [fp, #-20]  @ 0xffffffec\n'
                  '  return 0x0102030405060708;\n'
                  '  b0:  e28f3018   add  r3, pc, #24\n'
                  '  b4:  e1c320d0   ldrd  r2, [r3]\n'
                  '}\n'
                  '  b8:  e1a00002   mov  r0, r2\n'
                  '  bc:  e1a01003   mov  r1, r3\n'
                  '  c0:  e28bd000   add  sp, fp, #0\n'
                  '  c4:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  '  c8:  e12fff1e   bx  lr\n'
                  '  cc:  e320f000   nop  {0}\n'
                  '  d0:  05060708   .word  0x05060708\n'
                  '  d4:  01020304   .word  0x01020304\n'
                  '\n'
                  '000000d8 <foo_03>:\n'
                  '                          unsigned char c,\n'
                  '                          unsigned long long d,\n'
                  '                          unsigned char e,\n'
                  '                          unsigned char f,\n'
                  '                          unsigned int g)\n'
                  '{\n'
                  '  d8:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  '  dc:  e28db000   add  fp, sp, #0\n'
                  '  e0:  e24dd014   sub  sp, sp, #20\n'
                  '  e4:  e14b00fc   strd  r0, [fp, #-12]\n'
                  '  e8:  e14b21f4   strd  r2, [fp, #-20]  @ 0xffffffec\n'
                  '  return 0x0102030405060708;\n'
                  '  ec:  e28f3014   add  r3, pc, #20\n'
                  '  f0:  e1c320d0   ldrd  r2, [r3]\n'
                  '}\n'
                  '  f4:  e1a00002   mov  r0, r2\n'
                  '  f8:  e1a01003   mov  r1, r3\n'
                  '  fc:  e28bd000   add  sp, fp, #0\n'
                  ' 100:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 104:  e12fff1e   bx  lr\n'
                  ' 108:  05060708   .word  0x05060708\n'
                  ' 10c:  01020304   .word  0x01020304\n'
                  '\n'
                  '00000110 <foo_04>:\n'
                  '// Argument split between register and the stack.\n'
                  '//##############################################################################\n'
                  'struct struct_04 { unsigned int a; unsigned int b; unsigned '
                  'int c; };\n'
                  '\n'
                  'unsigned int foo_04(unsigned int a, unsigned int b, struct '
                  'struct_04 c)\n'
                  '{\n'
                  ' 110:  e24dd008   sub  sp, sp, #8\n'
                  ' 114:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 118:  e28db000   add  fp, sp, #0\n'
                  ' 11c:  e24dd00c   sub  sp, sp, #12\n'
                  ' 120:  e50b0008   str  r0, [fp, #-8]\n'
                  ' 124:  e50b100c   str  r1, [fp, #-12]\n'
                  ' 128:  e28b1004   add  r1, fp, #4\n'
                  ' 12c:  e881000c   stm  r1, {r2, r3}\n'
                  '  return 1;\n'
                  ' 130:  e3a03001   mov  r3, #1\n'
                  '}\n'
                  ' 134:  e1a00003   mov  r0, r3\n'
                  ' 138:  e28bd000   add  sp, fp, #0\n'
                  ' 13c:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 140:  e28dd008   add  sp, sp, #8\n'
                  ' 144:  e12fff1e   bx  lr\n'
                  '\n'
                  '00000148 <foo_05>:\n'
                  '// Aggregate argument with heterogeneous size members.\n'
                  '//##############################################################################\n'
                  'struct struct_05 { char a; short b; unsigned int c; char d; '
                  'long long e; };\n'
                  '\n'
                  'unsigned int foo_05(struct struct_05 aggregate)\n'
                  '{\n'
                  ' 148:  e24dd010   sub  sp, sp, #16\n'
                  ' 14c:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 150:  e28db000   add  fp, sp, #0\n'
                  ' 154:  e28bc004   add  ip, fp, #4\n'
                  ' 158:  e88c000f   stm  ip, {r0, r1, r2, r3}\n'
                  '  return 1;\n'
                  ' 15c:  e3a03001   mov  r3, #1\n'
                  '}\n'
                  ' 160:  e1a00003   mov  r0, r3\n'
                  ' 164:  e28bd000   add  sp, fp, #0\n'
                  ' 168:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 16c:  e28dd010   add  sp, sp, #16\n'
                  ' 170:  e12fff1e   bx  lr\n'
                  '\n'
                  '00000174 <foo_06>:\n'
                  '// Aggregate argument lower than one word.\n'
                  '//##############################################################################\n'
                  'struct struct_06 { unsigned char a; };\n'
                  '\n'
                  'struct struct_06 foo_06(struct struct_06 aggregate)\n'
                  '{\n'
                  ' 174:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 178:  e28db000   add  fp, sp, #0\n'
                  ' 17c:  e24dd00c   sub  sp, sp, #12\n'
                  ' 180:  e54b0008   strb  r0, [fp, #-8]\n'
                  "  return (struct struct_06){.a='A'};\n"
                  ' 184:  e3a03041   mov  r3, #65  @ 0x41\n'
                  '}\n'
                  ' 188:  e1a00003   mov  r0, r3\n'
                  ' 18c:  e28bd000   add  sp, fp, #0\n'
                  ' 190:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 194:  e12fff1e   bx  lr\n'
                  '\n'
                  '00000198 <foo_07>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'float foo_07(int a, float x, int b, double y, float z)\n'
                  '{\n'
                  ' 198:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 19c:  e28db000   add  fp, sp, #0\n'
                  ' 1a0:  e24dd014   sub  sp, sp, #20\n'
                  ' 1a4:  e50b0008   str  r0, [fp, #-8]\n'
                  ' 1a8:  e50b100c   str  r1, [fp, #-12]\n'
                  ' 1ac:  e50b2010   str  r2, [fp, #-16]\n'
                  '  return 0.9375;\n'
                  ' 1b0:  e59f300c   ldr  r3, [pc, #12]  @ 1c4 <foo_07+0x2c>\n'
                  '}\n'
                  ' 1b4:  e1a00003   mov  r0, r3\n'
                  ' 1b8:  e28bd000   add  sp, fp, #0\n'
                  ' 1bc:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 1c0:  e12fff1e   bx  lr\n'
                  ' 1c4:  3f700000   .word  0x3f700000\n'
                  '\n'
                  '000001c8 <foo_08>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'float foo_08(int a, float b, int c, double d, __fp16 e, '
                  'float f)\n'
                  '{\n'
                  ' 1c8:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 1cc:  e28db000   add  fp, sp, #0\n'
                  ' 1d0:  e24dd014   sub  sp, sp, #20\n'
                  ' 1d4:  e50b0008   str  r0, [fp, #-8]\n'
                  ' 1d8:  e50b100c   str  r1, [fp, #-12]\n'
                  ' 1dc:  e50b2010   str  r2, [fp, #-16]\n'
                  '  return 0.9375;\n'
                  ' 1e0:  e59f300c   ldr  r3, [pc, #12]  @ 1f4 <foo_08+0x2c>\n'
                  '}\n'
                  ' 1e4:  e1a00003   mov  r0, r3\n'
                  ' 1e8:  e28bd000   add  sp, fp, #0\n'
                  ' 1ec:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 1f0:  e12fff1e   bx  lr\n'
                  ' 1f4:  3f700000   .word  0x3f700000\n'
                  '\n'
                  '000001f8 <foo_09>:\n'
                  'struct struct_09_2 { double c; double d; };\n'
                  'struct struct_09_3 { struct struct_09_2 b; };\n'
                  'struct struct_09_4 { struct struct_09_1 a; struct '
                  'struct_09_3 wrap; };\n'
                  '\n'
                  'float foo_09(struct struct_09_4 a)\n'
                  '{\n'
                  ' 1f8:  e24dd010   sub  sp, sp, #16\n'
                  ' 1fc:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 200:  e28db000   add  fp, sp, #0\n'
                  ' 204:  e28bc004   add  ip, fp, #4\n'
                  ' 208:  e88c000f   stm  ip, {r0, r1, r2, r3}\n'
                  '  return 0.9375;\n'
                  ' 20c:  e59f3010   ldr  r3, [pc, #16]  @ 224 <foo_09+0x2c>\n'
                  '}\n'
                  ' 210:  e1a00003   mov  r0, r3\n'
                  ' 214:  e28bd000   add  sp, fp, #0\n'
                  ' 218:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 21c:  e28dd010   add  sp, sp, #16\n'
                  ' 220:  e12fff1e   bx  lr\n'
                  ' 224:  3f700000   .word  0x3f700000\n'
                  '\n'
                  '00000228 <foo_10>:\n'
                  '// force aapcs32 c2 rule vfp registers with double.\n'
                  '//##############################################################################\n'
                  'double foo_10(double x1, double x2, double x3, double x4,\n'
                  '              double x5, double x6, double x7, double x8,\n'
                  '              double x9, double x10)\n'
                  '{\n'
                  ' 228:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 22c:  e28db000   add  fp, sp, #0\n'
                  ' 230:  e24dd014   sub  sp, sp, #20\n'
                  ' 234:  e14b00fc   strd  r0, [fp, #-12]\n'
                  ' 238:  e14b21f4   strd  r2, [fp, #-20]  @ 0xffffffec\n'
                  '  return 0.25;\n'
                  ' 23c:  e3a02000   mov  r2, #0\n'
                  ' 240:  e59f3010   ldr  r3, [pc, #16]  @ 258 <foo_10+0x30>\n'
                  '}\n'
                  ' 244:  e1a00002   mov  r0, r2\n'
                  ' 248:  e1a01003   mov  r1, r3\n'
                  ' 24c:  e28bd000   add  sp, fp, #0\n'
                  ' 250:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 254:  e12fff1e   bx  lr\n'
                  ' 258:  3fd00000   .word  0x3fd00000\n'
                  '\n'
                  '0000025c <foo_11>:\n'
                  '//#############################################################################\n'
                  '__fp16 foo_11(__fp16 x1, __fp16 x2, __fp16 x3, __fp16 x4, '
                  '__fp16 x5, __fp16 x6,\n'
                  '              __fp16 x7, __fp16 x8, __fp16 x9, __fp16 x10, '
                  '__fp16 x11,\n'
                  '              __fp16 x12, __fp16 x13, __fp16 x14, __fp16 '
                  'x15, __fp16 x16,\n'
                  '              __fp16 x17, __fp16 x18)\n'
                  '{\n'
                  ' 25c:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 260:  e28db000   add  fp, sp, #0\n'
                  ' 264:  e24dd00c   sub  sp, sp, #12\n'
                  ' 268:  e14b00b6   strh  r0, [fp, #-6]\n'
                  ' 26c:  e14b10b8   strh  r1, [fp, #-8]\n'
                  ' 270:  e14b20ba   strh  r2, [fp, #-10]\n'
                  ' 274:  e14b30bc   strh  r3, [fp, #-12]\n'
                  '  return 0.25;\n'
                  ' 278:  e3a03b0d   mov  r3, #13312  @ 0x3400\n'
                  ' 27c:  e3833000   orr  r3, r3, #0\n'
                  '}\n'
                  ' 280:  e1a00003   mov  r0, r3\n'
                  ' 284:  e28bd000   add  sp, fp, #0\n'
                  ' 288:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 28c:  e12fff1e   bx  lr\n'
                  '\n'
                  '00000290 <foo_12>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '// Return fundamental type smaller than a word.\n'
                  '//##############################################################################\n'
                  'unsigned short foo_12(void)\n'
                  '{\n'
                  ' 290:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 294:  e28db000   add  fp, sp, #0\n'
                  '  return 0xabcd;\n'
                  ' 298:  e59f300c   ldr  r3, [pc, #12]  @ 2ac <foo_12+0x1c>\n'
                  '}\n'
                  ' 29c:  e1a00003   mov  r0, r3\n'
                  ' 2a0:  e28bd000   add  sp, fp, #0\n'
                  ' 2a4:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 2a8:  e12fff1e   bx  lr\n'
                  ' 2ac:  0000abcd   .word  0x0000abcd\n'
                  '\n'
                  '000002b0 <foo_13>:\n'
                  '\n'
                  '//#############################################################################\n'
                  '// Return fundamental type with double word size.\n'
                  '//#############################################################################\n'
                  'unsigned long long foo_13(void)\n'
                  '{\n'
                  ' 2b0:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 2b4:  e28db000   add  fp, sp, #0\n'
                  '  return 0xffeeddccbbaa9988;;\n'
                  ' 2b8:  e28f3018   add  r3, pc, #24\n'
                  ' 2bc:  e1c320d0   ldrd  r2, [r3]\n'
                  '}\n'
                  ' 2c0:  e1a00002   mov  r0, r2\n'
                  ' 2c4:  e1a01003   mov  r1, r3\n'
                  ' 2c8:  e28bd000   add  sp, fp, #0\n'
                  ' 2cc:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 2d0:  e12fff1e   bx  lr\n'
                  ' 2d4:  e320f000   nop  {0}\n'
                  ' 2d8:  bbaa9988   .word  0xbbaa9988\n'
                  ' 2dc:  ffeeddcc   .word  0xffeeddcc\n'
                  '\n'
                  '000002e0 <foo_14>:\n'
                  '// Return aggregate lower than a word.\n'
                  '//#############################################################################\n'
                  'struct struct_14 { unsigned char a; unsigned char b; '
                  'unsigned char c; };\n'
                  '\n'
                  'struct struct_14 foo_14(void)\n'
                  '{\n'
                  ' 2e0:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 2e4:  e28db000   add  fp, sp, #0\n'
                  ' 2e8:  e24dd00c   sub  sp, sp, #12\n'
                  "  return (struct struct_14){.a='I', .b='J', .c='K'};\n"
                  ' 2ec:  e59f2060   ldr  r2, [pc, #96]  @ 354 <foo_14+0x74>\n'
                  ' 2f0:  e24b3008   sub  r3, fp, #8\n'
                  ' 2f4:  e5922000   ldr  r2, [r2]\n'
                  ' 2f8:  e1c320b0   strh  r2, [r3]\n'
                  ' 2fc:  e2833002   add  r3, r3, #2\n'
                  ' 300:  e1a02822   lsr  r2, r2, #16\n'
                  ' 304:  e5c32000   strb  r2, [r3]\n'
                  ' 308:  e3a03000   mov  r3, #0\n'
                  ' 30c:  e55b2008   ldrb  r2, [fp, #-8]\n'
                  ' 310:  e6ef2072   uxtb  r2, r2\n'
                  ' 314:  e3c330ff   bic  r3, r3, #255  @ 0xff\n'
                  ' 318:  e1823003   orr  r3, r2, r3\n'
                  ' 31c:  e55b2007   ldrb  r2, [fp, #-7]\n'
                  ' 320:  e6ef2072   uxtb  r2, r2\n'
                  ' 324:  e3c33cff   bic  r3, r3, #65280  @ 0xff00\n'
                  ' 328:  e1a02402   lsl  r2, r2, #8\n'
                  ' 32c:  e1823003   orr  r3, r2, r3\n'
                  ' 330:  e55b2006   ldrb  r2, [fp, #-6]\n'
                  ' 334:  e6ef2072   uxtb  r2, r2\n'
                  ' 338:  e3c338ff   bic  r3, r3, #16711680  @ 0xff0000\n'
                  ' 33c:  e1a02802   lsl  r2, r2, #16\n'
                  ' 340:  e1823003   orr  r3, r2, r3\n'
                  '}\n'
                  ' 344:  e1a00003   mov  r0, r3\n'
                  ' 348:  e28bd000   add  sp, fp, #0\n'
                  ' 34c:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 350:  e12fff1e   bx  lr\n'
                  ' 354:  000007c0   .word  0x000007c0\n'
                  '\n'
                  '00000358 <foo_15>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  '__fp16 foo_15(void)\n'
                  '{\n'
                  ' 358:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 35c:  e28db000   add  fp, sp, #0\n'
                  '  return 3.875;\n'
                  ' 360:  e3a03c43   mov  r3, #17152  @ 0x4300\n'
                  ' 364:  e38330c0   orr  r3, r3, #192  @ 0xc0\n'
                  '}\n'
                  ' 368:  e1a00003   mov  r0, r3\n'
                  ' 36c:  e28bd000   add  sp, fp, #0\n'
                  ' 370:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 374:  e12fff1e   bx  lr\n'
                  '\n'
                  '00000378 <foo_16>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'float foo_16(void)\n'
                  '{\n'
                  ' 378:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 37c:  e28db000   add  fp, sp, #0\n'
                  '  return 0.75;\n'
                  ' 380:  e3a035fd   mov  r3, #1061158912  @ 0x3f400000\n'
                  '}\n'
                  ' 384:  e1a00003   mov  r0, r3\n'
                  ' 388:  e28bd000   add  sp, fp, #0\n'
                  ' 38c:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 390:  e12fff1e   bx  lr\n'
                  '\n'
                  '00000394 <foo_17>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'double foo_17(void)\n'
                  '{\n'
                  ' 394:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 398:  e28db000   add  fp, sp, #0\n'
                  '  return 0.75;\n'
                  ' 39c:  e3a02000   mov  r2, #0\n'
                  ' 3a0:  e59f3010   ldr  r3, [pc, #16]  @ 3b8 <foo_17+0x24>\n'
                  '}\n'
                  ' 3a4:  e1a00002   mov  r0, r2\n'
                  ' 3a8:  e1a01003   mov  r1, r3\n'
                  ' 3ac:  e28bd000   add  sp, fp, #0\n'
                  ' 3b0:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 3b4:  e12fff1e   bx  lr\n'
                  ' 3b8:  3fe80000   .word  0x3fe80000\n'
                  '\n'
                  '000003bc <foo_19>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'void foo_19(void)\n'
                  '{\n'
                  ' 3bc:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 3c0:  e28db000   add  fp, sp, #0\n'
                  '}\n'
                  ' 3c4:  e320f000   nop  {0}\n'
                  ' 3c8:  e28bd000   add  sp, fp, #0\n'
                  ' 3cc:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 3d0:  e12fff1e   bx  lr\n'
                  '\n'
                  '000003d4 <foo_20>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '// Argument with size lower than a word.\n'
                  '//##############################################################################\n'
                  'unsigned int foo_20(unsigned short a)\n'
                  '{\n'
                  ' 3d4:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 3d8:  e28db000   add  fp, sp, #0\n'
                  ' 3dc:  e24dd00c   sub  sp, sp, #12\n'
                  ' 3e0:  e1a03000   mov  r3, r0\n'
                  ' 3e4:  e14b30b6   strh  r3, [fp, #-6]\n'
                  '    return 1;\n'
                  ' 3e8:  e3a03001   mov  r3, #1\n'
                  '}\n'
                  ' 3ec:  e1a00003   mov  r0, r3\n'
                  ' 3f0:  e28bd000   add  sp, fp, #0\n'
                  ' 3f4:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 3f8:  e12fff1e   bx  lr\n'
                  '\n'
                  '000003fc <foo_21>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'unsigned char * foo_21(unsigned char * a)\n'
                  '{\n'
                  ' 3fc:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 400:  e28db000   add  fp, sp, #0\n'
                  ' 404:  e24dd00c   sub  sp, sp, #12\n'
                  ' 408:  e50b0008   str  r0, [fp, #-8]\n'
                  '    return (unsigned char *) 0xBADEBABE;\n'
                  ' 40c:  e59f300c   ldr  r3, [pc, #12]  @ 420 <foo_21+0x24>\n'
                  '}\n'
                  ' 410:  e1a00003   mov  r0, r3\n'
                  ' 414:  e28bd000   add  sp, fp, #0\n'
                  ' 418:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 41c:  e12fff1e   bx  lr\n'
                  ' 420:  badebabe   .word  0xbadebabe\n'
                  '\n'
                  '00000424 <foo_22>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'unsigned char ** foo_22(unsigned char ** a)\n'
                  '{\n'
                  ' 424:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 428:  e28db000   add  fp, sp, #0\n'
                  ' 42c:  e24dd00c   sub  sp, sp, #12\n'
                  ' 430:  e50b0008   str  r0, [fp, #-8]\n'
                  '    return (unsigned char **) 0xBABEBADE;\n'
                  ' 434:  e59f300c   ldr  r3, [pc, #12]  @ 448 <foo_22+0x24>\n'
                  '}\n'
                  ' 438:  e1a00003   mov  r0, r3\n'
                  ' 43c:  e28bd000   add  sp, fp, #0\n'
                  ' 440:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 444:  e12fff1e   bx  lr\n'
                  ' 448:  babebade   .word  0xbabebade\n'
                  '\n'
                  '0000044c <__entry__>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '// Entry Point\n'
                  '//##############################################################################\n'
                  'void __entry__(void)\n'
                  '{\n'
                  ' 44c:  e92d4800   push  {fp, lr}\n'
                  ' 450:  e28db004   add  fp, sp, #4\n'
                  ' 454:  e24dd088   sub  sp, sp, #136  @ 0x88\n'
                  '  cc_call_test_wrapper();\n'
                  ' 458:  ebfffef6   bl  38 <cc_call_test_wrapper>\n'
                  '\n'
                  '  foo_01(0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10);\n'
                  ' 45c:  e59f32fc   ldr  r3, [pc, #764]  @ 760 '
                  '<__entry__+0x314>\n'
                  ' 460:  e59f22fc   ldr  r2, [pc, #764]  @ 764 '
                  '<__entry__+0x318>\n'
                  ' 464:  e59f12fc   ldr  r1, [pc, #764]  @ 768 '
                  '<__entry__+0x31c>\n'
                  ' 468:  e59f02fc   ldr  r0, [pc, #764]  @ 76c '
                  '<__entry__+0x320>\n'
                  ' 46c:  ebfffefd   bl  68 <foo_01>\n'
                  '\n'
                  '  foo_02(0x01020304, 0x05060708090A0B0C);\n'
                  ' 470:  e28f3fb2   add  r3, pc, #712  @ 0x2c8\n'
                  ' 474:  e1c320d0   ldrd  r2, [r3]\n'
                  ' 478:  e59f02ec   ldr  r0, [pc, #748]  @ 76c '
                  '<__entry__+0x320>\n'
                  ' 47c:  ebffff06   bl  9c <foo_02>\n'
                  '\n'
                  '  foo_03(0x0807060504030201, 0x100F0E0D0C0B0A09,\n'
                  ' 480:  e59f32e8   ldr  r3, [pc, #744]  @ 770 '
                  '<__entry__+0x324>\n'
                  ' 484:  e58d3018   str  r3, [sp, #24]\n'
                  ' 488:  e3a0304a   mov  r3, #74  @ 0x4a\n'
                  ' 48c:  e58d3014   str  r3, [sp, #20]\n'
                  ' 490:  e3a0304b   mov  r3, #75  @ 0x4b\n'
                  ' 494:  e58d3010   str  r3, [sp, #16]\n'
                  ' 498:  e28f3faa   add  r3, pc, #680  @ 0x2a8\n'
                  ' 49c:  e1c320d0   ldrd  r2, [r3]\n'
                  ' 4a0:  e1cd20f8   strd  r2, [sp, #8]\n'
                  ' 4a4:  e3a03041   mov  r3, #65  @ 0x41\n'
                  ' 4a8:  e58d3000   str  r3, [sp]\n'
                  ' 4ac:  e28f3fa7   add  r3, pc, #668  @ 0x29c\n'
                  ' 4b0:  e1c320d0   ldrd  r2, [r3]\n'
                  ' 4b4:  e28f1fa7   add  r1, pc, #668  @ 0x29c\n'
                  ' 4b8:  e1c100d0   ldrd  r0, [r1]\n'
                  ' 4bc:  ebffff05   bl  d8 <foo_03>\n'
                  "         'A', 0x1817161514131211, 'K', 'J', 0x1c1b1a19);\n"
                  '\n'
                  '  foo_04(1, 3, (struct struct_04){.a=0x0f101112, '
                  '.b=0x13141516, .c=0x17181920});\n'
                  ' 4c0:  e59f22ac   ldr  r2, [pc, #684]  @ 774 '
                  '<__entry__+0x328>\n'
                  ' 4c4:  e24b3010   sub  r3, fp, #16\n'
                  ' 4c8:  e8920007   ldm  r2, {r0, r1, r2}\n'
                  ' 4cc:  e8830007   stm  r3, {r0, r1, r2}\n'
                  ' 4d0:  e51b3008   ldr  r3, [fp, #-8]\n'
                  ' 4d4:  e58d3000   str  r3, [sp]\n'
                  ' 4d8:  e24b3010   sub  r3, fp, #16\n'
                  ' 4dc:  e893000c   ldm  r3, {r2, r3}\n'
                  ' 4e0:  e3a01003   mov  r1, #3\n'
                  ' 4e4:  e3a00001   mov  r0, #1\n'
                  ' 4e8:  ebffff08   bl  110 <foo_04>\n'
                  '\n'
                  '  foo_05((struct struct_05)\n'
                  "        {.a='a', .b=0x0f10, .c=0x11121314, .d='b', "
                  '.e=0x15161718191a1b1c});\n'
                  ' 4ec:  e59f3284   ldr  r3, [pc, #644]  @ 778 '
                  '<__entry__+0x32c>\n'
                  ' 4f0:  e24bc02c   sub  ip, fp, #44  @ 0x2c\n'
                  ' 4f4:  e1a0e003   mov  lr, r3\n'
                  ' 4f8:  e8be000f   ldm  lr!, {r0, r1, r2, r3}\n'
                  ' 4fc:  e8ac000f   stmia  ip!, {r0, r1, r2, r3}\n'
                  ' 500:  e89e0003   ldm  lr, {r0, r1}\n'
                  ' 504:  e88c0003   stm  ip, {r0, r1}\n'
                  '  foo_05((struct struct_05)\n'
                  ' 508:  e1a0200d   mov  r2, sp\n'
                  ' 50c:  e24b301c   sub  r3, fp, #28\n'
                  ' 510:  e8930003   ldm  r3, {r0, r1}\n'
                  ' 514:  e8820003   stm  r2, {r0, r1}\n'
                  ' 518:  e24b302c   sub  r3, fp, #44  @ 0x2c\n'
                  ' 51c:  e893000f   ldm  r3, {r0, r1, r2, r3}\n'
                  ' 520:  ebffff08   bl  148 <foo_05>\n'
                  '\n'
                  "  foo_06((struct struct_06){.a='a'});\n"
                  ' 524:  e3a03061   mov  r3, #97  @ 0x61\n'
                  ' 528:  e1a00003   mov  r0, r3\n'
                  ' 52c:  ebffff10   bl  174 <foo_06>\n'
                  '\n'
                  '  foo_07(4, 0.5, 8, 0.75, 0.875);\n'
                  ' 530:  e59f3244   ldr  r3, [pc, #580]  @ 77c '
                  '<__entry__+0x330>\n'
                  ' 534:  e58d3008   str  r3, [sp, #8]\n'
                  ' 538:  e3a02000   mov  r2, #0\n'
                  ' 53c:  e59f323c   ldr  r3, [pc, #572]  @ 780 '
                  '<__entry__+0x334>\n'
                  ' 540:  e1cd20f0   strd  r2, [sp]\n'
                  ' 544:  e3a02008   mov  r2, #8\n'
                  ' 548:  e3a0143f   mov  r1, #1056964608  @ 0x3f000000\n'
                  ' 54c:  e3a00004   mov  r0, #4\n'
                  ' 550:  ebffff10   bl  198 <foo_07>\n'
                  '\n'
                  '  foo_08(4, 0.5, 8, 0.75, 0.875, 0.984375);\n'
                  ' 554:  e59f3228   ldr  r3, [pc, #552]  @ 784 '
                  '<__entry__+0x338>\n'
                  ' 558:  e58d300c   str  r3, [sp, #12]\n'
                  ' 55c:  e3a03c3b   mov  r3, #15104  @ 0x3b00\n'
                  ' 560:  e3833000   orr  r3, r3, #0\n'
                  ' 564:  e1cd30b8   strh  r3, [sp, #8]\n'
                  ' 568:  e3a02000   mov  r2, #0\n'
                  ' 56c:  e59f320c   ldr  r3, [pc, #524]  @ 780 '
                  '<__entry__+0x334>\n'
                  ' 570:  e1cd20f0   strd  r2, [sp]\n'
                  ' 574:  e3a02008   mov  r2, #8\n'
                  ' 578:  e3a0143f   mov  r1, #1056964608  @ 0x3f000000\n'
                  ' 57c:  e3a00004   mov  r0, #4\n'
                  ' 580:  ebffff10   bl  1c8 <foo_08>\n'
                  '\n'
                  '  foo_09((struct struct_09_4){.a={.a=0.5, .b=0.75},\n'
                  ' 584:  e59f31fc   ldr  r3, [pc, #508]  @ 788 '
                  '<__entry__+0x33c>\n'
                  ' 588:  e24bc04c   sub  ip, fp, #76  @ 0x4c\n'
                  ' 58c:  e1a0e003   mov  lr, r3\n'
                  ' 590:  e8be000f   ldm  lr!, {r0, r1, r2, r3}\n'
                  ' 594:  e8ac000f   stmia  ip!, {r0, r1, r2, r3}\n'
                  ' 598:  e89e000f   ldm  lr, {r0, r1, r2, r3}\n'
                  ' 59c:  e88c000f   stm  ip, {r0, r1, r2, r3}\n'
                  ' 5a0:  e1a0c00d   mov  ip, sp\n'
                  ' 5a4:  e24b303c   sub  r3, fp, #60  @ 0x3c\n'
                  ' 5a8:  e893000f   ldm  r3, {r0, r1, r2, r3}\n'
                  ' 5ac:  e88c000f   stm  ip, {r0, r1, r2, r3}\n'
                  ' 5b0:  e24b304c   sub  r3, fp, #76  @ 0x4c\n'
                  ' 5b4:  e893000f   ldm  r3, {r0, r1, r2, r3}\n'
                  ' 5b8:  ebffff0e   bl  1f8 <foo_09>\n'
                  '                              .wrap={.b={.c=0.875, '
                  '.d=0.984375}}});\n'
                  '\n'
                  '  foo_10(0.25, 0.375, 0.4375, 0.46875, 0.484375, 0.4921875, '
                  '0.49609375,\n'
                  ' 5bc:  e3a02000   mov  r2, #0\n'
                  ' 5c0:  e59f31c4   ldr  r3, [pc, #452]  @ 78c '
                  '<__entry__+0x340>\n'
                  ' 5c4:  e1cd23f8   strd  r2, [sp, #56]  @ 0x38\n'
                  ' 5c8:  e3a02000   mov  r2, #0\n'
                  ' 5cc:  e59f31bc   ldr  r3, [pc, #444]  @ 790 '
                  '<__entry__+0x344>\n'
                  ' 5d0:  e1cd23f0   strd  r2, [sp, #48]  @ 0x30\n'
                  ' 5d4:  e3a02000   mov  r2, #0\n'
                  ' 5d8:  e59f31b4   ldr  r3, [pc, #436]  @ 794 '
                  '<__entry__+0x348>\n'
                  ' 5dc:  e1cd22f8   strd  r2, [sp, #40]  @ 0x28\n'
                  ' 5e0:  e3a02000   mov  r2, #0\n'
                  ' 5e4:  e59f31ac   ldr  r3, [pc, #428]  @ 798 '
                  '<__entry__+0x34c>\n'
                  ' 5e8:  e1cd22f0   strd  r2, [sp, #32]\n'
                  ' 5ec:  e3a02000   mov  r2, #0\n'
                  ' 5f0:  e59f31a4   ldr  r3, [pc, #420]  @ 79c '
                  '<__entry__+0x350>\n'
                  ' 5f4:  e1cd21f8   strd  r2, [sp, #24]\n'
                  ' 5f8:  e3a02000   mov  r2, #0\n'
                  ' 5fc:  e59f319c   ldr  r3, [pc, #412]  @ 7a0 '
                  '<__entry__+0x354>\n'
                  ' 600:  e1cd21f0   strd  r2, [sp, #16]\n'
                  ' 604:  e3a02000   mov  r2, #0\n'
                  ' 608:  e59f3194   ldr  r3, [pc, #404]  @ 7a4 '
                  '<__entry__+0x358>\n'
                  ' 60c:  e1cd20f8   strd  r2, [sp, #8]\n'
                  ' 610:  e3a02000   mov  r2, #0\n'
                  ' 614:  e59f318c   ldr  r3, [pc, #396]  @ 7a8 '
                  '<__entry__+0x35c>\n'
                  ' 618:  e1cd20f0   strd  r2, [sp]\n'
                  ' 61c:  e3a02000   mov  r2, #0\n'
                  ' 620:  e59f3184   ldr  r3, [pc, #388]  @ 7ac '
                  '<__entry__+0x360>\n'
                  ' 624:  e3a00000   mov  r0, #0\n'
                  ' 628:  e59f1180   ldr  r1, [pc, #384]  @ 7b0 '
                  '<__entry__+0x364>\n'
                  ' 62c:  ebfffefd   bl  228 <foo_10>\n'
                  '         0.498046875, 0.4990234375, 0.49951171875);\n'
                  '\n'
                  '  foo_11(2, 3, 3.5, 3.75, 3.875, 8192, 12288, 14336, 15360, '
                  '15872, 16128, 512,\n'
                  ' 630:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 634:  e38330f0   orr  r3, r3, #240  @ 0xf0\n'
                  ' 638:  e1cd33b4   strh  r3, [sp, #52]  @ 0x34\n'
                  ' 63c:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 640:  e38330e0   orr  r3, r3, #224  @ 0xe0\n'
                  ' 644:  e1cd33b0   strh  r3, [sp, #48]  @ 0x30\n'
                  ' 648:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 64c:  e38330c0   orr  r3, r3, #192  @ 0xc0\n'
                  ' 650:  e1cd32bc   strh  r3, [sp, #44]  @ 0x2c\n'
                  ' 654:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 658:  e3833080   orr  r3, r3, #128  @ 0x80\n'
                  ' 65c:  e1cd32b8   strh  r3, [sp, #40]  @ 0x28\n'
                  ' 660:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 664:  e3833000   orr  r3, r3, #0\n'
                  ' 668:  e1cd32b4   strh  r3, [sp, #36]  @ 0x24\n'
                  ' 66c:  e3a03c62   mov  r3, #25088  @ 0x6200\n'
                  ' 670:  e3833000   orr  r3, r3, #0\n'
                  ' 674:  e1cd32b0   strh  r3, [sp, #32]\n'
                  ' 678:  e3a03a06   mov  r3, #24576  @ 0x6000\n'
                  ' 67c:  e3833000   orr  r3, r3, #0\n'
                  ' 680:  e1cd31bc   strh  r3, [sp, #28]\n'
                  ' 684:  e3a03c73   mov  r3, #29440  @ 0x7300\n'
                  ' 688:  e38330e0   orr  r3, r3, #224  @ 0xe0\n'
                  ' 68c:  e1cd31b8   strh  r3, [sp, #24]\n'
                  ' 690:  e3a03c73   mov  r3, #29440  @ 0x7300\n'
                  ' 694:  e38330c0   orr  r3, r3, #192  @ 0xc0\n'
                  ' 698:  e1cd31b4   strh  r3, [sp, #20]\n'
                  ' 69c:  e3a03c73   mov  r3, #29440  @ 0x7300\n'
                  ' 6a0:  e3833080   orr  r3, r3, #128  @ 0x80\n'
                  ' 6a4:  e1cd31b0   strh  r3, [sp, #16]\n'
                  ' 6a8:  e3a03c73   mov  r3, #29440  @ 0x7300\n'
                  ' 6ac:  e3833000   orr  r3, r3, #0\n'
                  ' 6b0:  e1cd30bc   strh  r3, [sp, #12]\n'
                  ' 6b4:  e3a03c72   mov  r3, #29184  @ 0x7200\n'
                  ' 6b8:  e3833000   orr  r3, r3, #0\n'
                  ' 6bc:  e1cd30b8   strh  r3, [sp, #8]\n'
                  ' 6c0:  e3a03a07   mov  r3, #28672  @ 0x7000\n'
                  ' 6c4:  e3833000   orr  r3, r3, #0\n'
                  ' 6c8:  e1cd30b4   strh  r3, [sp, #4]\n'
                  ' 6cc:  e3a03c43   mov  r3, #17152  @ 0x4300\n'
                  ' 6d0:  e38330c0   orr  r3, r3, #192  @ 0xc0\n'
                  ' 6d4:  e1cd30b0   strh  r3, [sp]\n'
                  ' 6d8:  e3a03c43   mov  r3, #17152  @ 0x4300\n'
                  ' 6dc:  e3833080   orr  r3, r3, #128  @ 0x80\n'
                  ' 6e0:  e3a02c43   mov  r2, #17152  @ 0x4300\n'
                  ' 6e4:  e3822000   orr  r2, r2, #0\n'
                  ' 6e8:  e3a01c42   mov  r1, #16896  @ 0x4200\n'
                  ' 6ec:  e3811000   orr  r1, r1, #0\n'
                  ' 6f0:  e3a00901   mov  r0, #16384  @ 0x4000\n'
                  ' 6f4:  e3800000   orr  r0, r0, #0\n'
                  ' 6f8:  ebfffed7   bl  25c <foo_11>\n'
                  '         768, 896, 960, 992, 1008, 1016);\n'
                  '\n'
                  '  foo_12();\n'
                  ' 6fc:  ebfffee3   bl  290 <foo_12>\n'
                  '  foo_13();\n'
                  ' 700:  ebfffeea   bl  2b0 <foo_13>\n'
                  '  foo_14();\n'
                  ' 704:  ebfffef5   bl  2e0 <foo_14>\n'
                  '  foo_15();\n'
                  ' 708:  ebffff12   bl  358 <foo_15>\n'
                  '  foo_16();\n'
                  ' 70c:  ebffff19   bl  378 <foo_16>\n'
                  '  foo_17();\n'
                  ' 710:  ebffff1f   bl  394 <foo_17>\n'
                  '  foo_19();\n'
                  ' 714:  ebffff28   bl  3bc <foo_19>\n'
                  '  foo_20(0x1234);\n'
                  ' 718:  e59f0094   ldr  r0, [pc, #148]  @ 7b4 '
                  '<__entry__+0x368>\n'
                  ' 71c:  ebffff2c   bl  3d4 <foo_20>\n'
                  '  foo_21((unsigned char *) 0xC0DEC0FE);\n'
                  ' 720:  e59f0090   ldr  r0, [pc, #144]  @ 7b8 '
                  '<__entry__+0x36c>\n'
                  ' 724:  ebffff34   bl  3fc <foo_21>\n'
                  '  foo_22((unsigned char **) 0xC0FEC0DE);\n'
                  ' 728:  e59f008c   ldr  r0, [pc, #140]  @ 7bc '
                  '<__entry__+0x370>\n'
                  ' 72c:  ebffff3c   bl  424 <foo_22>\n'
                  '\n'
                  '#ifdef WITH_FP_HARD\n'
                  '  foo_18();\n'
                  '#endif\n'
                  '}\n'
                  ' 730:  e320f000   nop  {0}\n'
                  ' 734:  e24bd004   sub  sp, fp, #4\n'
                  ' 738:  e8bd8800   pop  {fp, pc}\n'
                  ' 73c:  e320f000   nop  {0}\n'
                  ' 740:  090a0b0c   .word  0x090a0b0c\n'
                  ' 744:  05060708   .word  0x05060708\n'
                  ' 748:  14131211   .word  0x14131211\n'
                  ' 74c:  18171615   .word  0x18171615\n'
                  ' 750:  0c0b0a09   .word  0x0c0b0a09\n'
                  ' 754:  100f0e0d   .word  0x100f0e0d\n'
                  ' 758:  04030201   .word  0x04030201\n'
                  ' 75c:  08070605   .word  0x08070605\n'
                  ' 760:  0d0e0f10   .word  0x0d0e0f10\n'
                  ' 764:  090a0b0c   .word  0x090a0b0c\n'
                  ' 768:  05060708   .word  0x05060708\n'
                  ' 76c:  01020304   .word  0x01020304\n'
                  ' 770:  1c1b1a19   .word  0x1c1b1a19\n'
                  ' 774:  000007c4   .word  0x000007c4\n'
                  ' 778:  000007d0   .word  0x000007d0\n'
                  ' 77c:  3f600000   .word  0x3f600000\n'
                  ' 780:  3fe80000   .word  0x3fe80000\n'
                  ' 784:  3f7c0000   .word  0x3f7c0000\n'
                  ' 788:  000007e8   .word  0x000007e8\n'
                  ' 78c:  3fdff800   .word  0x3fdff800\n'
                  ' 790:  3fdff000   .word  0x3fdff000\n'
                  ' 794:  3fdfe000   .word  0x3fdfe000\n'
                  ' 798:  3fdfc000   .word  0x3fdfc000\n'
                  ' 79c:  3fdf8000   .word  0x3fdf8000\n'
                  ' 7a0:  3fdf0000   .word  0x3fdf0000\n'
                  ' 7a4:  3fde0000   .word  0x3fde0000\n'
                  ' 7a8:  3fdc0000   .word  0x3fdc0000\n'
                  ' 7ac:  3fd80000   .word  0x3fd80000\n'
                  ' 7b0:  3fd00000   .word  0x3fd00000\n'
                  ' 7b4:  00001234   .word  0x00001234\n'
                  ' 7b8:  c0dec0fe   .word  0xc0dec0fe\n'
                  ' 7bc:  c0fec0de   .word  0xc0fec0de\n',
   'mapped_blobs': [{'loading_address': 0,
                     'blob': b'\x06\x00\x00\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\x80\x00\xc0\xe3\x00\xf0\x29\xe1\x01\xd9\xa0\xe3\x06\x01\x00\xeb\x00\x00\xa0\xe1\xfe\xff\xff\xea\xf0\x5f\x2d\xe9\x1c\x40\x9f\xe5\x04\x40\x2d\xe5\x00\x00\xa0\xe1\x00\x00\xa0\xe1\x00\x00\xa0\xe1\x00\x00\xa0\xe1\x00\x00\xa0\xe1\x04\x00\x9d\xe4\xf0\x9f\xbd\xe8\xbe\xba\xef\xbe\x00\x00\x00\x00\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x14\xd0\x4d\xe2\x08\x00\x0b\xe5\x0c\x10\x0b\xe5\x10\x20\x0b\xe5\x14\x30\x0b\xe5\x0c\x30\x9f\xe5\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x04\x03\x02\x01\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x14\xd0\x4d\xe2\x08\x00\x0b\xe5\xf4\x21\x4b\xe1\x18\x30\x8f\xe2\xd0\x20\xc3\xe1\x02\x00\xa0\xe1\x03\x10\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x00\xf0\x20\xe3\x08\x07\x06\x05\x04\x03\x02\x01\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x14\xd0\x4d\xe2\xfc\x00\x4b\xe1\xf4\x21\x4b\xe1\x14\x30\x8f\xe2\xd0\x20\xc3\xe1\x02\x00\xa0\xe1\x03\x10\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x08\x07\x06\x05\x04\x03\x02\x01\x08\xd0\x4d\xe2\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\xd0\x4d\xe2\x08\x00\x0b\xe5\x0c\x10\x0b\xe5\x04\x10\x8b\xe2\x0c\x00\x81\xe8\x01\x30\xa0\xe3\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x08\xd0\x8d\xe2\x1e\xff\x2f\xe1\x10\xd0\x4d\xe2\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x04\xc0\x8b\xe2\x0f\x00\x8c\xe8\x01\x30\xa0\xe3\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x10\xd0\x8d\xe2\x1e\xff\x2f\xe1\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\xd0\x4d\xe2\x08\x00\x4b\xe5\x41\x30\xa0\xe3\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x14\xd0\x4d\xe2\x08\x00\x0b\xe5\x0c\x10\x0b\xe5\x10\x20\x0b\xe5\x0c\x30\x9f\xe5\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x00\x00\x70\x3f\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x14\xd0\x4d\xe2\x08\x00\x0b\xe5\x0c\x10\x0b\xe5\x10\x20\x0b\xe5\x0c\x30\x9f\xe5\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x00\x00\x70\x3f\x10\xd0\x4d\xe2\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x04\xc0\x8b\xe2\x0f\x00\x8c\xe8\x10\x30\x9f\xe5\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x10\xd0\x8d\xe2\x1e\xff\x2f\xe1\x00\x00\x70\x3f\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x14\xd0\x4d\xe2\xfc\x00\x4b\xe1\xf4\x21\x4b\xe1\x00\x20\xa0\xe3\x10\x30\x9f\xe5\x02\x00\xa0\xe1\x03\x10\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x00\x00\xd0\x3f\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\xd0\x4d\xe2\xb6\x00\x4b\xe1\xb8\x10\x4b\xe1\xba\x20\x4b\xe1\xbc\x30\x4b\xe1\x0d\x3b\xa0\xe3\x00\x30\x83\xe3\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\x30\x9f\xe5\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\xcd\xab\x00\x00\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x18\x30\x8f\xe2\xd0\x20\xc3\xe1\x02\x00\xa0\xe1\x03\x10\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x00\xf0\x20\xe3\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\xd0\x4d\xe2\x60\x20\x9f\xe5\x08\x30\x4b\xe2\x00\x20\x92\xe5\xb0\x20\xc3\xe1\x02\x30\x83\xe2\x22\x28\xa0\xe1\x00\x20\xc3\xe5\x00\x30\xa0\xe3\x08\x20\x5b\xe5\x72\x20\xef\xe6\xff\x30\xc3\xe3\x03\x30\x82\xe1\x07\x20\x5b\xe5\x72\x20\xef\xe6\xff\x3c\xc3\xe3\x02\x24\xa0\xe1\x03\x30\x82\xe1\x06\x20\x5b\xe5\x72\x20\xef\xe6\xff\x38\xc3\xe3\x02\x28\xa0\xe1\x03\x30\x82\xe1\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\xc0\x07\x00\x00\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x43\x3c\xa0\xe3\xc0\x30\x83\xe3\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\xfd\x35\xa0\xe3\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x00\x20\xa0\xe3\x10\x30\x9f\xe5\x02\x00\xa0\xe1\x03\x10\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x00\x00\xe8\x3f\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x00\xf0\x20\xe3\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\xd0\x4d\xe2\x00\x30\xa0\xe1\xb6\x30\x4b\xe1\x01\x30\xa0\xe3\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\xd0\x4d\xe2\x08\x00\x0b\xe5\x0c\x30\x9f\xe5\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\xbe\xba\xde\xba\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\xd0\x4d\xe2\x08\x00\x0b\xe5\x0c\x30\x9f\xe5\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\xde\xba\xbe\xba\x00\x48\x2d\xe9\x04\xb0\x8d\xe2\x88\xd0\x4d\xe2\xf6\xfe\xff\xeb\xfc\x32\x9f\xe5\xfc\x22\x9f\xe5\xfc\x12\x9f\xe5\xfc\x02\x9f\xe5\xfd\xfe\xff\xeb\xb2\x3f\x8f\xe2\xd0\x20\xc3\xe1\xec\x02\x9f\xe5\x06\xff\xff\xeb\xe8\x32\x9f\xe5\x18\x30\x8d\xe5\x4a\x30\xa0\xe3\x14\x30\x8d\xe5\x4b\x30\xa0\xe3\x10\x30\x8d\xe5\xaa\x3f\x8f\xe2\xd0\x20\xc3\xe1\xf8\x20\xcd\xe1\x41\x30\xa0\xe3\x00\x30\x8d\xe5\xa7\x3f\x8f\xe2\xd0\x20\xc3\xe1\xa7\x1f\x8f\xe2\xd0\x00\xc1\xe1\x05\xff\xff\xeb\xac\x22\x9f\xe5\x10\x30\x4b\xe2\x07\x00\x92\xe8\x07\x00\x83\xe8\x08\x30\x1b\xe5\x00\x30\x8d\xe5\x10\x30\x4b\xe2\x0c\x00\x93\xe8\x03\x10\xa0\xe3\x01\x00\xa0\xe3\x08\xff\xff\xeb\x84\x32\x9f\xe5\x2c\xc0\x4b\xe2\x03\xe0\xa0\xe1\x0f\x00\xbe\xe8\x0f\x00\xac\xe8\x03\x00\x9e\xe8\x03\x00\x8c\xe8\x0d\x20\xa0\xe1\x1c\x30\x4b\xe2\x03\x00\x93\xe8\x03\x00\x82\xe8\x2c\x30\x4b\xe2\x0f\x00\x93\xe8\x08\xff\xff\xeb\x61\x30\xa0\xe3\x03\x00\xa0\xe1\x10\xff\xff\xeb\x44\x32\x9f\xe5\x08\x30\x8d\xe5\x00\x20\xa0\xe3\x3c\x32\x9f\xe5\xf0\x20\xcd\xe1\x08\x20\xa0\xe3\x3f\x14\xa0\xe3\x04\x00\xa0\xe3\x10\xff\xff\xeb\x28\x32\x9f\xe5\x0c\x30\x8d\xe5\x3b\x3c\xa0\xe3\x00\x30\x83\xe3\xb8\x30\xcd\xe1\x00\x20\xa0\xe3\x0c\x32\x9f\xe5\xf0\x20\xcd\xe1\x08\x20\xa0\xe3\x3f\x14\xa0\xe3\x04\x00\xa0\xe3\x10\xff\xff\xeb\xfc\x31\x9f\xe5\x4c\xc0\x4b\xe2\x03\xe0\xa0\xe1\x0f\x00\xbe\xe8\x0f\x00\xac\xe8\x0f\x00\x9e\xe8\x0f\x00\x8c\xe8\x0d\xc0\xa0\xe1\x3c\x30\x4b\xe2\x0f\x00\x93\xe8\x0f\x00\x8c\xe8\x4c\x30\x4b\xe2\x0f\x00\x93\xe8\x0e\xff\xff\xeb\x00\x20\xa0\xe3\xc4\x31\x9f\xe5\xf8\x23\xcd\xe1\x00\x20\xa0\xe3\xbc\x31\x9f\xe5\xf0\x23\xcd\xe1\x00\x20\xa0\xe3\xb4\x31\x9f\xe5\xf8\x22\xcd\xe1\x00\x20\xa0\xe3\xac\x31\x9f\xe5\xf0\x22\xcd\xe1\x00\x20\xa0\xe3\xa4\x31\x9f\xe5\xf8\x21\xcd\xe1\x00\x20\xa0\xe3\x9c\x31\x9f\xe5\xf0\x21\xcd\xe1\x00\x20\xa0\xe3\x94\x31\x9f\xe5\xf8\x20\xcd\xe1\x00\x20\xa0\xe3\x8c\x31\x9f\xe5\xf0\x20\xcd\xe1\x00\x20\xa0\xe3\x84\x31\x9f\xe5\x00\x00\xa0\xe3\x80\x11\x9f\xe5\xfd\xfe\xff\xeb\x63\x3c\xa0\xe3\xf0\x30\x83\xe3\xb4\x33\xcd\xe1\x63\x3c\xa0\xe3\xe0\x30\x83\xe3\xb0\x33\xcd\xe1\x63\x3c\xa0\xe3\xc0\x30\x83\xe3\xbc\x32\xcd\xe1\x63\x3c\xa0\xe3\x80\x30\x83\xe3\xb8\x32\xcd\xe1\x63\x3c\xa0\xe3\x00\x30\x83\xe3\xb4\x32\xcd\xe1\x62\x3c\xa0\xe3\x00\x30\x83\xe3\xb0\x32\xcd\xe1\x06\x3a\xa0\xe3\x00\x30\x83\xe3\xbc\x31\xcd\xe1\x73\x3c\xa0\xe3\xe0\x30\x83\xe3\xb8\x31\xcd\xe1\x73\x3c\xa0\xe3\xc0\x30\x83\xe3\xb4\x31\xcd\xe1\x73\x3c\xa0\xe3\x80\x30\x83\xe3\xb0\x31\xcd\xe1\x73\x3c\xa0\xe3\x00\x30\x83\xe3\xbc\x30\xcd\xe1\x72\x3c\xa0\xe3\x00\x30\x83\xe3\xb8\x30\xcd\xe1\x07\x3a\xa0\xe3\x00\x30\x83\xe3\xb4\x30\xcd\xe1\x43\x3c\xa0\xe3\xc0\x30\x83\xe3\xb0\x30\xcd\xe1\x43\x3c\xa0\xe3\x80\x30\x83\xe3\x43\x2c\xa0\xe3\x00\x20\x82\xe3\x42\x1c\xa0\xe3\x00\x10\x81\xe3\x01\x09\xa0\xe3\x00\x00\x80\xe3\xd7\xfe\xff\xeb\xe3\xfe\xff\xeb\xea\xfe\xff\xeb\xf5\xfe\xff\xeb\x12\xff\xff\xeb\x19\xff\xff\xeb\x1f\xff\xff\xeb\x28\xff\xff\xeb\x94\x00\x9f\xe5\x2c\xff\xff\xeb\x90\x00\x9f\xe5\x34\xff\xff\xeb\x8c\x00\x9f\xe5\x3c\xff\xff\xeb\x00\xf0\x20\xe3\x04\xd0\x4b\xe2\x00\x88\xbd\xe8\x00\xf0\x20\xe3\x0c\x0b\x0a\x09\x08\x07\x06\x05\x11\x12\x13\x14\x15\x16\x17\x18\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\x10\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01\x19\x1a\x1b\x1c\xc4\x07\x00\x00\xd0\x07\x00\x00\x00\x00\x60\x3f\x00\x00\xe8\x3f\x00\x00\x7c\x3f\xe8\x07\x00\x00\x00\xf8\xdf\x3f\x00\xf0\xdf\x3f\x00\xe0\xdf\x3f\x00\xc0\xdf\x3f\x00\x80\xdf\x3f\x00\x00\xdf\x3f\x00\x00\xde\x3f\x00\x00\xdc\x3f\x00\x00\xd8\x3f\x00\x00\xd0\x3f\x34\x12\x00\x00\xfe\xc0\xde\xc0\xde\xc0\xfe\xc0\x49\x4a\x4b\x00\x12\x11\x10\x0f\x16\x15\x14\x13\x20\x19\x18\x17\x61\x00\x10\x0f\x14\x13\x12\x11\x62\x00\x00\x00\x00\x00\x00\x00\x1c\x1b\x1a\x19\x18\x17\x16\x15\x00\x00\x00\x00\x00\x00\xe0\x3f\x00\x00\x00\x00\x00\x00\xe8\x3f\x00\x00\x00\x00\x00\x00\xec\x3f\x00\x00\x00\x00\x00\x80\xef\x3f'}],
   'extra': {}}

BlobCcAapcs32ArmelV6SoftFloatFp16Ieee = MetaBinBlob.from_dict(meta_blob_cc_aapcs32_armel_v6_soft_float_fp16_ieee)


from ...cc.source_code_analyzer import MetaSourceCode

meta_source_code_cc_aapcs32_armel_v6_soft_float_fp16_ieee = \
  {'cc_call_test_info': {'cc_call_test_stack_canary': 3203381950,
                         'cc_call_test_call_site': 76,
                         'cc_call_test_wrapper': {'address': 56,
                                                  'size': 0,
                                                  'name': 'cc_call_test_wrapper',
                                                  'return_value_type': 'unsigned '
                                                                       'int',
                                                  'return_value': 3203381950,
                                                  'arguments': {},
                                                  'call_arg_values': {}}},
   'skip_test_func': ['__entry__', 'cc_call_test_wrapper'],
   'func': [{'address': 104,
             'size': 52,
             'name': 'foo_01',
             'return_value_type': 'unsigned int',
             'return_value': 16909060,
             'arguments': {0: ('a', 'unsigned int'),
                           1: ('b', 'unsigned int'),
                           2: ('c', 'unsigned int'),
                           3: ('d', 'unsigned int')},
             'call_arg_values': {0: 16909060,
                                 1: 84281096,
                                 2: 151653132,
                                 3: 219025168}},
            {'address': 156,
             'size': 60,
             'name': 'foo_02',
             'return_value_type': 'unsigned long long',
             'return_value': 72623859790382856,
             'arguments': {0: ('a', 'unsigned int'),
                           1: ('b', 'unsigned long long')},
             'call_arg_values': {0: 16909060, 1: 361984551142689548}},
            {'address': 216,
             'size': 56,
             'name': 'foo_03',
             'return_value_type': 'unsigned long long',
             'return_value': 72623859790382856,
             'arguments': {0: ('a', 'unsigned long long'),
                           1: ('b', 'unsigned long long'),
                           2: ('c', 'unsigned char'),
                           3: ('d', 'unsigned long long'),
                           4: ('e', 'unsigned char'),
                           5: ('f', 'unsigned char'),
                           6: ('g', 'unsigned int')},
             'call_arg_values': {0: 578437695752307201,
                                 1: 1157159078456920585,
                                 2: 65,
                                 3: 1735880461161533969,
                                 4: 75,
                                 5: 74,
                                 6: 471538201}},
            {'address': 272,
             'size': 56,
             'name': 'foo_04',
             'return_value_type': 'unsigned int',
             'return_value': 1,
             'arguments': {0: ('a', 'unsigned int'),
                           1: ('b', 'unsigned int'),
                           2: ('c', 'struct struct_04')},
             'call_arg_values': {0: 1,
                                 1: 3,
                                 2: {'a': 252711186,
                                     'b': 320083222,
                                     'c': 387455264}}},
            {'address': 328,
             'size': 44,
             'name': 'foo_05',
             'return_value_type': 'unsigned int',
             'return_value': 1,
             'arguments': {0: ('aggregate', 'struct struct_05')},
             'call_arg_values': {0: {'a': 97,
                                     'b': 3856,
                                     'c': 286397204,
                                     'd': 98,
                                     'e': 1519427316551916316}}},
            {'address': 372,
             'size': 36,
             'name': 'foo_06',
             'return_value_type': 'struct struct_06',
             'return_value': {'a': 65},
             'arguments': {0: ('aggregate', 'struct struct_06')},
             'call_arg_values': {0: {'a': 97}}},
            {'address': 408,
             'size': 48,
             'name': 'foo_07',
             'return_value_type': 'float',
             'return_value': 0.9375,
             'arguments': {0: ('a', 'int'),
                           1: ('x', 'float'),
                           2: ('b', 'int'),
                           3: ('y', 'double'),
                           4: ('z', 'float')},
             'call_arg_values': {0: 4, 1: 0.5, 2: 8, 3: 0.75, 4: 0.875}},
            {'address': 456,
             'size': 48,
             'name': 'foo_08',
             'return_value_type': 'float',
             'return_value': 0.9375,
             'arguments': {0: ('a', 'int'),
                           1: ('b', 'float'),
                           2: ('c', 'int'),
                           3: ('d', 'double'),
                           4: ('e', '__fp16'),
                           5: ('f', 'float')},
             'call_arg_values': {0: 4,
                                 1: 0.5,
                                 2: 8,
                                 3: 0.75,
                                 4: 0.875,
                                 5: 0.984375}},
            {'address': 504,
             'size': 48,
             'name': 'foo_09',
             'return_value_type': 'float',
             'return_value': 0.9375,
             'arguments': {0: ('a', 'struct struct_09_4')},
             'call_arg_values': {0: {'a': {'a': 0.5, 'b': 0.75},
                                     'wrap': {'b': {'c': 0.875,
                                                    'd': 0.984375}}}}},
            {'address': 552,
             'size': 52,
             'name': 'foo_10',
             'return_value_type': 'double',
             'return_value': 0.25,
             'arguments': {0: ('x1', 'double'),
                           1: ('x2', 'double'),
                           2: ('x3', 'double'),
                           3: ('x4', 'double'),
                           4: ('x5', 'double'),
                           5: ('x6', 'double'),
                           6: ('x7', 'double'),
                           7: ('x8', 'double'),
                           8: ('x9', 'double'),
                           9: ('x10', 'double')},
             'call_arg_values': {0: 0.25,
                                 1: 0.375,
                                 2: 0.4375,
                                 3: 0.46875,
                                 4: 0.484375,
                                 5: 0.4921875,
                                 6: 0.49609375,
                                 7: 0.498046875,
                                 8: 0.4990234375,
                                 9: 0.49951171875}},
            {'address': 604,
             'size': 52,
             'name': 'foo_11',
             'return_value_type': '__fp16',
             'return_value': 0.25,
             'arguments': {0: ('x1', '__fp16'),
                           1: ('x2', '__fp16'),
                           2: ('x3', '__fp16'),
                           3: ('x4', '__fp16'),
                           4: ('x5', '__fp16'),
                           5: ('x6', '__fp16'),
                           6: ('x7', '__fp16'),
                           7: ('x8', '__fp16'),
                           8: ('x9', '__fp16'),
                           9: ('x10', '__fp16'),
                           10: ('x11', '__fp16'),
                           11: ('x12', '__fp16'),
                           12: ('x13', '__fp16'),
                           13: ('x14', '__fp16'),
                           14: ('x15', '__fp16'),
                           15: ('x16', '__fp16'),
                           16: ('x17', '__fp16'),
                           17: ('x18', '__fp16')},
             'call_arg_values': {0: 2,
                                 1: 3,
                                 2: 3.5,
                                 3: 3.75,
                                 4: 3.875,
                                 5: 8192,
                                 6: 12288,
                                 7: 14336,
                                 8: 15360,
                                 9: 15872,
                                 10: 16128,
                                 11: 512,
                                 12: 768,
                                 13: 896,
                                 14: 960,
                                 15: 992,
                                 16: 1008,
                                 17: 1016}},
            {'address': 656,
             'size': 32,
             'name': 'foo_12',
             'return_value_type': 'unsigned short',
             'return_value': 43981,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 688,
             'size': 48,
             'name': 'foo_13',
             'return_value_type': 'unsigned long long',
             'return_value': 18441921395520346504,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 736,
             'size': 120,
             'name': 'foo_14',
             'return_value_type': 'struct struct_14',
             'return_value': {'a': 73, 'b': 74, 'c': 75},
             'arguments': {},
             'call_arg_values': {}},
            {'address': 856,
             'size': 32,
             'name': 'foo_15',
             'return_value_type': '__fp16',
             'return_value': 3.875,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 888,
             'size': 28,
             'name': 'foo_16',
             'return_value_type': 'float',
             'return_value': 0.75,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 916,
             'size': 40,
             'name': 'foo_17',
             'return_value_type': 'double',
             'return_value': 0.75,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 956,
             'size': 24,
             'name': 'foo_19',
             'return_value_type': None,
             'return_value': None,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 980,
             'size': 40,
             'name': 'foo_20',
             'return_value_type': 'unsigned int',
             'return_value': 1,
             'arguments': {0: ('a', 'unsigned short')},
             'call_arg_values': {0: 4660}},
            {'address': 1020,
             'size': 40,
             'name': 'foo_21',
             'return_value_type': 'unsigned char*',
             'return_value': 3135158974,
             'arguments': {0: ('a', 'unsigned char*')},
             'call_arg_values': {0: 3235823870}},
            {'address': 1060,
             'size': 40,
             'name': 'foo_22',
             'return_value_type': 'unsigned char**',
             'return_value': 3133061854,
             'arguments': {0: ('a', 'unsigned char**')},
             'call_arg_values': {0: 3237920990}},
            {'address': 1100,
             'size': 884,
             'name': '__entry__',
             'return_value_type': None,
             'return_value': None,
             'arguments': {},
             'call_arg_values': {}}],
   'cpp_source': '# 0 "entry.c"\n'
                 '# 0 "<built-in>"\n'
                 '# 0 "<command-line>"\n'
                 '# 1 "entry.c"\n'
                 '# 24 "entry.c"\n'
                 'unsigned int foo_01(unsigned int a, unsigned int b, unsigned '
                 'int c,\n'
                 '                    unsigned int d)\n'
                 '{\n'
                 '  return 0x01020304;\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'unsigned long long foo_02(unsigned int a, unsigned long long '
                 'b)\n'
                 '{\n'
                 '  return 0x0102030405060708;\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'unsigned long long foo_03(unsigned long long a,\n'
                 '                          unsigned long long b,\n'
                 '                          unsigned char c,\n'
                 '                          unsigned long long d,\n'
                 '                          unsigned char e,\n'
                 '                          unsigned char f,\n'
                 '                          unsigned int g)\n'
                 '{\n'
                 '  return 0x0102030405060708;\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'struct struct_04 { unsigned int a; unsigned int b; unsigned '
                 'int c; };\n'
                 '\n'
                 'unsigned int foo_04(unsigned int a, unsigned int b, struct '
                 'struct_04 c)\n'
                 '{\n'
                 '  return 1;\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'struct struct_05 { char a; short b; unsigned int c; char d; '
                 'long long e; };\n'
                 '\n'
                 'unsigned int foo_05(struct struct_05 aggregate)\n'
                 '{\n'
                 '  return 1;\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'struct struct_06 { unsigned char a; };\n'
                 '\n'
                 'struct struct_06 foo_06(struct struct_06 aggregate)\n'
                 '{\n'
                 "  return (struct struct_06){.a='A'};\n"
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'float foo_07(int a, float x, int b, double y, float z)\n'
                 '{\n'
                 '  return 0.9375;\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'float foo_08(int a, float b, int c, double d, __fp16 e, '
                 'float f)\n'
                 '{\n'
                 '  return 0.9375;\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'struct struct_09_1 { double a; double b; };\n'
                 'struct struct_09_2 { double c; double d; };\n'
                 'struct struct_09_3 { struct struct_09_2 b; };\n'
                 'struct struct_09_4 { struct struct_09_1 a; struct '
                 'struct_09_3 wrap; };\n'
                 '\n'
                 'float foo_09(struct struct_09_4 a)\n'
                 '{\n'
                 '  return 0.9375;\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'double foo_10(double x1, double x2, double x3, double x4,\n'
                 '              double x5, double x6, double x7, double x8,\n'
                 '              double x9, double x10)\n'
                 '{\n'
                 '  return 0.25;\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 '__fp16 foo_11(__fp16 x1, __fp16 x2, __fp16 x3, __fp16 x4, '
                 '__fp16 x5, __fp16 x6,\n'
                 '              __fp16 x7, __fp16 x8, __fp16 x9, __fp16 x10, '
                 '__fp16 x11,\n'
                 '              __fp16 x12, __fp16 x13, __fp16 x14, __fp16 '
                 'x15, __fp16 x16,\n'
                 '              __fp16 x17, __fp16 x18)\n'
                 '{\n'
                 '  return 0.25;\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'unsigned short foo_12(void)\n'
                 '{\n'
                 '  return 0xabcd;\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'unsigned long long foo_13(void)\n'
                 '{\n'
                 '  return 0xffeeddccbbaa9988;;\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'struct struct_14 { unsigned char a; unsigned char b; '
                 'unsigned char c; };\n'
                 '\n'
                 'struct struct_14 foo_14(void)\n'
                 '{\n'
                 "  return (struct struct_14){.a='I', .b='J', .c='K'};\n"
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 '__fp16 foo_15(void)\n'
                 '{\n'
                 '  return 3.875;\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'float foo_16(void)\n'
                 '{\n'
                 '  return 0.75;\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'double foo_17(void)\n'
                 '{\n'
                 '  return 0.75;\n'
                 '}\n'
                 '# 212 "entry.c"\n'
                 'void foo_19(void)\n'
                 '{\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'unsigned int foo_20(unsigned short a)\n'
                 '{\n'
                 '    return 1;\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'unsigned char * foo_21(unsigned char * a)\n'
                 '{\n'
                 '    return (unsigned char *) 0xBADEBABE;\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'unsigned char ** foo_22(unsigned char ** a)\n'
                 '{\n'
                 '    return (unsigned char **) 0xBABEBADE;\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'extern unsigned int cc_call_test_wrapper(void);\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'void __entry__(void)\n'
                 '{\n'
                 '  cc_call_test_wrapper();\n'
                 '\n'
                 '  foo_01(0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10);\n'
                 '\n'
                 '  foo_02(0x01020304, 0x05060708090A0B0C);\n'
                 '\n'
                 '  foo_03(0x0807060504030201, 0x100F0E0D0C0B0A09,\n'
                 "         'A', 0x1817161514131211, 'K', 'J', 0x1c1b1a19);\n"
                 '\n'
                 '  foo_04(1, 3, (struct struct_04){.a=0x0f101112, '
                 '.b=0x13141516, .c=0x17181920});\n'
                 '\n'
                 '  foo_05((struct struct_05)\n'
                 "        {.a='a', .b=0x0f10, .c=0x11121314, .d='b', "
                 '.e=0x15161718191a1b1c});\n'
                 '\n'
                 "  foo_06((struct struct_06){.a='a'});\n"
                 '\n'
                 '  foo_07(4, 0.5, 8, 0.75, 0.875);\n'
                 '\n'
                 '  foo_08(4, 0.5, 8, 0.75, 0.875, 0.984375);\n'
                 '\n'
                 '  foo_09((struct struct_09_4){.a={.a=0.5, .b=0.75},\n'
                 '                              .wrap={.b={.c=0.875, '
                 '.d=0.984375}}});\n'
                 '\n'
                 '  foo_10(0.25, 0.375, 0.4375, 0.46875, 0.484375, 0.4921875, '
                 '0.49609375,\n'
                 '         0.498046875, 0.4990234375, 0.49951171875);\n'
                 '\n'
                 '  foo_11(2, 3, 3.5, 3.75, 3.875, 8192, 12288, 14336, 15360, '
                 '15872, 16128, 512,\n'
                 '         768, 896, 960, 992, 1008, 1016);\n'
                 '\n'
                 '  foo_12();\n'
                 '  foo_13();\n'
                 '  foo_14();\n'
                 '  foo_15();\n'
                 '  foo_16();\n'
                 '  foo_17();\n'
                 '  foo_19();\n'
                 '  foo_20(0x1234);\n'
                 '  foo_21((unsigned char *) 0xC0DEC0FE);\n'
                 '  foo_22((unsigned char **) 0xC0FEC0DE);\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 '}\n'}

MetaSourceCodeCcAapcs32ArmelV6SoftFloatFp16Ieee = MetaSourceCode.from_dict(meta_source_code_cc_aapcs32_armel_v6_soft_float_fp16_ieee)

BlobCcAapcs32ArmelV6SoftFloatFp16Ieee.extra.update({"cc_test_data": MetaSourceCodeCcAapcs32ArmelV6SoftFloatFp16Ieee})
