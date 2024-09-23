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

meta_blob_cc_aapcs32_armeb_v6_soft_float_fp16_ieee = \
  {'arch_unicorn': 'arm:eb:32:1176',
   'arch_info': {'cpu_float_flag': 'FLOAT_SOFT',
                 'tag_cpu_arch': 'v6KZ',
                 'tag_cpu_name': 'ARM1176JZF-S',
                 'tag_fp_arch': None,
                 'tag_abi_fp_16bit_format': 'IEEE754'},
   'compiler': 'GCC: (Arch Repository) 13.1.0\x00',
   'producer': 'GNU C17 13.1.0 -mthumb-interwork -mcpu=arm1176jzf-s '
               '-mbig-endian -mfloat-abi=soft -mfp16-format=ieee -marm '
               '-march=armv6kz -g -O0',
   'emu_start': 0,
   'emu_end': 48,
   'mem_map': [{'name': 'rom', 'perm': 'rx', 'base_address': 0, 'size': 20480}],
   'disassembly': '\n'
                  'out.elf:     file format elf32-bigarm\n'
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
                  '  2c:  eb00010b   bl  460 <__entry__>\n'
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
                  '  b8:  e1a01003   mov  r1, r3\n'
                  '  bc:  e1a00002   mov  r0, r2\n'
                  '  c0:  e28bd000   add  sp, fp, #0\n'
                  '  c4:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  '  c8:  e12fff1e   bx  lr\n'
                  '  cc:  e320f000   nop  {0}\n'
                  '  d0:  01020304   .word  0x01020304\n'
                  '  d4:  05060708   .word  0x05060708\n'
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
                  '  f4:  e1a01003   mov  r1, r3\n'
                  '  f8:  e1a00002   mov  r0, r2\n'
                  '  fc:  e28bd000   add  sp, fp, #0\n'
                  ' 100:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 104:  e12fff1e   bx  lr\n'
                  ' 108:  01020304   .word  0x01020304\n'
                  ' 10c:  05060708   .word  0x05060708\n'
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
                  ' 180:  e50b0008   str  r0, [fp, #-8]\n'
                  "  return (struct struct_06){.a='A'};\n"
                  ' 184:  e3a03041   mov  r3, #65  @ 0x41\n'
                  '}\n'
                  ' 188:  e1a00003   mov  r0, r3\n'
                  ' 18c:  e1a00c00   lsl  r0, r0, #24\n'
                  ' 190:  e28bd000   add  sp, fp, #0\n'
                  ' 194:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 198:  e12fff1e   bx  lr\n'
                  '\n'
                  '0000019c <foo_07>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'float foo_07(int a, float x, int b, double y, float z)\n'
                  '{\n'
                  ' 19c:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 1a0:  e28db000   add  fp, sp, #0\n'
                  ' 1a4:  e24dd014   sub  sp, sp, #20\n'
                  ' 1a8:  e50b0008   str  r0, [fp, #-8]\n'
                  ' 1ac:  e50b100c   str  r1, [fp, #-12]\n'
                  ' 1b0:  e50b2010   str  r2, [fp, #-16]\n'
                  '  return 0.9375;\n'
                  ' 1b4:  e59f300c   ldr  r3, [pc, #12]  @ 1c8 <foo_07+0x2c>\n'
                  '}\n'
                  ' 1b8:  e1a00003   mov  r0, r3\n'
                  ' 1bc:  e28bd000   add  sp, fp, #0\n'
                  ' 1c0:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 1c4:  e12fff1e   bx  lr\n'
                  ' 1c8:  3f700000   .word  0x3f700000\n'
                  '\n'
                  '000001cc <foo_08>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'float foo_08(int a, float b, int c, double d, __fp16 e, '
                  'float f)\n'
                  '{\n'
                  ' 1cc:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 1d0:  e28db000   add  fp, sp, #0\n'
                  ' 1d4:  e24dd014   sub  sp, sp, #20\n'
                  ' 1d8:  e50b0008   str  r0, [fp, #-8]\n'
                  ' 1dc:  e50b100c   str  r1, [fp, #-12]\n'
                  ' 1e0:  e50b2010   str  r2, [fp, #-16]\n'
                  '  return 0.9375;\n'
                  ' 1e4:  e59f300c   ldr  r3, [pc, #12]  @ 1f8 <foo_08+0x2c>\n'
                  '}\n'
                  ' 1e8:  e1a00003   mov  r0, r3\n'
                  ' 1ec:  e28bd000   add  sp, fp, #0\n'
                  ' 1f0:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 1f4:  e12fff1e   bx  lr\n'
                  ' 1f8:  3f700000   .word  0x3f700000\n'
                  '\n'
                  '000001fc <foo_09>:\n'
                  'struct struct_09_2 { double c; double d; };\n'
                  'struct struct_09_3 { struct struct_09_2 b; };\n'
                  'struct struct_09_4 { struct struct_09_1 a; struct '
                  'struct_09_3 wrap; };\n'
                  '\n'
                  'float foo_09(struct struct_09_4 a)\n'
                  '{\n'
                  ' 1fc:  e24dd010   sub  sp, sp, #16\n'
                  ' 200:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 204:  e28db000   add  fp, sp, #0\n'
                  ' 208:  e28bc004   add  ip, fp, #4\n'
                  ' 20c:  e88c000f   stm  ip, {r0, r1, r2, r3}\n'
                  '  return 0.9375;\n'
                  ' 210:  e59f3010   ldr  r3, [pc, #16]  @ 228 <foo_09+0x2c>\n'
                  '}\n'
                  ' 214:  e1a00003   mov  r0, r3\n'
                  ' 218:  e28bd000   add  sp, fp, #0\n'
                  ' 21c:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 220:  e28dd010   add  sp, sp, #16\n'
                  ' 224:  e12fff1e   bx  lr\n'
                  ' 228:  3f700000   .word  0x3f700000\n'
                  '\n'
                  '0000022c <foo_10>:\n'
                  '// force aapcs32 c2 rule vfp registers with double.\n'
                  '//##############################################################################\n'
                  'double foo_10(double x1, double x2, double x3, double x4,\n'
                  '              double x5, double x6, double x7, double x8,\n'
                  '              double x9, double x10)\n'
                  '{\n'
                  ' 22c:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 230:  e28db000   add  fp, sp, #0\n'
                  ' 234:  e24dd014   sub  sp, sp, #20\n'
                  ' 238:  e14b00fc   strd  r0, [fp, #-12]\n'
                  ' 23c:  e14b21f4   strd  r2, [fp, #-20]  @ 0xffffffec\n'
                  '  return 0.25;\n'
                  ' 240:  e3a03000   mov  r3, #0\n'
                  ' 244:  e59f2010   ldr  r2, [pc, #16]  @ 25c <foo_10+0x30>\n'
                  '}\n'
                  ' 248:  e1a01003   mov  r1, r3\n'
                  ' 24c:  e1a00002   mov  r0, r2\n'
                  ' 250:  e28bd000   add  sp, fp, #0\n'
                  ' 254:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 258:  e12fff1e   bx  lr\n'
                  ' 25c:  3fd00000   .word  0x3fd00000\n'
                  '\n'
                  '00000260 <foo_11>:\n'
                  '//#############################################################################\n'
                  '__fp16 foo_11(__fp16 x1, __fp16 x2, __fp16 x3, __fp16 x4, '
                  '__fp16 x5, __fp16 x6,\n'
                  '              __fp16 x7, __fp16 x8, __fp16 x9, __fp16 x10, '
                  '__fp16 x11,\n'
                  '              __fp16 x12, __fp16 x13, __fp16 x14, __fp16 '
                  'x15, __fp16 x16,\n'
                  '              __fp16 x17, __fp16 x18)\n'
                  '{\n'
                  ' 260:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 264:  e28db000   add  fp, sp, #0\n'
                  ' 268:  e24dd00c   sub  sp, sp, #12\n'
                  ' 26c:  e14b00b6   strh  r0, [fp, #-6]\n'
                  ' 270:  e14b10b8   strh  r1, [fp, #-8]\n'
                  ' 274:  e14b20ba   strh  r2, [fp, #-10]\n'
                  ' 278:  e14b30bc   strh  r3, [fp, #-12]\n'
                  '  return 0.25;\n'
                  ' 27c:  e3a03b0d   mov  r3, #13312  @ 0x3400\n'
                  ' 280:  e3833000   orr  r3, r3, #0\n'
                  '}\n'
                  ' 284:  e1a00003   mov  r0, r3\n'
                  ' 288:  e28bd000   add  sp, fp, #0\n'
                  ' 28c:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 290:  e12fff1e   bx  lr\n'
                  '\n'
                  '00000294 <foo_12>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '// Return fundamental type smaller than a word.\n'
                  '//##############################################################################\n'
                  'unsigned short foo_12(void)\n'
                  '{\n'
                  ' 294:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 298:  e28db000   add  fp, sp, #0\n'
                  '  return 0xabcd;\n'
                  ' 29c:  e59f300c   ldr  r3, [pc, #12]  @ 2b0 <foo_12+0x1c>\n'
                  '}\n'
                  ' 2a0:  e1a00003   mov  r0, r3\n'
                  ' 2a4:  e28bd000   add  sp, fp, #0\n'
                  ' 2a8:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 2ac:  e12fff1e   bx  lr\n'
                  ' 2b0:  0000abcd   .word  0x0000abcd\n'
                  '\n'
                  '000002b4 <foo_13>:\n'
                  '\n'
                  '//#############################################################################\n'
                  '// Return fundamental type with double word size.\n'
                  '//#############################################################################\n'
                  'unsigned long long foo_13(void)\n'
                  '{\n'
                  ' 2b4:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 2b8:  e28db000   add  fp, sp, #0\n'
                  '  return 0xffeeddccbbaa9988;;\n'
                  ' 2bc:  e28f3014   add  r3, pc, #20\n'
                  ' 2c0:  e1c320d0   ldrd  r2, [r3]\n'
                  '}\n'
                  ' 2c4:  e1a01003   mov  r1, r3\n'
                  ' 2c8:  e1a00002   mov  r0, r2\n'
                  ' 2cc:  e28bd000   add  sp, fp, #0\n'
                  ' 2d0:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 2d4:  e12fff1e   bx  lr\n'
                  ' 2d8:  ffeeddcc   .word  0xffeeddcc\n'
                  ' 2dc:  bbaa9988   .word  0xbbaa9988\n'
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
                  ' 2ec:  e59f2074   ldr  r2, [pc, #116]  @ 368 <foo_14+0x88>\n'
                  ' 2f0:  e24b3008   sub  r3, fp, #8\n'
                  ' 2f4:  e5922000   ldr  r2, [r2]\n'
                  ' 2f8:  e1a02422   lsr  r2, r2, #8\n'
                  ' 2fc:  e1a01002   mov  r1, r2\n'
                  ' 300:  e5c31002   strb  r1, [r3, #2]\n'
                  ' 304:  e1a02422   lsr  r2, r2, #8\n'
                  ' 308:  e1a01002   mov  r1, r2\n'
                  ' 30c:  e5c31001   strb  r1, [r3, #1]\n'
                  ' 310:  e1a02422   lsr  r2, r2, #8\n'
                  ' 314:  e5c32000   strb  r2, [r3]\n'
                  ' 318:  e3a03000   mov  r3, #0\n'
                  ' 31c:  e55b2008   ldrb  r2, [fp, #-8]\n'
                  ' 320:  e6ef2072   uxtb  r2, r2\n'
                  ' 324:  e3c334ff   bic  r3, r3, #-16777216  @ 0xff000000\n'
                  ' 328:  e1a02c02   lsl  r2, r2, #24\n'
                  ' 32c:  e1823003   orr  r3, r2, r3\n'
                  ' 330:  e55b2007   ldrb  r2, [fp, #-7]\n'
                  ' 334:  e6ef2072   uxtb  r2, r2\n'
                  ' 338:  e3c338ff   bic  r3, r3, #16711680  @ 0xff0000\n'
                  ' 33c:  e1a02802   lsl  r2, r2, #16\n'
                  ' 340:  e1823003   orr  r3, r2, r3\n'
                  ' 344:  e55b2006   ldrb  r2, [fp, #-6]\n'
                  ' 348:  e6ef2072   uxtb  r2, r2\n'
                  ' 34c:  e3c33cff   bic  r3, r3, #65280  @ 0xff00\n'
                  ' 350:  e1a02402   lsl  r2, r2, #8\n'
                  ' 354:  e1823003   orr  r3, r2, r3\n'
                  '}\n'
                  ' 358:  e1a00003   mov  r0, r3\n'
                  ' 35c:  e28bd000   add  sp, fp, #0\n'
                  ' 360:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 364:  e12fff1e   bx  lr\n'
                  ' 368:  000007d8   .word  0x000007d8\n'
                  '\n'
                  '0000036c <foo_15>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  '__fp16 foo_15(void)\n'
                  '{\n'
                  ' 36c:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 370:  e28db000   add  fp, sp, #0\n'
                  '  return 3.875;\n'
                  ' 374:  e3a03c43   mov  r3, #17152  @ 0x4300\n'
                  ' 378:  e38330c0   orr  r3, r3, #192  @ 0xc0\n'
                  '}\n'
                  ' 37c:  e1a00003   mov  r0, r3\n'
                  ' 380:  e28bd000   add  sp, fp, #0\n'
                  ' 384:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 388:  e12fff1e   bx  lr\n'
                  '\n'
                  '0000038c <foo_16>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'float foo_16(void)\n'
                  '{\n'
                  ' 38c:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 390:  e28db000   add  fp, sp, #0\n'
                  '  return 0.75;\n'
                  ' 394:  e3a035fd   mov  r3, #1061158912  @ 0x3f400000\n'
                  '}\n'
                  ' 398:  e1a00003   mov  r0, r3\n'
                  ' 39c:  e28bd000   add  sp, fp, #0\n'
                  ' 3a0:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 3a4:  e12fff1e   bx  lr\n'
                  '\n'
                  '000003a8 <foo_17>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'double foo_17(void)\n'
                  '{\n'
                  ' 3a8:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 3ac:  e28db000   add  fp, sp, #0\n'
                  '  return 0.75;\n'
                  ' 3b0:  e3a03000   mov  r3, #0\n'
                  ' 3b4:  e59f2010   ldr  r2, [pc, #16]  @ 3cc <foo_17+0x24>\n'
                  '}\n'
                  ' 3b8:  e1a01003   mov  r1, r3\n'
                  ' 3bc:  e1a00002   mov  r0, r2\n'
                  ' 3c0:  e28bd000   add  sp, fp, #0\n'
                  ' 3c4:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 3c8:  e12fff1e   bx  lr\n'
                  ' 3cc:  3fe80000   .word  0x3fe80000\n'
                  '\n'
                  '000003d0 <foo_19>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'void foo_19(void)\n'
                  '{\n'
                  ' 3d0:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 3d4:  e28db000   add  fp, sp, #0\n'
                  '}\n'
                  ' 3d8:  e320f000   nop  {0}\n'
                  ' 3dc:  e28bd000   add  sp, fp, #0\n'
                  ' 3e0:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 3e4:  e12fff1e   bx  lr\n'
                  '\n'
                  '000003e8 <foo_20>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '// Argument with size lower than a word.\n'
                  '//##############################################################################\n'
                  'unsigned int foo_20(unsigned short a)\n'
                  '{\n'
                  ' 3e8:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 3ec:  e28db000   add  fp, sp, #0\n'
                  ' 3f0:  e24dd00c   sub  sp, sp, #12\n'
                  ' 3f4:  e1a03000   mov  r3, r0\n'
                  ' 3f8:  e14b30b6   strh  r3, [fp, #-6]\n'
                  '    return 1;\n'
                  ' 3fc:  e3a03001   mov  r3, #1\n'
                  '}\n'
                  ' 400:  e1a00003   mov  r0, r3\n'
                  ' 404:  e28bd000   add  sp, fp, #0\n'
                  ' 408:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 40c:  e12fff1e   bx  lr\n'
                  '\n'
                  '00000410 <foo_21>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'unsigned char * foo_21(unsigned char * a)\n'
                  '{\n'
                  ' 410:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 414:  e28db000   add  fp, sp, #0\n'
                  ' 418:  e24dd00c   sub  sp, sp, #12\n'
                  ' 41c:  e50b0008   str  r0, [fp, #-8]\n'
                  '    return (unsigned char *) 0xBADEBABE;\n'
                  ' 420:  e59f300c   ldr  r3, [pc, #12]  @ 434 <foo_21+0x24>\n'
                  '}\n'
                  ' 424:  e1a00003   mov  r0, r3\n'
                  ' 428:  e28bd000   add  sp, fp, #0\n'
                  ' 42c:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 430:  e12fff1e   bx  lr\n'
                  ' 434:  badebabe   .word  0xbadebabe\n'
                  '\n'
                  '00000438 <foo_22>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'unsigned char ** foo_22(unsigned char ** a)\n'
                  '{\n'
                  ' 438:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 43c:  e28db000   add  fp, sp, #0\n'
                  ' 440:  e24dd00c   sub  sp, sp, #12\n'
                  ' 444:  e50b0008   str  r0, [fp, #-8]\n'
                  '    return (unsigned char **) 0xBABEBADE;\n'
                  ' 448:  e59f300c   ldr  r3, [pc, #12]  @ 45c <foo_22+0x24>\n'
                  '}\n'
                  ' 44c:  e1a00003   mov  r0, r3\n'
                  ' 450:  e28bd000   add  sp, fp, #0\n'
                  ' 454:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 458:  e12fff1e   bx  lr\n'
                  ' 45c:  babebade   .word  0xbabebade\n'
                  '\n'
                  '00000460 <__entry__>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '// Entry Point\n'
                  '//##############################################################################\n'
                  'void __entry__(void)\n'
                  '{\n'
                  ' 460:  e92d4800   push  {fp, lr}\n'
                  ' 464:  e28db004   add  fp, sp, #4\n'
                  ' 468:  e24dd088   sub  sp, sp, #136  @ 0x88\n'
                  '  cc_call_test_wrapper();\n'
                  ' 46c:  ebfffef1   bl  38 <cc_call_test_wrapper>\n'
                  '\n'
                  '  foo_01(0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10);\n'
                  ' 470:  e59f3300   ldr  r3, [pc, #768]  @ 778 '
                  '<__entry__+0x318>\n'
                  ' 474:  e59f2300   ldr  r2, [pc, #768]  @ 77c '
                  '<__entry__+0x31c>\n'
                  ' 478:  e59f1300   ldr  r1, [pc, #768]  @ 780 '
                  '<__entry__+0x320>\n'
                  ' 47c:  e59f0300   ldr  r0, [pc, #768]  @ 784 '
                  '<__entry__+0x324>\n'
                  ' 480:  ebfffef8   bl  68 <foo_01>\n'
                  '\n'
                  '  foo_02(0x01020304, 0x05060708090A0B0C);\n'
                  ' 484:  e28f3fb3   add  r3, pc, #716  @ 0x2cc\n'
                  ' 488:  e1c320d0   ldrd  r2, [r3]\n'
                  ' 48c:  e59f02f0   ldr  r0, [pc, #752]  @ 784 '
                  '<__entry__+0x324>\n'
                  ' 490:  ebffff01   bl  9c <foo_02>\n'
                  '\n'
                  '  foo_03(0x0807060504030201, 0x100F0E0D0C0B0A09,\n'
                  ' 494:  e59f32ec   ldr  r3, [pc, #748]  @ 788 '
                  '<__entry__+0x328>\n'
                  ' 498:  e58d3018   str  r3, [sp, #24]\n'
                  ' 49c:  e3a0304a   mov  r3, #74  @ 0x4a\n'
                  ' 4a0:  e58d3014   str  r3, [sp, #20]\n'
                  ' 4a4:  e3a0304b   mov  r3, #75  @ 0x4b\n'
                  ' 4a8:  e58d3010   str  r3, [sp, #16]\n'
                  ' 4ac:  e28f3fab   add  r3, pc, #684  @ 0x2ac\n'
                  ' 4b0:  e1c320d0   ldrd  r2, [r3]\n'
                  ' 4b4:  e1cd20f8   strd  r2, [sp, #8]\n'
                  ' 4b8:  e3a03041   mov  r3, #65  @ 0x41\n'
                  ' 4bc:  e58d3000   str  r3, [sp]\n'
                  ' 4c0:  e28f3e2a   add  r3, pc, #672  @ 0x2a0\n'
                  ' 4c4:  e1c320d0   ldrd  r2, [r3]\n'
                  ' 4c8:  e28f1e2a   add  r1, pc, #672  @ 0x2a0\n'
                  ' 4cc:  e1c100d0   ldrd  r0, [r1]\n'
                  ' 4d0:  ebffff00   bl  d8 <foo_03>\n'
                  "         'A', 0x1817161514131211, 'K', 'J', 0x1c1b1a19);\n"
                  '\n'
                  '  foo_04(1, 3, (struct struct_04){.a=0x0f101112, '
                  '.b=0x13141516, .c=0x17181920});\n'
                  ' 4d4:  e59f22b0   ldr  r2, [pc, #688]  @ 78c '
                  '<__entry__+0x32c>\n'
                  ' 4d8:  e24b3010   sub  r3, fp, #16\n'
                  ' 4dc:  e8920007   ldm  r2, {r0, r1, r2}\n'
                  ' 4e0:  e8830007   stm  r3, {r0, r1, r2}\n'
                  ' 4e4:  e51b3008   ldr  r3, [fp, #-8]\n'
                  ' 4e8:  e58d3000   str  r3, [sp]\n'
                  ' 4ec:  e24b3010   sub  r3, fp, #16\n'
                  ' 4f0:  e893000c   ldm  r3, {r2, r3}\n'
                  ' 4f4:  e3a01003   mov  r1, #3\n'
                  ' 4f8:  e3a00001   mov  r0, #1\n'
                  ' 4fc:  ebffff03   bl  110 <foo_04>\n'
                  '\n'
                  '  foo_05((struct struct_05)\n'
                  "        {.a='a', .b=0x0f10, .c=0x11121314, .d='b', "
                  '.e=0x15161718191a1b1c});\n'
                  ' 500:  e59f3288   ldr  r3, [pc, #648]  @ 790 '
                  '<__entry__+0x330>\n'
                  ' 504:  e24bc02c   sub  ip, fp, #44  @ 0x2c\n'
                  ' 508:  e1a0e003   mov  lr, r3\n'
                  ' 50c:  e8be000f   ldm  lr!, {r0, r1, r2, r3}\n'
                  ' 510:  e8ac000f   stmia  ip!, {r0, r1, r2, r3}\n'
                  ' 514:  e89e0003   ldm  lr, {r0, r1}\n'
                  ' 518:  e88c0003   stm  ip, {r0, r1}\n'
                  '  foo_05((struct struct_05)\n'
                  ' 51c:  e1a0200d   mov  r2, sp\n'
                  ' 520:  e24b301c   sub  r3, fp, #28\n'
                  ' 524:  e8930003   ldm  r3, {r0, r1}\n'
                  ' 528:  e8820003   stm  r2, {r0, r1}\n'
                  ' 52c:  e24b302c   sub  r3, fp, #44  @ 0x2c\n'
                  ' 530:  e893000f   ldm  r3, {r0, r1, r2, r3}\n'
                  ' 534:  ebffff03   bl  148 <foo_05>\n'
                  '\n'
                  "  foo_06((struct struct_06){.a='a'});\n"
                  ' 538:  e3a03061   mov  r3, #97  @ 0x61\n'
                  ' 53c:  e1a00003   mov  r0, r3\n'
                  ' 540:  e1a00c00   lsl  r0, r0, #24\n'
                  ' 544:  ebffff0a   bl  174 <foo_06>\n'
                  ' 548:  e1a00c40   asr  r0, r0, #24\n'
                  '\n'
                  '  foo_07(4, 0.5, 8, 0.75, 0.875);\n'
                  ' 54c:  e59f3240   ldr  r3, [pc, #576]  @ 794 '
                  '<__entry__+0x334>\n'
                  ' 550:  e58d3008   str  r3, [sp, #8]\n'
                  ' 554:  e3a03000   mov  r3, #0\n'
                  ' 558:  e59f2238   ldr  r2, [pc, #568]  @ 798 '
                  '<__entry__+0x338>\n'
                  ' 55c:  e1cd20f0   strd  r2, [sp]\n'
                  ' 560:  e3a02008   mov  r2, #8\n'
                  ' 564:  e3a0143f   mov  r1, #1056964608  @ 0x3f000000\n'
                  ' 568:  e3a00004   mov  r0, #4\n'
                  ' 56c:  ebffff0a   bl  19c <foo_07>\n'
                  '\n'
                  '  foo_08(4, 0.5, 8, 0.75, 0.875, 0.984375);\n'
                  ' 570:  e59f3224   ldr  r3, [pc, #548]  @ 79c '
                  '<__entry__+0x33c>\n'
                  ' 574:  e58d300c   str  r3, [sp, #12]\n'
                  ' 578:  e3a03c3b   mov  r3, #15104  @ 0x3b00\n'
                  ' 57c:  e3833000   orr  r3, r3, #0\n'
                  ' 580:  e1cd30b8   strh  r3, [sp, #8]\n'
                  ' 584:  e3a03000   mov  r3, #0\n'
                  ' 588:  e59f2208   ldr  r2, [pc, #520]  @ 798 '
                  '<__entry__+0x338>\n'
                  ' 58c:  e1cd20f0   strd  r2, [sp]\n'
                  ' 590:  e3a02008   mov  r2, #8\n'
                  ' 594:  e3a0143f   mov  r1, #1056964608  @ 0x3f000000\n'
                  ' 598:  e3a00004   mov  r0, #4\n'
                  ' 59c:  ebffff0a   bl  1cc <foo_08>\n'
                  '\n'
                  '  foo_09((struct struct_09_4){.a={.a=0.5, .b=0.75},\n'
                  ' 5a0:  e59f31f8   ldr  r3, [pc, #504]  @ 7a0 '
                  '<__entry__+0x340>\n'
                  ' 5a4:  e24bc04c   sub  ip, fp, #76  @ 0x4c\n'
                  ' 5a8:  e1a0e003   mov  lr, r3\n'
                  ' 5ac:  e8be000f   ldm  lr!, {r0, r1, r2, r3}\n'
                  ' 5b0:  e8ac000f   stmia  ip!, {r0, r1, r2, r3}\n'
                  ' 5b4:  e89e000f   ldm  lr, {r0, r1, r2, r3}\n'
                  ' 5b8:  e88c000f   stm  ip, {r0, r1, r2, r3}\n'
                  ' 5bc:  e1a0c00d   mov  ip, sp\n'
                  ' 5c0:  e24b303c   sub  r3, fp, #60  @ 0x3c\n'
                  ' 5c4:  e893000f   ldm  r3, {r0, r1, r2, r3}\n'
                  ' 5c8:  e88c000f   stm  ip, {r0, r1, r2, r3}\n'
                  ' 5cc:  e24b304c   sub  r3, fp, #76  @ 0x4c\n'
                  ' 5d0:  e893000f   ldm  r3, {r0, r1, r2, r3}\n'
                  ' 5d4:  ebffff08   bl  1fc <foo_09>\n'
                  '                              .wrap={.b={.c=0.875, '
                  '.d=0.984375}}});\n'
                  '\n'
                  '  foo_10(0.25, 0.375, 0.4375, 0.46875, 0.484375, 0.4921875, '
                  '0.49609375,\n'
                  ' 5d8:  e3a03000   mov  r3, #0\n'
                  ' 5dc:  e59f21c0   ldr  r2, [pc, #448]  @ 7a4 '
                  '<__entry__+0x344>\n'
                  ' 5e0:  e1cd23f8   strd  r2, [sp, #56]  @ 0x38\n'
                  ' 5e4:  e3a03000   mov  r3, #0\n'
                  ' 5e8:  e59f21b8   ldr  r2, [pc, #440]  @ 7a8 '
                  '<__entry__+0x348>\n'
                  ' 5ec:  e1cd23f0   strd  r2, [sp, #48]  @ 0x30\n'
                  ' 5f0:  e3a03000   mov  r3, #0\n'
                  ' 5f4:  e59f21b0   ldr  r2, [pc, #432]  @ 7ac '
                  '<__entry__+0x34c>\n'
                  ' 5f8:  e1cd22f8   strd  r2, [sp, #40]  @ 0x28\n'
                  ' 5fc:  e3a03000   mov  r3, #0\n'
                  ' 600:  e59f21a8   ldr  r2, [pc, #424]  @ 7b0 '
                  '<__entry__+0x350>\n'
                  ' 604:  e1cd22f0   strd  r2, [sp, #32]\n'
                  ' 608:  e3a03000   mov  r3, #0\n'
                  ' 60c:  e59f21a0   ldr  r2, [pc, #416]  @ 7b4 '
                  '<__entry__+0x354>\n'
                  ' 610:  e1cd21f8   strd  r2, [sp, #24]\n'
                  ' 614:  e3a03000   mov  r3, #0\n'
                  ' 618:  e59f2198   ldr  r2, [pc, #408]  @ 7b8 '
                  '<__entry__+0x358>\n'
                  ' 61c:  e1cd21f0   strd  r2, [sp, #16]\n'
                  ' 620:  e3a03000   mov  r3, #0\n'
                  ' 624:  e59f2190   ldr  r2, [pc, #400]  @ 7bc '
                  '<__entry__+0x35c>\n'
                  ' 628:  e1cd20f8   strd  r2, [sp, #8]\n'
                  ' 62c:  e3a03000   mov  r3, #0\n'
                  ' 630:  e59f2188   ldr  r2, [pc, #392]  @ 7c0 '
                  '<__entry__+0x360>\n'
                  ' 634:  e1cd20f0   strd  r2, [sp]\n'
                  ' 638:  e3a03000   mov  r3, #0\n'
                  ' 63c:  e59f2180   ldr  r2, [pc, #384]  @ 7c4 '
                  '<__entry__+0x364>\n'
                  ' 640:  e3a01000   mov  r1, #0\n'
                  ' 644:  e59f017c   ldr  r0, [pc, #380]  @ 7c8 '
                  '<__entry__+0x368>\n'
                  ' 648:  ebfffef7   bl  22c <foo_10>\n'
                  '         0.498046875, 0.4990234375, 0.49951171875);\n'
                  '\n'
                  '  foo_11(2, 3, 3.5, 3.75, 3.875, 8192, 12288, 14336, 15360, '
                  '15872, 16128, 512,\n'
                  ' 64c:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 650:  e38330f0   orr  r3, r3, #240  @ 0xf0\n'
                  ' 654:  e1cd33b4   strh  r3, [sp, #52]  @ 0x34\n'
                  ' 658:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 65c:  e38330e0   orr  r3, r3, #224  @ 0xe0\n'
                  ' 660:  e1cd33b0   strh  r3, [sp, #48]  @ 0x30\n'
                  ' 664:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 668:  e38330c0   orr  r3, r3, #192  @ 0xc0\n'
                  ' 66c:  e1cd32bc   strh  r3, [sp, #44]  @ 0x2c\n'
                  ' 670:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 674:  e3833080   orr  r3, r3, #128  @ 0x80\n'
                  ' 678:  e1cd32b8   strh  r3, [sp, #40]  @ 0x28\n'
                  ' 67c:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 680:  e3833000   orr  r3, r3, #0\n'
                  ' 684:  e1cd32b4   strh  r3, [sp, #36]  @ 0x24\n'
                  ' 688:  e3a03c62   mov  r3, #25088  @ 0x6200\n'
                  ' 68c:  e3833000   orr  r3, r3, #0\n'
                  ' 690:  e1cd32b0   strh  r3, [sp, #32]\n'
                  ' 694:  e3a03a06   mov  r3, #24576  @ 0x6000\n'
                  ' 698:  e3833000   orr  r3, r3, #0\n'
                  ' 69c:  e1cd31bc   strh  r3, [sp, #28]\n'
                  ' 6a0:  e3a03c73   mov  r3, #29440  @ 0x7300\n'
                  ' 6a4:  e38330e0   orr  r3, r3, #224  @ 0xe0\n'
                  ' 6a8:  e1cd31b8   strh  r3, [sp, #24]\n'
                  ' 6ac:  e3a03c73   mov  r3, #29440  @ 0x7300\n'
                  ' 6b0:  e38330c0   orr  r3, r3, #192  @ 0xc0\n'
                  ' 6b4:  e1cd31b4   strh  r3, [sp, #20]\n'
                  ' 6b8:  e3a03c73   mov  r3, #29440  @ 0x7300\n'
                  ' 6bc:  e3833080   orr  r3, r3, #128  @ 0x80\n'
                  ' 6c0:  e1cd31b0   strh  r3, [sp, #16]\n'
                  ' 6c4:  e3a03c73   mov  r3, #29440  @ 0x7300\n'
                  ' 6c8:  e3833000   orr  r3, r3, #0\n'
                  ' 6cc:  e1cd30bc   strh  r3, [sp, #12]\n'
                  ' 6d0:  e3a03c72   mov  r3, #29184  @ 0x7200\n'
                  ' 6d4:  e3833000   orr  r3, r3, #0\n'
                  ' 6d8:  e1cd30b8   strh  r3, [sp, #8]\n'
                  ' 6dc:  e3a03a07   mov  r3, #28672  @ 0x7000\n'
                  ' 6e0:  e3833000   orr  r3, r3, #0\n'
                  ' 6e4:  e1cd30b4   strh  r3, [sp, #4]\n'
                  ' 6e8:  e3a03c43   mov  r3, #17152  @ 0x4300\n'
                  ' 6ec:  e38330c0   orr  r3, r3, #192  @ 0xc0\n'
                  ' 6f0:  e1cd30b0   strh  r3, [sp]\n'
                  ' 6f4:  e3a03c43   mov  r3, #17152  @ 0x4300\n'
                  ' 6f8:  e3833080   orr  r3, r3, #128  @ 0x80\n'
                  ' 6fc:  e3a02c43   mov  r2, #17152  @ 0x4300\n'
                  ' 700:  e3822000   orr  r2, r2, #0\n'
                  ' 704:  e3a01c42   mov  r1, #16896  @ 0x4200\n'
                  ' 708:  e3811000   orr  r1, r1, #0\n'
                  ' 70c:  e3a00901   mov  r0, #16384  @ 0x4000\n'
                  ' 710:  e3800000   orr  r0, r0, #0\n'
                  ' 714:  ebfffed1   bl  260 <foo_11>\n'
                  '         768, 896, 960, 992, 1008, 1016);\n'
                  '\n'
                  '  foo_12();\n'
                  ' 718:  ebfffedd   bl  294 <foo_12>\n'
                  '  foo_13();\n'
                  ' 71c:  ebfffee4   bl  2b4 <foo_13>\n'
                  '  foo_14();\n'
                  ' 720:  ebfffeee   bl  2e0 <foo_14>\n'
                  '  foo_15();\n'
                  ' 724:  ebffff10   bl  36c <foo_15>\n'
                  '  foo_16();\n'
                  ' 728:  ebffff17   bl  38c <foo_16>\n'
                  '  foo_17();\n'
                  ' 72c:  ebffff1d   bl  3a8 <foo_17>\n'
                  '  foo_19();\n'
                  ' 730:  ebffff26   bl  3d0 <foo_19>\n'
                  '  foo_20(0x1234);\n'
                  ' 734:  e59f0090   ldr  r0, [pc, #144]  @ 7cc '
                  '<__entry__+0x36c>\n'
                  ' 738:  ebffff2a   bl  3e8 <foo_20>\n'
                  '  foo_21((unsigned char *) 0xC0DEC0FE);\n'
                  ' 73c:  e59f008c   ldr  r0, [pc, #140]  @ 7d0 '
                  '<__entry__+0x370>\n'
                  ' 740:  ebffff32   bl  410 <foo_21>\n'
                  '  foo_22((unsigned char **) 0xC0FEC0DE);\n'
                  ' 744:  e59f0088   ldr  r0, [pc, #136]  @ 7d4 '
                  '<__entry__+0x374>\n'
                  ' 748:  ebffff3a   bl  438 <foo_22>\n'
                  '\n'
                  '#ifdef WITH_FP_HARD\n'
                  '  foo_18();\n'
                  '#endif\n'
                  '}\n'
                  ' 74c:  e320f000   nop  {0}\n'
                  ' 750:  e24bd004   sub  sp, fp, #4\n'
                  ' 754:  e8bd8800   pop  {fp, pc}\n'
                  ' 758:  05060708   .word  0x05060708\n'
                  ' 75c:  090a0b0c   .word  0x090a0b0c\n'
                  ' 760:  18171615   .word  0x18171615\n'
                  ' 764:  14131211   .word  0x14131211\n'
                  ' 768:  100f0e0d   .word  0x100f0e0d\n'
                  ' 76c:  0c0b0a09   .word  0x0c0b0a09\n'
                  ' 770:  08070605   .word  0x08070605\n'
                  ' 774:  04030201   .word  0x04030201\n'
                  ' 778:  0d0e0f10   .word  0x0d0e0f10\n'
                  ' 77c:  090a0b0c   .word  0x090a0b0c\n'
                  ' 780:  05060708   .word  0x05060708\n'
                  ' 784:  01020304   .word  0x01020304\n'
                  ' 788:  1c1b1a19   .word  0x1c1b1a19\n'
                  ' 78c:  000007dc   .word  0x000007dc\n'
                  ' 790:  000007e8   .word  0x000007e8\n'
                  ' 794:  3f600000   .word  0x3f600000\n'
                  ' 798:  3fe80000   .word  0x3fe80000\n'
                  ' 79c:  3f7c0000   .word  0x3f7c0000\n'
                  ' 7a0:  00000800   .word  0x00000800\n'
                  ' 7a4:  3fdff800   .word  0x3fdff800\n'
                  ' 7a8:  3fdff000   .word  0x3fdff000\n'
                  ' 7ac:  3fdfe000   .word  0x3fdfe000\n'
                  ' 7b0:  3fdfc000   .word  0x3fdfc000\n'
                  ' 7b4:  3fdf8000   .word  0x3fdf8000\n'
                  ' 7b8:  3fdf0000   .word  0x3fdf0000\n'
                  ' 7bc:  3fde0000   .word  0x3fde0000\n'
                  ' 7c0:  3fdc0000   .word  0x3fdc0000\n'
                  ' 7c4:  3fd80000   .word  0x3fd80000\n'
                  ' 7c8:  3fd00000   .word  0x3fd00000\n'
                  ' 7cc:  00001234   .word  0x00001234\n'
                  ' 7d0:  c0dec0fe   .word  0xc0dec0fe\n'
                  ' 7d4:  c0fec0de   .word  0xc0fec0de\n',
   'mapped_blobs': [{'loading_address': 0,
                     'blob': b'\xea\x00\x00\x06\xea\xff\xff\xfe\xea\xff\xff\xfe\xea\xff\xff\xfe\xea\xff\xff\xfe\xea\xff\xff\xfe\xea\xff\xff\xfe\xea\xff\xff\xfe\xe3\xc0\x00\x80\xe1\x29\xf0\x00\xe3\xa0\xd9\x01\xeb\x00\x01\x0b\xe1\xa0\x00\x00\xea\xff\xff\xfe\xe9\x2d\x5f\xf0\xe5\x9f\x40\x1c\xe5\x2d\x40\x04\xe1\xa0\x00\x00\xe1\xa0\x00\x00\xe1\xa0\x00\x00\xe1\xa0\x00\x00\xe1\xa0\x00\x00\xe4\x9d\x00\x04\xe8\xbd\x9f\xf0\xbe\xef\xba\xbe\x00\x00\x00\x00\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x14\xe5\x0b\x00\x08\xe5\x0b\x10\x0c\xe5\x0b\x20\x10\xe5\x0b\x30\x14\xe5\x9f\x30\x0c\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x01\x02\x03\x04\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x14\xe5\x0b\x00\x08\xe1\x4b\x21\xf4\xe2\x8f\x30\x18\xe1\xc3\x20\xd0\xe1\xa0\x10\x03\xe1\xa0\x00\x02\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xe3\x20\xf0\x00\x01\x02\x03\x04\x05\x06\x07\x08\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x14\xe1\x4b\x00\xfc\xe1\x4b\x21\xf4\xe2\x8f\x30\x14\xe1\xc3\x20\xd0\xe1\xa0\x10\x03\xe1\xa0\x00\x02\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x01\x02\x03\x04\x05\x06\x07\x08\xe2\x4d\xd0\x08\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x0c\xe5\x0b\x00\x08\xe5\x0b\x10\x0c\xe2\x8b\x10\x04\xe8\x81\x00\x0c\xe3\xa0\x30\x01\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe2\x8d\xd0\x08\xe1\x2f\xff\x1e\xe2\x4d\xd0\x10\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x8b\xc0\x04\xe8\x8c\x00\x0f\xe3\xa0\x30\x01\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe2\x8d\xd0\x10\xe1\x2f\xff\x1e\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x0c\xe5\x0b\x00\x08\xe3\xa0\x30\x41\xe1\xa0\x00\x03\xe1\xa0\x0c\x00\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x14\xe5\x0b\x00\x08\xe5\x0b\x10\x0c\xe5\x0b\x20\x10\xe5\x9f\x30\x0c\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x3f\x70\x00\x00\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x14\xe5\x0b\x00\x08\xe5\x0b\x10\x0c\xe5\x0b\x20\x10\xe5\x9f\x30\x0c\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x3f\x70\x00\x00\xe2\x4d\xd0\x10\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x8b\xc0\x04\xe8\x8c\x00\x0f\xe5\x9f\x30\x10\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe2\x8d\xd0\x10\xe1\x2f\xff\x1e\x3f\x70\x00\x00\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x14\xe1\x4b\x00\xfc\xe1\x4b\x21\xf4\xe3\xa0\x30\x00\xe5\x9f\x20\x10\xe1\xa0\x10\x03\xe1\xa0\x00\x02\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x3f\xd0\x00\x00\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x0c\xe1\x4b\x00\xb6\xe1\x4b\x10\xb8\xe1\x4b\x20\xba\xe1\x4b\x30\xbc\xe3\xa0\x3b\x0d\xe3\x83\x30\x00\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe5\x9f\x30\x0c\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x00\x00\xab\xcd\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x8f\x30\x14\xe1\xc3\x20\xd0\xe1\xa0\x10\x03\xe1\xa0\x00\x02\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xff\xee\xdd\xcc\xbb\xaa\x99\x88\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x0c\xe5\x9f\x20\x74\xe2\x4b\x30\x08\xe5\x92\x20\x00\xe1\xa0\x24\x22\xe1\xa0\x10\x02\xe5\xc3\x10\x02\xe1\xa0\x24\x22\xe1\xa0\x10\x02\xe5\xc3\x10\x01\xe1\xa0\x24\x22\xe5\xc3\x20\x00\xe3\xa0\x30\x00\xe5\x5b\x20\x08\xe6\xef\x20\x72\xe3\xc3\x34\xff\xe1\xa0\x2c\x02\xe1\x82\x30\x03\xe5\x5b\x20\x07\xe6\xef\x20\x72\xe3\xc3\x38\xff\xe1\xa0\x28\x02\xe1\x82\x30\x03\xe5\x5b\x20\x06\xe6\xef\x20\x72\xe3\xc3\x3c\xff\xe1\xa0\x24\x02\xe1\x82\x30\x03\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x00\x00\x07\xd8\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe3\xa0\x3c\x43\xe3\x83\x30\xc0\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe3\xa0\x35\xfd\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe3\xa0\x30\x00\xe5\x9f\x20\x10\xe1\xa0\x10\x03\xe1\xa0\x00\x02\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x3f\xe8\x00\x00\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe3\x20\xf0\x00\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x0c\xe1\xa0\x30\x00\xe1\x4b\x30\xb6\xe3\xa0\x30\x01\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x0c\xe5\x0b\x00\x08\xe5\x9f\x30\x0c\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xba\xde\xba\xbe\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x0c\xe5\x0b\x00\x08\xe5\x9f\x30\x0c\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xba\xbe\xba\xde\xe9\x2d\x48\x00\xe2\x8d\xb0\x04\xe2\x4d\xd0\x88\xeb\xff\xfe\xf1\xe5\x9f\x33\x00\xe5\x9f\x23\x00\xe5\x9f\x13\x00\xe5\x9f\x03\x00\xeb\xff\xfe\xf8\xe2\x8f\x3f\xb3\xe1\xc3\x20\xd0\xe5\x9f\x02\xf0\xeb\xff\xff\x01\xe5\x9f\x32\xec\xe5\x8d\x30\x18\xe3\xa0\x30\x4a\xe5\x8d\x30\x14\xe3\xa0\x30\x4b\xe5\x8d\x30\x10\xe2\x8f\x3f\xab\xe1\xc3\x20\xd0\xe1\xcd\x20\xf8\xe3\xa0\x30\x41\xe5\x8d\x30\x00\xe2\x8f\x3e\x2a\xe1\xc3\x20\xd0\xe2\x8f\x1e\x2a\xe1\xc1\x00\xd0\xeb\xff\xff\x00\xe5\x9f\x22\xb0\xe2\x4b\x30\x10\xe8\x92\x00\x07\xe8\x83\x00\x07\xe5\x1b\x30\x08\xe5\x8d\x30\x00\xe2\x4b\x30\x10\xe8\x93\x00\x0c\xe3\xa0\x10\x03\xe3\xa0\x00\x01\xeb\xff\xff\x03\xe5\x9f\x32\x88\xe2\x4b\xc0\x2c\xe1\xa0\xe0\x03\xe8\xbe\x00\x0f\xe8\xac\x00\x0f\xe8\x9e\x00\x03\xe8\x8c\x00\x03\xe1\xa0\x20\x0d\xe2\x4b\x30\x1c\xe8\x93\x00\x03\xe8\x82\x00\x03\xe2\x4b\x30\x2c\xe8\x93\x00\x0f\xeb\xff\xff\x03\xe3\xa0\x30\x61\xe1\xa0\x00\x03\xe1\xa0\x0c\x00\xeb\xff\xff\x0a\xe1\xa0\x0c\x40\xe5\x9f\x32\x40\xe5\x8d\x30\x08\xe3\xa0\x30\x00\xe5\x9f\x22\x38\xe1\xcd\x20\xf0\xe3\xa0\x20\x08\xe3\xa0\x14\x3f\xe3\xa0\x00\x04\xeb\xff\xff\x0a\xe5\x9f\x32\x24\xe5\x8d\x30\x0c\xe3\xa0\x3c\x3b\xe3\x83\x30\x00\xe1\xcd\x30\xb8\xe3\xa0\x30\x00\xe5\x9f\x22\x08\xe1\xcd\x20\xf0\xe3\xa0\x20\x08\xe3\xa0\x14\x3f\xe3\xa0\x00\x04\xeb\xff\xff\x0a\xe5\x9f\x31\xf8\xe2\x4b\xc0\x4c\xe1\xa0\xe0\x03\xe8\xbe\x00\x0f\xe8\xac\x00\x0f\xe8\x9e\x00\x0f\xe8\x8c\x00\x0f\xe1\xa0\xc0\x0d\xe2\x4b\x30\x3c\xe8\x93\x00\x0f\xe8\x8c\x00\x0f\xe2\x4b\x30\x4c\xe8\x93\x00\x0f\xeb\xff\xff\x08\xe3\xa0\x30\x00\xe5\x9f\x21\xc0\xe1\xcd\x23\xf8\xe3\xa0\x30\x00\xe5\x9f\x21\xb8\xe1\xcd\x23\xf0\xe3\xa0\x30\x00\xe5\x9f\x21\xb0\xe1\xcd\x22\xf8\xe3\xa0\x30\x00\xe5\x9f\x21\xa8\xe1\xcd\x22\xf0\xe3\xa0\x30\x00\xe5\x9f\x21\xa0\xe1\xcd\x21\xf8\xe3\xa0\x30\x00\xe5\x9f\x21\x98\xe1\xcd\x21\xf0\xe3\xa0\x30\x00\xe5\x9f\x21\x90\xe1\xcd\x20\xf8\xe3\xa0\x30\x00\xe5\x9f\x21\x88\xe1\xcd\x20\xf0\xe3\xa0\x30\x00\xe5\x9f\x21\x80\xe3\xa0\x10\x00\xe5\x9f\x01\x7c\xeb\xff\xfe\xf7\xe3\xa0\x3c\x63\xe3\x83\x30\xf0\xe1\xcd\x33\xb4\xe3\xa0\x3c\x63\xe3\x83\x30\xe0\xe1\xcd\x33\xb0\xe3\xa0\x3c\x63\xe3\x83\x30\xc0\xe1\xcd\x32\xbc\xe3\xa0\x3c\x63\xe3\x83\x30\x80\xe1\xcd\x32\xb8\xe3\xa0\x3c\x63\xe3\x83\x30\x00\xe1\xcd\x32\xb4\xe3\xa0\x3c\x62\xe3\x83\x30\x00\xe1\xcd\x32\xb0\xe3\xa0\x3a\x06\xe3\x83\x30\x00\xe1\xcd\x31\xbc\xe3\xa0\x3c\x73\xe3\x83\x30\xe0\xe1\xcd\x31\xb8\xe3\xa0\x3c\x73\xe3\x83\x30\xc0\xe1\xcd\x31\xb4\xe3\xa0\x3c\x73\xe3\x83\x30\x80\xe1\xcd\x31\xb0\xe3\xa0\x3c\x73\xe3\x83\x30\x00\xe1\xcd\x30\xbc\xe3\xa0\x3c\x72\xe3\x83\x30\x00\xe1\xcd\x30\xb8\xe3\xa0\x3a\x07\xe3\x83\x30\x00\xe1\xcd\x30\xb4\xe3\xa0\x3c\x43\xe3\x83\x30\xc0\xe1\xcd\x30\xb0\xe3\xa0\x3c\x43\xe3\x83\x30\x80\xe3\xa0\x2c\x43\xe3\x82\x20\x00\xe3\xa0\x1c\x42\xe3\x81\x10\x00\xe3\xa0\x09\x01\xe3\x80\x00\x00\xeb\xff\xfe\xd1\xeb\xff\xfe\xdd\xeb\xff\xfe\xe4\xeb\xff\xfe\xee\xeb\xff\xff\x10\xeb\xff\xff\x17\xeb\xff\xff\x1d\xeb\xff\xff\x26\xe5\x9f\x00\x90\xeb\xff\xff\x2a\xe5\x9f\x00\x8c\xeb\xff\xff\x32\xe5\x9f\x00\x88\xeb\xff\xff\x3a\xe3\x20\xf0\x00\xe2\x4b\xd0\x04\xe8\xbd\x88\x00\x05\x06\x07\x08\x09\x0a\x0b\x0c\x18\x17\x16\x15\x14\x13\x12\x11\x10\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01\x0d\x0e\x0f\x10\x09\x0a\x0b\x0c\x05\x06\x07\x08\x01\x02\x03\x04\x1c\x1b\x1a\x19\x00\x00\x07\xdc\x00\x00\x07\xe8\x3f\x60\x00\x00\x3f\xe8\x00\x00\x3f\x7c\x00\x00\x00\x00\x08\x00\x3f\xdf\xf8\x00\x3f\xdf\xf0\x00\x3f\xdf\xe0\x00\x3f\xdf\xc0\x00\x3f\xdf\x80\x00\x3f\xdf\x00\x00\x3f\xde\x00\x00\x3f\xdc\x00\x00\x3f\xd8\x00\x00\x3f\xd0\x00\x00\x00\x00\x12\x34\xc0\xde\xc0\xfe\xc0\xfe\xc0\xde\x49\x4a\x4b\x00\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x61\x00\x0f\x10\x11\x12\x13\x14\x62\x00\x00\x00\x00\x00\x00\x00\x15\x16\x17\x18\x19\x1a\x1b\x1c\x3f\xe0\x00\x00\x00\x00\x00\x00\x3f\xe8\x00\x00\x00\x00\x00\x00\x3f\xec\x00\x00\x00\x00\x00\x00\x3f\xef\x80\x00\x00\x00\x00\x00'}],
   'extra': {}}

BlobCcAapcs32ArmebV6SoftFloatFp16Ieee = MetaBinBlob.from_dict(meta_blob_cc_aapcs32_armeb_v6_soft_float_fp16_ieee)


from ...cc.source_code_analyzer import MetaSourceCode

meta_source_code_cc_aapcs32_armeb_v6_soft_float_fp16_ieee = \
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
             'size': 40,
             'name': 'foo_06',
             'return_value_type': 'struct struct_06',
             'return_value': {'a': 65},
             'arguments': {0: ('aggregate', 'struct struct_06')},
             'call_arg_values': {0: {'a': 97}}},
            {'address': 412,
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
            {'address': 460,
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
            {'address': 508,
             'size': 48,
             'name': 'foo_09',
             'return_value_type': 'float',
             'return_value': 0.9375,
             'arguments': {0: ('a', 'struct struct_09_4')},
             'call_arg_values': {0: {'a': {'a': 0.5, 'b': 0.75},
                                     'wrap': {'b': {'c': 0.875,
                                                    'd': 0.984375}}}}},
            {'address': 556,
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
            {'address': 608,
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
            {'address': 660,
             'size': 32,
             'name': 'foo_12',
             'return_value_type': 'unsigned short',
             'return_value': 43981,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 692,
             'size': 44,
             'name': 'foo_13',
             'return_value_type': 'unsigned long long',
             'return_value': 18441921395520346504,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 736,
             'size': 140,
             'name': 'foo_14',
             'return_value_type': 'struct struct_14',
             'return_value': {'a': 73, 'b': 74, 'c': 75},
             'arguments': {},
             'call_arg_values': {}},
            {'address': 876,
             'size': 32,
             'name': 'foo_15',
             'return_value_type': '__fp16',
             'return_value': 3.875,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 908,
             'size': 28,
             'name': 'foo_16',
             'return_value_type': 'float',
             'return_value': 0.75,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 936,
             'size': 40,
             'name': 'foo_17',
             'return_value_type': 'double',
             'return_value': 0.75,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 976,
             'size': 24,
             'name': 'foo_19',
             'return_value_type': None,
             'return_value': None,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 1000,
             'size': 40,
             'name': 'foo_20',
             'return_value_type': 'unsigned int',
             'return_value': 1,
             'arguments': {0: ('a', 'unsigned short')},
             'call_arg_values': {0: 4660}},
            {'address': 1040,
             'size': 40,
             'name': 'foo_21',
             'return_value_type': 'unsigned char*',
             'return_value': 3135158974,
             'arguments': {0: ('a', 'unsigned char*')},
             'call_arg_values': {0: 3235823870}},
            {'address': 1080,
             'size': 40,
             'name': 'foo_22',
             'return_value_type': 'unsigned char**',
             'return_value': 3133061854,
             'arguments': {0: ('a', 'unsigned char**')},
             'call_arg_values': {0: 3237920990}},
            {'address': 1120,
             'size': 888,
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

MetaSourceCodeCcAapcs32ArmebV6SoftFloatFp16Ieee = MetaSourceCode.from_dict(meta_source_code_cc_aapcs32_armeb_v6_soft_float_fp16_ieee)

BlobCcAapcs32ArmebV6SoftFloatFp16Ieee.extra.update({"cc_test_data": MetaSourceCodeCcAapcs32ArmebV6SoftFloatFp16Ieee})
