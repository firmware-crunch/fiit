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

meta_blob_cc_aapcs32_armel_v6_hard_float_fp16_ieee = \
  {'arch_unicorn': 'arm:el:32:1176',
   'arch_info': {'cpu_float_flag': 'FLOAT_HARD',
                 'tag_cpu_arch': 'v6KZ',
                 'tag_cpu_name': 'ARM1176JZF-S',
                 'tag_fp_arch': 'VFPv2',
                 'tag_abi_fp_16bit_format': 'IEEE754'},
   'compiler': 'GCC: (Arch Repository) 13.1.0\x00',
   'producer': 'GNU C17 13.1.0 -mthumb-interwork -mcpu=arm1176jzf-s '
               '-mlittle-endian -mfpu=vfp -mfloat-abi=hard -mfp16-format=ieee '
               '-marm -march=armv6kz+fp -g -O0',
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
                  '  2c:  eb00014f   bl  570 <__entry__>\n'
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
                  ' 1a0:  e24dd01c   sub  sp, sp, #28\n'
                  ' 1a4:  e50b0008   str  r0, [fp, #-8]\n'
                  ' 1a8:  ed0b0a03   vstr  s0, [fp, #-12]\n'
                  ' 1ac:  e50b1010   str  r1, [fp, #-16]\n'
                  ' 1b0:  ed0b1b07   vstr  d1, [fp, #-28]  @ 0xffffffe4\n'
                  ' 1b4:  ed4b0a05   vstr  s1, [fp, #-20]  @ 0xffffffec\n'
                  '  return 0.9375;\n'
                  ' 1b8:  e59f3010   ldr  r3, [pc, #16]  @ 1d0 <foo_07+0x38>\n'
                  ' 1bc:  ee073a90   vmov  s15, r3\n'
                  '}\n'
                  ' 1c0:  eeb00a67   vmov.f32  s0, s15\n'
                  ' 1c4:  e28bd000   add  sp, fp, #0\n'
                  ' 1c8:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 1cc:  e12fff1e   bx  lr\n'
                  ' 1d0:  3f700000   .word  0x3f700000\n'
                  '\n'
                  '000001d4 <foo_08>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'float foo_08(int a, float b, int c, double d, __fp16 e, '
                  'float f)\n'
                  '{\n'
                  ' 1d4:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 1d8:  e28db000   add  fp, sp, #0\n'
                  ' 1dc:  e24dd024   sub  sp, sp, #36  @ 0x24\n'
                  ' 1e0:  e50b0008   str  r0, [fp, #-8]\n'
                  ' 1e4:  ed0b0a03   vstr  s0, [fp, #-12]\n'
                  ' 1e8:  e50b1010   str  r1, [fp, #-16]\n'
                  ' 1ec:  ed0b1b07   vstr  d1, [fp, #-28]  @ 0xffffffe4\n'
                  ' 1f0:  ee103a90   vmov  r3, s1\n'
                  ' 1f4:  e14b31b2   strh  r3, [fp, #-18]  @ 0xffffffee\n'
                  ' 1f8:  ed0b2a08   vstr  s4, [fp, #-32]  @ 0xffffffe0\n'
                  '  return 0.9375;\n'
                  ' 1fc:  e59f3010   ldr  r3, [pc, #16]  @ 214 <foo_08+0x40>\n'
                  ' 200:  ee073a90   vmov  s15, r3\n'
                  '}\n'
                  ' 204:  eeb00a67   vmov.f32  s0, s15\n'
                  ' 208:  e28bd000   add  sp, fp, #0\n'
                  ' 20c:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 210:  e12fff1e   bx  lr\n'
                  ' 214:  3f700000   .word  0x3f700000\n'
                  '\n'
                  '00000218 <foo_09>:\n'
                  'struct struct_09_2 { double c; double d; };\n'
                  'struct struct_09_3 { struct struct_09_2 b; };\n'
                  'struct struct_09_4 { struct struct_09_1 a; struct '
                  'struct_09_3 wrap; };\n'
                  '\n'
                  'float foo_09(struct struct_09_4 a)\n'
                  '{\n'
                  ' 218:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 21c:  e28db000   add  fp, sp, #0\n'
                  ' 220:  e24dd024   sub  sp, sp, #36  @ 0x24\n'
                  ' 224:  eeb04b40   vmov.f64  d4, d0\n'
                  ' 228:  eeb05b41   vmov.f64  d5, d1\n'
                  ' 22c:  eeb06b42   vmov.f64  d6, d2\n'
                  ' 230:  eeb07b43   vmov.f64  d7, d3\n'
                  ' 234:  ed0b4b09   vstr  d4, [fp, #-36]  @ 0xffffffdc\n'
                  ' 238:  ed0b5b07   vstr  d5, [fp, #-28]  @ 0xffffffe4\n'
                  ' 23c:  ed0b6b05   vstr  d6, [fp, #-20]  @ 0xffffffec\n'
                  ' 240:  ed0b7b03   vstr  d7, [fp, #-12]\n'
                  '  return 0.9375;\n'
                  ' 244:  e59f3010   ldr  r3, [pc, #16]  @ 25c <foo_09+0x44>\n'
                  ' 248:  ee073a90   vmov  s15, r3\n'
                  '}\n'
                  ' 24c:  eeb00a67   vmov.f32  s0, s15\n'
                  ' 250:  e28bd000   add  sp, fp, #0\n'
                  ' 254:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 258:  e12fff1e   bx  lr\n'
                  ' 25c:  3f700000   .word  0x3f700000\n'
                  '\n'
                  '00000260 <foo_10>:\n'
                  '// force aapcs32 c2 rule vfp registers with double.\n'
                  '//##############################################################################\n'
                  'double foo_10(double x1, double x2, double x3, double x4,\n'
                  '              double x5, double x6, double x7, double x8,\n'
                  '              double x9, double x10)\n'
                  '{\n'
                  ' 260:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 264:  e28db000   add  fp, sp, #0\n'
                  ' 268:  e24dd044   sub  sp, sp, #68  @ 0x44\n'
                  ' 26c:  ed0b0b03   vstr  d0, [fp, #-12]\n'
                  ' 270:  ed0b1b05   vstr  d1, [fp, #-20]  @ 0xffffffec\n'
                  ' 274:  ed0b2b07   vstr  d2, [fp, #-28]  @ 0xffffffe4\n'
                  ' 278:  ed0b3b09   vstr  d3, [fp, #-36]  @ 0xffffffdc\n'
                  ' 27c:  ed0b4b0b   vstr  d4, [fp, #-44]  @ 0xffffffd4\n'
                  ' 280:  ed0b5b0d   vstr  d5, [fp, #-52]  @ 0xffffffcc\n'
                  ' 284:  ed0b6b0f   vstr  d6, [fp, #-60]  @ 0xffffffc4\n'
                  ' 288:  ed0b7b11   vstr  d7, [fp, #-68]  @ 0xffffffbc\n'
                  '  return 0.25;\n'
                  ' 28c:  e3a02000   mov  r2, #0\n'
                  ' 290:  e59f3010   ldr  r3, [pc, #16]  @ 2a8 <foo_10+0x48>\n'
                  ' 294:  ec432b17   vmov  d7, r2, r3\n'
                  '}\n'
                  ' 298:  eeb00b47   vmov.f64  d0, d7\n'
                  ' 29c:  e28bd000   add  sp, fp, #0\n'
                  ' 2a0:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 2a4:  e12fff1e   bx  lr\n'
                  ' 2a8:  3fd00000   .word  0x3fd00000\n'
                  '\n'
                  '000002ac <foo_11>:\n'
                  '//#############################################################################\n'
                  '__fp16 foo_11(__fp16 x1, __fp16 x2, __fp16 x3, __fp16 x4, '
                  '__fp16 x5, __fp16 x6,\n'
                  '              __fp16 x7, __fp16 x8, __fp16 x9, __fp16 x10, '
                  '__fp16 x11,\n'
                  '              __fp16 x12, __fp16 x13, __fp16 x14, __fp16 '
                  'x15, __fp16 x16,\n'
                  '              __fp16 x17, __fp16 x18)\n'
                  '{\n'
                  ' 2ac:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 2b0:  e28db000   add  fp, sp, #0\n'
                  ' 2b4:  e24dd024   sub  sp, sp, #36  @ 0x24\n'
                  ' 2b8:  ee103a10   vmov  r3, s0\n'
                  ' 2bc:  e14b30b6   strh  r3, [fp, #-6]\n'
                  ' 2c0:  ee103a90   vmov  r3, s1\n'
                  ' 2c4:  e14b30b8   strh  r3, [fp, #-8]\n'
                  ' 2c8:  ee113a10   vmov  r3, s2\n'
                  ' 2cc:  e14b30ba   strh  r3, [fp, #-10]\n'
                  ' 2d0:  ee113a90   vmov  r3, s3\n'
                  ' 2d4:  e14b30bc   strh  r3, [fp, #-12]\n'
                  ' 2d8:  ee123a10   vmov  r3, s4\n'
                  ' 2dc:  e14b30be   strh  r3, [fp, #-14]\n'
                  ' 2e0:  ee123a90   vmov  r3, s5\n'
                  ' 2e4:  e14b31b0   strh  r3, [fp, #-16]\n'
                  ' 2e8:  ee133a10   vmov  r3, s6\n'
                  ' 2ec:  e14b31b2   strh  r3, [fp, #-18]  @ 0xffffffee\n'
                  ' 2f0:  ee133a90   vmov  r3, s7\n'
                  ' 2f4:  e14b31b4   strh  r3, [fp, #-20]  @ 0xffffffec\n'
                  ' 2f8:  ee143a10   vmov  r3, s8\n'
                  ' 2fc:  e14b31b6   strh  r3, [fp, #-22]  @ 0xffffffea\n'
                  ' 300:  ee143a90   vmov  r3, s9\n'
                  ' 304:  e14b31b8   strh  r3, [fp, #-24]  @ 0xffffffe8\n'
                  ' 308:  ee153a10   vmov  r3, s10\n'
                  ' 30c:  e14b31ba   strh  r3, [fp, #-26]  @ 0xffffffe6\n'
                  ' 310:  ee153a90   vmov  r3, s11\n'
                  ' 314:  e14b31bc   strh  r3, [fp, #-28]  @ 0xffffffe4\n'
                  ' 318:  ee163a10   vmov  r3, s12\n'
                  ' 31c:  e14b31be   strh  r3, [fp, #-30]  @ 0xffffffe2\n'
                  ' 320:  ee163a90   vmov  r3, s13\n'
                  ' 324:  e14b32b0   strh  r3, [fp, #-32]  @ 0xffffffe0\n'
                  ' 328:  ee173a10   vmov  r3, s14\n'
                  ' 32c:  e14b32b2   strh  r3, [fp, #-34]  @ 0xffffffde\n'
                  ' 330:  ee173a90   vmov  r3, s15\n'
                  ' 334:  e14b32b4   strh  r3, [fp, #-36]  @ 0xffffffdc\n'
                  '  return 0.25;\n'
                  ' 338:  e3a03b0d   mov  r3, #13312  @ 0x3400\n'
                  ' 33c:  e3833000   orr  r3, r3, #0\n'
                  ' 340:  ee073a90   vmov  s15, r3\n'
                  '}\n'
                  ' 344:  eeb00a67   vmov.f32  s0, s15\n'
                  ' 348:  e28bd000   add  sp, fp, #0\n'
                  ' 34c:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 350:  e12fff1e   bx  lr\n'
                  '\n'
                  '00000354 <foo_12>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '// Return fundamental type smaller than a word.\n'
                  '//##############################################################################\n'
                  'unsigned short foo_12(void)\n'
                  '{\n'
                  ' 354:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 358:  e28db000   add  fp, sp, #0\n'
                  '  return 0xabcd;\n'
                  ' 35c:  e59f300c   ldr  r3, [pc, #12]  @ 370 <foo_12+0x1c>\n'
                  '}\n'
                  ' 360:  e1a00003   mov  r0, r3\n'
                  ' 364:  e28bd000   add  sp, fp, #0\n'
                  ' 368:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 36c:  e12fff1e   bx  lr\n'
                  ' 370:  0000abcd   .word  0x0000abcd\n'
                  '\n'
                  '00000374 <foo_13>:\n'
                  '\n'
                  '//#############################################################################\n'
                  '// Return fundamental type with double word size.\n'
                  '//#############################################################################\n'
                  'unsigned long long foo_13(void)\n'
                  '{\n'
                  ' 374:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 378:  e28db000   add  fp, sp, #0\n'
                  '  return 0xffeeddccbbaa9988;;\n'
                  ' 37c:  e28f3014   add  r3, pc, #20\n'
                  ' 380:  e1c320d0   ldrd  r2, [r3]\n'
                  '}\n'
                  ' 384:  e1a00002   mov  r0, r2\n'
                  ' 388:  e1a01003   mov  r1, r3\n'
                  ' 38c:  e28bd000   add  sp, fp, #0\n'
                  ' 390:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 394:  e12fff1e   bx  lr\n'
                  ' 398:  bbaa9988   .word  0xbbaa9988\n'
                  ' 39c:  ffeeddcc   .word  0xffeeddcc\n'
                  '\n'
                  '000003a0 <foo_14>:\n'
                  '// Return aggregate lower than a word.\n'
                  '//#############################################################################\n'
                  'struct struct_14 { unsigned char a; unsigned char b; '
                  'unsigned char c; };\n'
                  '\n'
                  'struct struct_14 foo_14(void)\n'
                  '{\n'
                  ' 3a0:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 3a4:  e28db000   add  fp, sp, #0\n'
                  ' 3a8:  e24dd00c   sub  sp, sp, #12\n'
                  "  return (struct struct_14){.a='I', .b='J', .c='K'};\n"
                  ' 3ac:  e59f2060   ldr  r2, [pc, #96]  @ 414 <foo_14+0x74>\n'
                  ' 3b0:  e24b3008   sub  r3, fp, #8\n'
                  ' 3b4:  e5922000   ldr  r2, [r2]\n'
                  ' 3b8:  e1c320b0   strh  r2, [r3]\n'
                  ' 3bc:  e2833002   add  r3, r3, #2\n'
                  ' 3c0:  e1a02822   lsr  r2, r2, #16\n'
                  ' 3c4:  e5c32000   strb  r2, [r3]\n'
                  ' 3c8:  e3a03000   mov  r3, #0\n'
                  ' 3cc:  e55b2008   ldrb  r2, [fp, #-8]\n'
                  ' 3d0:  e6ef2072   uxtb  r2, r2\n'
                  ' 3d4:  e3c330ff   bic  r3, r3, #255  @ 0xff\n'
                  ' 3d8:  e1823003   orr  r3, r2, r3\n'
                  ' 3dc:  e55b2007   ldrb  r2, [fp, #-7]\n'
                  ' 3e0:  e6ef2072   uxtb  r2, r2\n'
                  ' 3e4:  e3c33cff   bic  r3, r3, #65280  @ 0xff00\n'
                  ' 3e8:  e1a02402   lsl  r2, r2, #8\n'
                  ' 3ec:  e1823003   orr  r3, r2, r3\n'
                  ' 3f0:  e55b2006   ldrb  r2, [fp, #-6]\n'
                  ' 3f4:  e6ef2072   uxtb  r2, r2\n'
                  ' 3f8:  e3c338ff   bic  r3, r3, #16711680  @ 0xff0000\n'
                  ' 3fc:  e1a02802   lsl  r2, r2, #16\n'
                  ' 400:  e1823003   orr  r3, r2, r3\n'
                  '}\n'
                  ' 404:  e1a00003   mov  r0, r3\n'
                  ' 408:  e28bd000   add  sp, fp, #0\n'
                  ' 40c:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 410:  e12fff1e   bx  lr\n'
                  ' 414:  000008d8   .word  0x000008d8\n'
                  '\n'
                  '00000418 <foo_15>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  '__fp16 foo_15(void)\n'
                  '{\n'
                  ' 418:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 41c:  e28db000   add  fp, sp, #0\n'
                  '  return 3.875;\n'
                  ' 420:  e3a03c43   mov  r3, #17152  @ 0x4300\n'
                  ' 424:  e38330c0   orr  r3, r3, #192  @ 0xc0\n'
                  ' 428:  ee073a90   vmov  s15, r3\n'
                  '}\n'
                  ' 42c:  eeb00a67   vmov.f32  s0, s15\n'
                  ' 430:  e28bd000   add  sp, fp, #0\n'
                  ' 434:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 438:  e12fff1e   bx  lr\n'
                  '\n'
                  '0000043c <foo_16>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'float foo_16(void)\n'
                  '{\n'
                  ' 43c:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 440:  e28db000   add  fp, sp, #0\n'
                  '  return 0.75;\n'
                  ' 444:  e3a035fd   mov  r3, #1061158912  @ 0x3f400000\n'
                  ' 448:  ee073a90   vmov  s15, r3\n'
                  '}\n'
                  ' 44c:  eeb00a67   vmov.f32  s0, s15\n'
                  ' 450:  e28bd000   add  sp, fp, #0\n'
                  ' 454:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 458:  e12fff1e   bx  lr\n'
                  '\n'
                  '0000045c <foo_17>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'double foo_17(void)\n'
                  '{\n'
                  ' 45c:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 460:  e28db000   add  fp, sp, #0\n'
                  '  return 0.75;\n'
                  ' 464:  e3a02000   mov  r2, #0\n'
                  ' 468:  e59f3010   ldr  r3, [pc, #16]  @ 480 <foo_17+0x24>\n'
                  ' 46c:  ec432b17   vmov  d7, r2, r3\n'
                  '}\n'
                  ' 470:  eeb00b47   vmov.f64  d0, d7\n'
                  ' 474:  e28bd000   add  sp, fp, #0\n'
                  ' 478:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 47c:  e12fff1e   bx  lr\n'
                  ' 480:  3fe80000   .word  0x3fe80000\n'
                  '\n'
                  '00000484 <foo_18>:\n'
                  'struct struct_18_wrap_l1 { struct struct_18_b b; };\n'
                  '\n'
                  'struct struct_18_wrap_l2 { struct struct_18_a a; struct '
                  'struct_18_wrap_l1 wrap; };\n'
                  '\n'
                  'struct struct_18_wrap_l2 foo_18(void)\n'
                  '{\n'
                  ' 484:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 488:  e28db000   add  fp, sp, #0\n'
                  ' 48c:  e24dd034   sub  sp, sp, #52  @ 0x34\n'
                  '    return (struct struct_18_wrap_l2){\n'
                  ' 490:  e59f3044   ldr  r3, [pc, #68]  @ 4dc <foo_18+0x58>\n'
                  ' 494:  e24bc014   sub  ip, fp, #20\n'
                  ' 498:  e893000f   ldm  r3, {r0, r1, r2, r3}\n'
                  ' 49c:  e88c000f   stm  ip, {r0, r1, r2, r3}\n'
                  ' 4a0:  e51b0014   ldr  r0, [fp, #-20]  @ 0xffffffec\n'
                  ' 4a4:  e51b1010   ldr  r1, [fp, #-16]\n'
                  ' 4a8:  e51b200c   ldr  r2, [fp, #-12]\n'
                  ' 4ac:  e51b3008   ldr  r3, [fp, #-8]\n'
                  ' 4b0:  ee060a10   vmov  s12, r0\n'
                  ' 4b4:  ee061a90   vmov  s13, r1\n'
                  ' 4b8:  ee072a10   vmov  s14, r2\n'
                  ' 4bc:  ee073a90   vmov  s15, r3\n'
                  '        .a = {.a=0.5, .b=0.75}, .wrap = {.b = {.c=0.875, '
                  '.d=0.984375}}};\n'
                  '}\n'
                  ' 4c0:  eeb00a46   vmov.f32  s0, s12\n'
                  ' 4c4:  eef00a66   vmov.f32  s1, s13\n'
                  ' 4c8:  eeb01a47   vmov.f32  s2, s14\n'
                  ' 4cc:  eef01a67   vmov.f32  s3, s15\n'
                  ' 4d0:  e28bd000   add  sp, fp, #0\n'
                  ' 4d4:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 4d8:  e12fff1e   bx  lr\n'
                  ' 4dc:  000008dc   .word  0x000008dc\n'
                  '\n'
                  '000004e0 <foo_19>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'void foo_19(void)\n'
                  '{\n'
                  ' 4e0:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 4e4:  e28db000   add  fp, sp, #0\n'
                  '}\n'
                  ' 4e8:  e320f000   nop  {0}\n'
                  ' 4ec:  e28bd000   add  sp, fp, #0\n'
                  ' 4f0:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 4f4:  e12fff1e   bx  lr\n'
                  '\n'
                  '000004f8 <foo_20>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '// Argument with size lower than a word.\n'
                  '//##############################################################################\n'
                  'unsigned int foo_20(unsigned short a)\n'
                  '{\n'
                  ' 4f8:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 4fc:  e28db000   add  fp, sp, #0\n'
                  ' 500:  e24dd00c   sub  sp, sp, #12\n'
                  ' 504:  e1a03000   mov  r3, r0\n'
                  ' 508:  e14b30b6   strh  r3, [fp, #-6]\n'
                  '    return 1;\n'
                  ' 50c:  e3a03001   mov  r3, #1\n'
                  '}\n'
                  ' 510:  e1a00003   mov  r0, r3\n'
                  ' 514:  e28bd000   add  sp, fp, #0\n'
                  ' 518:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 51c:  e12fff1e   bx  lr\n'
                  '\n'
                  '00000520 <foo_21>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'unsigned char * foo_21(unsigned char * a)\n'
                  '{\n'
                  ' 520:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 524:  e28db000   add  fp, sp, #0\n'
                  ' 528:  e24dd00c   sub  sp, sp, #12\n'
                  ' 52c:  e50b0008   str  r0, [fp, #-8]\n'
                  '    return (unsigned char *) 0xBADEBABE;\n'
                  ' 530:  e59f300c   ldr  r3, [pc, #12]  @ 544 <foo_21+0x24>\n'
                  '}\n'
                  ' 534:  e1a00003   mov  r0, r3\n'
                  ' 538:  e28bd000   add  sp, fp, #0\n'
                  ' 53c:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 540:  e12fff1e   bx  lr\n'
                  ' 544:  badebabe   .word  0xbadebabe\n'
                  '\n'
                  '00000548 <foo_22>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'unsigned char ** foo_22(unsigned char ** a)\n'
                  '{\n'
                  ' 548:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 54c:  e28db000   add  fp, sp, #0\n'
                  ' 550:  e24dd00c   sub  sp, sp, #12\n'
                  ' 554:  e50b0008   str  r0, [fp, #-8]\n'
                  '    return (unsigned char **) 0xBABEBADE;\n'
                  ' 558:  e59f300c   ldr  r3, [pc, #12]  @ 56c <foo_22+0x24>\n'
                  '}\n'
                  ' 55c:  e1a00003   mov  r0, r3\n'
                  ' 560:  e28bd000   add  sp, fp, #0\n'
                  ' 564:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 568:  e12fff1e   bx  lr\n'
                  ' 56c:  babebade   .word  0xbabebade\n'
                  '\n'
                  '00000570 <__entry__>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '// Entry Point\n'
                  '//##############################################################################\n'
                  'void __entry__(void)\n'
                  '{\n'
                  ' 570:  e92d4800   push  {fp, lr}\n'
                  ' 574:  e28db004   add  fp, sp, #4\n'
                  ' 578:  e24dd068   sub  sp, sp, #104  @ 0x68\n'
                  '  cc_call_test_wrapper();\n'
                  ' 57c:  ebfffead   bl  38 <cc_call_test_wrapper>\n'
                  '\n'
                  '  foo_01(0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10);\n'
                  ' 580:  e59f331c   ldr  r3, [pc, #796]  @ 8a4 '
                  '<__entry__+0x334>\n'
                  ' 584:  e59f231c   ldr  r2, [pc, #796]  @ 8a8 '
                  '<__entry__+0x338>\n'
                  ' 588:  e59f131c   ldr  r1, [pc, #796]  @ 8ac '
                  '<__entry__+0x33c>\n'
                  ' 58c:  e59f031c   ldr  r0, [pc, #796]  @ 8b0 '
                  '<__entry__+0x340>\n'
                  ' 590:  ebfffeb4   bl  68 <foo_01>\n'
                  '\n'
                  '  foo_02(0x01020304, 0x05060708090A0B0C);\n'
                  ' 594:  e28f3fa5   add  r3, pc, #660  @ 0x294\n'
                  ' 598:  e1c320d0   ldrd  r2, [r3]\n'
                  ' 59c:  e59f030c   ldr  r0, [pc, #780]  @ 8b0 '
                  '<__entry__+0x340>\n'
                  ' 5a0:  ebfffebd   bl  9c <foo_02>\n'
                  '\n'
                  '  foo_03(0x0807060504030201, 0x100F0E0D0C0B0A09,\n'
                  ' 5a4:  e59f3308   ldr  r3, [pc, #776]  @ 8b4 '
                  '<__entry__+0x344>\n'
                  ' 5a8:  e58d3018   str  r3, [sp, #24]\n'
                  ' 5ac:  e3a0304a   mov  r3, #74  @ 0x4a\n'
                  ' 5b0:  e58d3014   str  r3, [sp, #20]\n'
                  ' 5b4:  e3a0304b   mov  r3, #75  @ 0x4b\n'
                  ' 5b8:  e58d3010   str  r3, [sp, #16]\n'
                  ' 5bc:  e28f3f9d   add  r3, pc, #628  @ 0x274\n'
                  ' 5c0:  e1c320d0   ldrd  r2, [r3]\n'
                  ' 5c4:  e1cd20f8   strd  r2, [sp, #8]\n'
                  ' 5c8:  e3a03041   mov  r3, #65  @ 0x41\n'
                  ' 5cc:  e58d3000   str  r3, [sp]\n'
                  ' 5d0:  e28f3f9a   add  r3, pc, #616  @ 0x268\n'
                  ' 5d4:  e1c320d0   ldrd  r2, [r3]\n'
                  ' 5d8:  e28f1f9a   add  r1, pc, #616  @ 0x268\n'
                  ' 5dc:  e1c100d0   ldrd  r0, [r1]\n'
                  ' 5e0:  ebfffebc   bl  d8 <foo_03>\n'
                  "         'A', 0x1817161514131211, 'K', 'J', 0x1c1b1a19);\n"
                  '\n'
                  '  foo_04(1, 3, (struct struct_04){.a=0x0f101112, '
                  '.b=0x13141516, .c=0x17181920});\n'
                  ' 5e4:  e59f22cc   ldr  r2, [pc, #716]  @ 8b8 '
                  '<__entry__+0x348>\n'
                  ' 5e8:  e24b3010   sub  r3, fp, #16\n'
                  ' 5ec:  e8920007   ldm  r2, {r0, r1, r2}\n'
                  ' 5f0:  e8830007   stm  r3, {r0, r1, r2}\n'
                  ' 5f4:  e51b3008   ldr  r3, [fp, #-8]\n'
                  ' 5f8:  e58d3000   str  r3, [sp]\n'
                  ' 5fc:  e24b3010   sub  r3, fp, #16\n'
                  ' 600:  e893000c   ldm  r3, {r2, r3}\n'
                  ' 604:  e3a01003   mov  r1, #3\n'
                  ' 608:  e3a00001   mov  r0, #1\n'
                  ' 60c:  ebfffebf   bl  110 <foo_04>\n'
                  '\n'
                  '  foo_05((struct struct_05)\n'
                  "        {.a='a', .b=0x0f10, .c=0x11121314, .d='b', "
                  '.e=0x15161718191a1b1c});\n'
                  ' 610:  e59f32a4   ldr  r3, [pc, #676]  @ 8bc '
                  '<__entry__+0x34c>\n'
                  ' 614:  e24bc02c   sub  ip, fp, #44  @ 0x2c\n'
                  ' 618:  e1a0e003   mov  lr, r3\n'
                  ' 61c:  e8be000f   ldm  lr!, {r0, r1, r2, r3}\n'
                  ' 620:  e8ac000f   stmia  ip!, {r0, r1, r2, r3}\n'
                  ' 624:  e89e0003   ldm  lr, {r0, r1}\n'
                  ' 628:  e88c0003   stm  ip, {r0, r1}\n'
                  '  foo_05((struct struct_05)\n'
                  ' 62c:  e1a0200d   mov  r2, sp\n'
                  ' 630:  e24b301c   sub  r3, fp, #28\n'
                  ' 634:  e8930003   ldm  r3, {r0, r1}\n'
                  ' 638:  e8820003   stm  r2, {r0, r1}\n'
                  ' 63c:  e24b302c   sub  r3, fp, #44  @ 0x2c\n'
                  ' 640:  e893000f   ldm  r3, {r0, r1, r2, r3}\n'
                  ' 644:  ebfffebf   bl  148 <foo_05>\n'
                  '\n'
                  "  foo_06((struct struct_06){.a='a'});\n"
                  ' 648:  e3a03061   mov  r3, #97  @ 0x61\n'
                  ' 64c:  e1a00003   mov  r0, r3\n'
                  ' 650:  ebfffec7   bl  174 <foo_06>\n'
                  '\n'
                  '  foo_07(4, 0.5, 8, 0.75, 0.875);\n'
                  ' 654:  eddf0a8f   vldr  s1, [pc, #572]  @ 898 '
                  '<__entry__+0x328>\n'
                  ' 658:  ed9f1b7c   vldr  d1, [pc, #496]  @ 850 '
                  '<__entry__+0x2e0>\n'
                  ' 65c:  e3a01008   mov  r1, #8\n'
                  ' 660:  ed9f0a8d   vldr  s0, [pc, #564]  @ 89c '
                  '<__entry__+0x32c>\n'
                  ' 664:  e3a00004   mov  r0, #4\n'
                  ' 668:  ebfffeca   bl  198 <foo_07>\n'
                  '\n'
                  '  foo_08(4, 0.5, 8, 0.75, 0.875, 0.984375);\n'
                  ' 66c:  ed9f2a8b   vldr  s4, [pc, #556]  @ 8a0 '
                  '<__entry__+0x330>\n'
                  ' 670:  e3a03c3b   mov  r3, #15104  @ 0x3b00\n'
                  ' 674:  e3833000   orr  r3, r3, #0\n'
                  ' 678:  ee003a90   vmov  s1, r3\n'
                  ' 67c:  ed9f1b73   vldr  d1, [pc, #460]  @ 850 '
                  '<__entry__+0x2e0>\n'
                  ' 680:  e3a01008   mov  r1, #8\n'
                  ' 684:  ed9f0a84   vldr  s0, [pc, #528]  @ 89c '
                  '<__entry__+0x32c>\n'
                  ' 688:  e3a00004   mov  r0, #4\n'
                  ' 68c:  ebfffed0   bl  1d4 <foo_08>\n'
                  '\n'
                  '  foo_09((struct struct_09_4){.a={.a=0.5, .b=0.75},\n'
                  ' 690:  e59f3228   ldr  r3, [pc, #552]  @ 8c0 '
                  '<__entry__+0x350>\n'
                  ' 694:  e24bc04c   sub  ip, fp, #76  @ 0x4c\n'
                  ' 698:  e1a0e003   mov  lr, r3\n'
                  ' 69c:  e8be000f   ldm  lr!, {r0, r1, r2, r3}\n'
                  ' 6a0:  e8ac000f   stmia  ip!, {r0, r1, r2, r3}\n'
                  ' 6a4:  e89e000f   ldm  lr, {r0, r1, r2, r3}\n'
                  ' 6a8:  e88c000f   stm  ip, {r0, r1, r2, r3}\n'
                  ' 6ac:  ed1b4b13   vldr  d4, [fp, #-76]  @ 0xffffffb4\n'
                  ' 6b0:  ed1b5b11   vldr  d5, [fp, #-68]  @ 0xffffffbc\n'
                  ' 6b4:  ed1b6b0f   vldr  d6, [fp, #-60]  @ 0xffffffc4\n'
                  ' 6b8:  ed1b7b0d   vldr  d7, [fp, #-52]  @ 0xffffffcc\n'
                  ' 6bc:  eeb00b44   vmov.f64  d0, d4\n'
                  ' 6c0:  eeb01b45   vmov.f64  d1, d5\n'
                  ' 6c4:  eeb02b46   vmov.f64  d2, d6\n'
                  ' 6c8:  eeb03b47   vmov.f64  d3, d7\n'
                  ' 6cc:  ebfffed1   bl  218 <foo_09>\n'
                  '                              .wrap={.b={.c=0.875, '
                  '.d=0.984375}}});\n'
                  '\n'
                  '  foo_10(0.25, 0.375, 0.4375, 0.46875, 0.484375, 0.4921875, '
                  '0.49609375,\n'
                  ' 6d0:  e3a02000   mov  r2, #0\n'
                  ' 6d4:  e59f31e8   ldr  r3, [pc, #488]  @ 8c4 '
                  '<__entry__+0x354>\n'
                  ' 6d8:  e1cd20f8   strd  r2, [sp, #8]\n'
                  ' 6dc:  e3a02000   mov  r2, #0\n'
                  ' 6e0:  e59f31e0   ldr  r3, [pc, #480]  @ 8c8 '
                  '<__entry__+0x358>\n'
                  ' 6e4:  e1cd20f0   strd  r2, [sp]\n'
                  ' 6e8:  ed9f7b5a   vldr  d7, [pc, #360]  @ 858 '
                  '<__entry__+0x2e8>\n'
                  ' 6ec:  ed9f6b5b   vldr  d6, [pc, #364]  @ 860 '
                  '<__entry__+0x2f0>\n'
                  ' 6f0:  ed9f5b5c   vldr  d5, [pc, #368]  @ 868 '
                  '<__entry__+0x2f8>\n'
                  ' 6f4:  ed9f4b5d   vldr  d4, [pc, #372]  @ 870 '
                  '<__entry__+0x300>\n'
                  ' 6f8:  ed9f3b5e   vldr  d3, [pc, #376]  @ 878 '
                  '<__entry__+0x308>\n'
                  ' 6fc:  ed9f2b5f   vldr  d2, [pc, #380]  @ 880 '
                  '<__entry__+0x310>\n'
                  ' 700:  ed9f1b60   vldr  d1, [pc, #384]  @ 888 '
                  '<__entry__+0x318>\n'
                  ' 704:  ed9f0b61   vldr  d0, [pc, #388]  @ 890 '
                  '<__entry__+0x320>\n'
                  ' 708:  ebfffed4   bl  260 <foo_10>\n'
                  '         0.498046875, 0.4990234375, 0.49951171875);\n'
                  '\n'
                  '  foo_11(2, 3, 3.5, 3.75, 3.875, 8192, 12288, 14336, 15360, '
                  '15872, 16128, 512,\n'
                  ' 70c:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 710:  e38330f0   orr  r3, r3, #240  @ 0xf0\n'
                  ' 714:  e1cd30b4   strh  r3, [sp, #4]\n'
                  ' 718:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 71c:  e38330e0   orr  r3, r3, #224  @ 0xe0\n'
                  ' 720:  e1cd30b0   strh  r3, [sp]\n'
                  ' 724:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 728:  e38330c0   orr  r3, r3, #192  @ 0xc0\n'
                  ' 72c:  ee073a90   vmov  s15, r3\n'
                  ' 730:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 734:  e3833080   orr  r3, r3, #128  @ 0x80\n'
                  ' 738:  ee073a10   vmov  s14, r3\n'
                  ' 73c:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 740:  e3833000   orr  r3, r3, #0\n'
                  ' 744:  ee063a90   vmov  s13, r3\n'
                  ' 748:  e3a03c62   mov  r3, #25088  @ 0x6200\n'
                  ' 74c:  e3833000   orr  r3, r3, #0\n'
                  ' 750:  ee063a10   vmov  s12, r3\n'
                  ' 754:  e3a03a06   mov  r3, #24576  @ 0x6000\n'
                  ' 758:  e3833000   orr  r3, r3, #0\n'
                  ' 75c:  ee053a90   vmov  s11, r3\n'
                  ' 760:  e3a03c73   mov  r3, #29440  @ 0x7300\n'
                  ' 764:  e38330e0   orr  r3, r3, #224  @ 0xe0\n'
                  ' 768:  ee053a10   vmov  s10, r3\n'
                  ' 76c:  e3a03c73   mov  r3, #29440  @ 0x7300\n'
                  ' 770:  e38330c0   orr  r3, r3, #192  @ 0xc0\n'
                  ' 774:  ee043a90   vmov  s9, r3\n'
                  ' 778:  e3a03c73   mov  r3, #29440  @ 0x7300\n'
                  ' 77c:  e3833080   orr  r3, r3, #128  @ 0x80\n'
                  ' 780:  ee043a10   vmov  s8, r3\n'
                  ' 784:  e3a03c73   mov  r3, #29440  @ 0x7300\n'
                  ' 788:  e3833000   orr  r3, r3, #0\n'
                  ' 78c:  ee033a90   vmov  s7, r3\n'
                  ' 790:  e3a03c72   mov  r3, #29184  @ 0x7200\n'
                  ' 794:  e3833000   orr  r3, r3, #0\n'
                  ' 798:  ee033a10   vmov  s6, r3\n'
                  ' 79c:  e3a03a07   mov  r3, #28672  @ 0x7000\n'
                  ' 7a0:  e3833000   orr  r3, r3, #0\n'
                  ' 7a4:  ee023a90   vmov  s5, r3\n'
                  ' 7a8:  e3a03c43   mov  r3, #17152  @ 0x4300\n'
                  ' 7ac:  e38330c0   orr  r3, r3, #192  @ 0xc0\n'
                  ' 7b0:  ee023a10   vmov  s4, r3\n'
                  ' 7b4:  e3a03c43   mov  r3, #17152  @ 0x4300\n'
                  ' 7b8:  e3833080   orr  r3, r3, #128  @ 0x80\n'
                  ' 7bc:  ee013a90   vmov  s3, r3\n'
                  ' 7c0:  e3a03c43   mov  r3, #17152  @ 0x4300\n'
                  ' 7c4:  e3833000   orr  r3, r3, #0\n'
                  ' 7c8:  ee013a10   vmov  s2, r3\n'
                  ' 7cc:  e3a03c42   mov  r3, #16896  @ 0x4200\n'
                  ' 7d0:  e3833000   orr  r3, r3, #0\n'
                  ' 7d4:  ee003a90   vmov  s1, r3\n'
                  ' 7d8:  e3a03901   mov  r3, #16384  @ 0x4000\n'
                  ' 7dc:  e3833000   orr  r3, r3, #0\n'
                  ' 7e0:  ee003a10   vmov  s0, r3\n'
                  ' 7e4:  ebfffeb0   bl  2ac <foo_11>\n'
                  '         768, 896, 960, 992, 1008, 1016);\n'
                  '\n'
                  '  foo_12();\n'
                  ' 7e8:  ebfffed9   bl  354 <foo_12>\n'
                  '  foo_13();\n'
                  ' 7ec:  ebfffee0   bl  374 <foo_13>\n'
                  '  foo_14();\n'
                  ' 7f0:  ebfffeea   bl  3a0 <foo_14>\n'
                  '  foo_15();\n'
                  ' 7f4:  ebffff07   bl  418 <foo_15>\n'
                  '  foo_16();\n'
                  ' 7f8:  ebffff0f   bl  43c <foo_16>\n'
                  '  foo_17();\n'
                  ' 7fc:  ebffff16   bl  45c <foo_17>\n'
                  '  foo_19();\n'
                  ' 800:  ebffff36   bl  4e0 <foo_19>\n'
                  '  foo_20(0x1234);\n'
                  ' 804:  e59f00c0   ldr  r0, [pc, #192]  @ 8cc '
                  '<__entry__+0x35c>\n'
                  ' 808:  ebffff3a   bl  4f8 <foo_20>\n'
                  '  foo_21((unsigned char *) 0xC0DEC0FE);\n'
                  ' 80c:  e59f00bc   ldr  r0, [pc, #188]  @ 8d0 '
                  '<__entry__+0x360>\n'
                  ' 810:  ebffff42   bl  520 <foo_21>\n'
                  '  foo_22((unsigned char **) 0xC0FEC0DE);\n'
                  ' 814:  e59f00b8   ldr  r0, [pc, #184]  @ 8d4 '
                  '<__entry__+0x364>\n'
                  ' 818:  ebffff4a   bl  548 <foo_22>\n'
                  '\n'
                  '#ifdef WITH_FP_HARD\n'
                  '  foo_18();\n'
                  ' 81c:  ebffff18   bl  484 <foo_18>\n'
                  '#endif\n'
                  '}\n'
                  ' 820:  e320f000   nop  {0}\n'
                  ' 824:  e24bd004   sub  sp, fp, #4\n'
                  ' 828:  e8bd8800   pop  {fp, pc}\n'
                  ' 82c:  e320f000   nop  {0}\n'
                  ' 830:  090a0b0c   .word  0x090a0b0c\n'
                  ' 834:  05060708   .word  0x05060708\n'
                  ' 838:  14131211   .word  0x14131211\n'
                  ' 83c:  18171615   .word  0x18171615\n'
                  ' 840:  0c0b0a09   .word  0x0c0b0a09\n'
                  ' 844:  100f0e0d   .word  0x100f0e0d\n'
                  ' 848:  04030201   .word  0x04030201\n'
                  ' 84c:  08070605   .word  0x08070605\n'
                  ' 850:  00000000   .word  0x00000000\n'
                  ' 854:  3fe80000   .word  0x3fe80000\n'
                  ' 858:  00000000   .word  0x00000000\n'
                  ' 85c:  3fdfe000   .word  0x3fdfe000\n'
                  ' 860:  00000000   .word  0x00000000\n'
                  ' 864:  3fdfc000   .word  0x3fdfc000\n'
                  ' 868:  00000000   .word  0x00000000\n'
                  ' 86c:  3fdf8000   .word  0x3fdf8000\n'
                  ' 870:  00000000   .word  0x00000000\n'
                  ' 874:  3fdf0000   .word  0x3fdf0000\n'
                  ' 878:  00000000   .word  0x00000000\n'
                  ' 87c:  3fde0000   .word  0x3fde0000\n'
                  ' 880:  00000000   .word  0x00000000\n'
                  ' 884:  3fdc0000   .word  0x3fdc0000\n'
                  ' 888:  00000000   .word  0x00000000\n'
                  ' 88c:  3fd80000   .word  0x3fd80000\n'
                  ' 890:  00000000   .word  0x00000000\n'
                  ' 894:  3fd00000   .word  0x3fd00000\n'
                  ' 898:  3f600000   .word  0x3f600000\n'
                  ' 89c:  3f000000   .word  0x3f000000\n'
                  ' 8a0:  3f7c0000   .word  0x3f7c0000\n'
                  ' 8a4:  0d0e0f10   .word  0x0d0e0f10\n'
                  ' 8a8:  090a0b0c   .word  0x090a0b0c\n'
                  ' 8ac:  05060708   .word  0x05060708\n'
                  ' 8b0:  01020304   .word  0x01020304\n'
                  ' 8b4:  1c1b1a19   .word  0x1c1b1a19\n'
                  ' 8b8:  000008ec   .word  0x000008ec\n'
                  ' 8bc:  000008f8   .word  0x000008f8\n'
                  ' 8c0:  00000910   .word  0x00000910\n'
                  ' 8c4:  3fdff800   .word  0x3fdff800\n'
                  ' 8c8:  3fdff000   .word  0x3fdff000\n'
                  ' 8cc:  00001234   .word  0x00001234\n'
                  ' 8d0:  c0dec0fe   .word  0xc0dec0fe\n'
                  ' 8d4:  c0fec0de   .word  0xc0fec0de\n',
   'mapped_blobs': [{'loading_address': 0,
                     'blob': b'\x06\x00\x00\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\x80\x00\xc0\xe3\x00\xf0\x29\xe1\x01\xd9\xa0\xe3\x4f\x01\x00\xeb\x00\x00\xa0\xe1\xfe\xff\xff\xea\xf0\x5f\x2d\xe9\x1c\x40\x9f\xe5\x04\x40\x2d\xe5\x00\x00\xa0\xe1\x00\x00\xa0\xe1\x00\x00\xa0\xe1\x00\x00\xa0\xe1\x00\x00\xa0\xe1\x04\x00\x9d\xe4\xf0\x9f\xbd\xe8\xbe\xba\xef\xbe\x00\x00\x00\x00\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x14\xd0\x4d\xe2\x08\x00\x0b\xe5\x0c\x10\x0b\xe5\x10\x20\x0b\xe5\x14\x30\x0b\xe5\x0c\x30\x9f\xe5\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x04\x03\x02\x01\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x14\xd0\x4d\xe2\x08\x00\x0b\xe5\xf4\x21\x4b\xe1\x18\x30\x8f\xe2\xd0\x20\xc3\xe1\x02\x00\xa0\xe1\x03\x10\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x00\xf0\x20\xe3\x08\x07\x06\x05\x04\x03\x02\x01\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x14\xd0\x4d\xe2\xfc\x00\x4b\xe1\xf4\x21\x4b\xe1\x14\x30\x8f\xe2\xd0\x20\xc3\xe1\x02\x00\xa0\xe1\x03\x10\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x08\x07\x06\x05\x04\x03\x02\x01\x08\xd0\x4d\xe2\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\xd0\x4d\xe2\x08\x00\x0b\xe5\x0c\x10\x0b\xe5\x04\x10\x8b\xe2\x0c\x00\x81\xe8\x01\x30\xa0\xe3\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x08\xd0\x8d\xe2\x1e\xff\x2f\xe1\x10\xd0\x4d\xe2\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x04\xc0\x8b\xe2\x0f\x00\x8c\xe8\x01\x30\xa0\xe3\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x10\xd0\x8d\xe2\x1e\xff\x2f\xe1\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\xd0\x4d\xe2\x08\x00\x4b\xe5\x41\x30\xa0\xe3\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x1c\xd0\x4d\xe2\x08\x00\x0b\xe5\x03\x0a\x0b\xed\x10\x10\x0b\xe5\x07\x1b\x0b\xed\x05\x0a\x4b\xed\x10\x30\x9f\xe5\x90\x3a\x07\xee\x67\x0a\xb0\xee\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x00\x00\x70\x3f\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x24\xd0\x4d\xe2\x08\x00\x0b\xe5\x03\x0a\x0b\xed\x10\x10\x0b\xe5\x07\x1b\x0b\xed\x90\x3a\x10\xee\xb2\x31\x4b\xe1\x08\x2a\x0b\xed\x10\x30\x9f\xe5\x90\x3a\x07\xee\x67\x0a\xb0\xee\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x00\x00\x70\x3f\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x24\xd0\x4d\xe2\x40\x4b\xb0\xee\x41\x5b\xb0\xee\x42\x6b\xb0\xee\x43\x7b\xb0\xee\x09\x4b\x0b\xed\x07\x5b\x0b\xed\x05\x6b\x0b\xed\x03\x7b\x0b\xed\x10\x30\x9f\xe5\x90\x3a\x07\xee\x67\x0a\xb0\xee\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x00\x00\x70\x3f\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x44\xd0\x4d\xe2\x03\x0b\x0b\xed\x05\x1b\x0b\xed\x07\x2b\x0b\xed\x09\x3b\x0b\xed\x0b\x4b\x0b\xed\x0d\x5b\x0b\xed\x0f\x6b\x0b\xed\x11\x7b\x0b\xed\x00\x20\xa0\xe3\x10\x30\x9f\xe5\x17\x2b\x43\xec\x47\x0b\xb0\xee\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x00\x00\xd0\x3f\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x24\xd0\x4d\xe2\x10\x3a\x10\xee\xb6\x30\x4b\xe1\x90\x3a\x10\xee\xb8\x30\x4b\xe1\x10\x3a\x11\xee\xba\x30\x4b\xe1\x90\x3a\x11\xee\xbc\x30\x4b\xe1\x10\x3a\x12\xee\xbe\x30\x4b\xe1\x90\x3a\x12\xee\xb0\x31\x4b\xe1\x10\x3a\x13\xee\xb2\x31\x4b\xe1\x90\x3a\x13\xee\xb4\x31\x4b\xe1\x10\x3a\x14\xee\xb6\x31\x4b\xe1\x90\x3a\x14\xee\xb8\x31\x4b\xe1\x10\x3a\x15\xee\xba\x31\x4b\xe1\x90\x3a\x15\xee\xbc\x31\x4b\xe1\x10\x3a\x16\xee\xbe\x31\x4b\xe1\x90\x3a\x16\xee\xb0\x32\x4b\xe1\x10\x3a\x17\xee\xb2\x32\x4b\xe1\x90\x3a\x17\xee\xb4\x32\x4b\xe1\x0d\x3b\xa0\xe3\x00\x30\x83\xe3\x90\x3a\x07\xee\x67\x0a\xb0\xee\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\x30\x9f\xe5\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\xcd\xab\x00\x00\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x14\x30\x8f\xe2\xd0\x20\xc3\xe1\x02\x00\xa0\xe1\x03\x10\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\xd0\x4d\xe2\x60\x20\x9f\xe5\x08\x30\x4b\xe2\x00\x20\x92\xe5\xb0\x20\xc3\xe1\x02\x30\x83\xe2\x22\x28\xa0\xe1\x00\x20\xc3\xe5\x00\x30\xa0\xe3\x08\x20\x5b\xe5\x72\x20\xef\xe6\xff\x30\xc3\xe3\x03\x30\x82\xe1\x07\x20\x5b\xe5\x72\x20\xef\xe6\xff\x3c\xc3\xe3\x02\x24\xa0\xe1\x03\x30\x82\xe1\x06\x20\x5b\xe5\x72\x20\xef\xe6\xff\x38\xc3\xe3\x02\x28\xa0\xe1\x03\x30\x82\xe1\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\xd8\x08\x00\x00\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x43\x3c\xa0\xe3\xc0\x30\x83\xe3\x90\x3a\x07\xee\x67\x0a\xb0\xee\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\xfd\x35\xa0\xe3\x90\x3a\x07\xee\x67\x0a\xb0\xee\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x00\x20\xa0\xe3\x10\x30\x9f\xe5\x17\x2b\x43\xec\x47\x0b\xb0\xee\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x00\x00\xe8\x3f\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x34\xd0\x4d\xe2\x44\x30\x9f\xe5\x14\xc0\x4b\xe2\x0f\x00\x93\xe8\x0f\x00\x8c\xe8\x14\x00\x1b\xe5\x10\x10\x1b\xe5\x0c\x20\x1b\xe5\x08\x30\x1b\xe5\x10\x0a\x06\xee\x90\x1a\x06\xee\x10\x2a\x07\xee\x90\x3a\x07\xee\x46\x0a\xb0\xee\x66\x0a\xf0\xee\x47\x1a\xb0\xee\x67\x1a\xf0\xee\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\xdc\x08\x00\x00\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x00\xf0\x20\xe3\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\xd0\x4d\xe2\x00\x30\xa0\xe1\xb6\x30\x4b\xe1\x01\x30\xa0\xe3\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\xd0\x4d\xe2\x08\x00\x0b\xe5\x0c\x30\x9f\xe5\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\xbe\xba\xde\xba\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\xd0\x4d\xe2\x08\x00\x0b\xe5\x0c\x30\x9f\xe5\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d\xe4\x1e\xff\x2f\xe1\xde\xba\xbe\xba\x00\x48\x2d\xe9\x04\xb0\x8d\xe2\x68\xd0\x4d\xe2\xad\xfe\xff\xeb\x1c\x33\x9f\xe5\x1c\x23\x9f\xe5\x1c\x13\x9f\xe5\x1c\x03\x9f\xe5\xb4\xfe\xff\xeb\xa5\x3f\x8f\xe2\xd0\x20\xc3\xe1\x0c\x03\x9f\xe5\xbd\xfe\xff\xeb\x08\x33\x9f\xe5\x18\x30\x8d\xe5\x4a\x30\xa0\xe3\x14\x30\x8d\xe5\x4b\x30\xa0\xe3\x10\x30\x8d\xe5\x9d\x3f\x8f\xe2\xd0\x20\xc3\xe1\xf8\x20\xcd\xe1\x41\x30\xa0\xe3\x00\x30\x8d\xe5\x9a\x3f\x8f\xe2\xd0\x20\xc3\xe1\x9a\x1f\x8f\xe2\xd0\x00\xc1\xe1\xbc\xfe\xff\xeb\xcc\x22\x9f\xe5\x10\x30\x4b\xe2\x07\x00\x92\xe8\x07\x00\x83\xe8\x08\x30\x1b\xe5\x00\x30\x8d\xe5\x10\x30\x4b\xe2\x0c\x00\x93\xe8\x03\x10\xa0\xe3\x01\x00\xa0\xe3\xbf\xfe\xff\xeb\xa4\x32\x9f\xe5\x2c\xc0\x4b\xe2\x03\xe0\xa0\xe1\x0f\x00\xbe\xe8\x0f\x00\xac\xe8\x03\x00\x9e\xe8\x03\x00\x8c\xe8\x0d\x20\xa0\xe1\x1c\x30\x4b\xe2\x03\x00\x93\xe8\x03\x00\x82\xe8\x2c\x30\x4b\xe2\x0f\x00\x93\xe8\xbf\xfe\xff\xeb\x61\x30\xa0\xe3\x03\x00\xa0\xe1\xc7\xfe\xff\xeb\x8f\x0a\xdf\xed\x7c\x1b\x9f\xed\x08\x10\xa0\xe3\x8d\x0a\x9f\xed\x04\x00\xa0\xe3\xca\xfe\xff\xeb\x8b\x2a\x9f\xed\x3b\x3c\xa0\xe3\x00\x30\x83\xe3\x90\x3a\x00\xee\x73\x1b\x9f\xed\x08\x10\xa0\xe3\x84\x0a\x9f\xed\x04\x00\xa0\xe3\xd0\xfe\xff\xeb\x28\x32\x9f\xe5\x4c\xc0\x4b\xe2\x03\xe0\xa0\xe1\x0f\x00\xbe\xe8\x0f\x00\xac\xe8\x0f\x00\x9e\xe8\x0f\x00\x8c\xe8\x13\x4b\x1b\xed\x11\x5b\x1b\xed\x0f\x6b\x1b\xed\x0d\x7b\x1b\xed\x44\x0b\xb0\xee\x45\x1b\xb0\xee\x46\x2b\xb0\xee\x47\x3b\xb0\xee\xd1\xfe\xff\xeb\x00\x20\xa0\xe3\xe8\x31\x9f\xe5\xf8\x20\xcd\xe1\x00\x20\xa0\xe3\xe0\x31\x9f\xe5\xf0\x20\xcd\xe1\x5a\x7b\x9f\xed\x5b\x6b\x9f\xed\x5c\x5b\x9f\xed\x5d\x4b\x9f\xed\x5e\x3b\x9f\xed\x5f\x2b\x9f\xed\x60\x1b\x9f\xed\x61\x0b\x9f\xed\xd4\xfe\xff\xeb\x63\x3c\xa0\xe3\xf0\x30\x83\xe3\xb4\x30\xcd\xe1\x63\x3c\xa0\xe3\xe0\x30\x83\xe3\xb0\x30\xcd\xe1\x63\x3c\xa0\xe3\xc0\x30\x83\xe3\x90\x3a\x07\xee\x63\x3c\xa0\xe3\x80\x30\x83\xe3\x10\x3a\x07\xee\x63\x3c\xa0\xe3\x00\x30\x83\xe3\x90\x3a\x06\xee\x62\x3c\xa0\xe3\x00\x30\x83\xe3\x10\x3a\x06\xee\x06\x3a\xa0\xe3\x00\x30\x83\xe3\x90\x3a\x05\xee\x73\x3c\xa0\xe3\xe0\x30\x83\xe3\x10\x3a\x05\xee\x73\x3c\xa0\xe3\xc0\x30\x83\xe3\x90\x3a\x04\xee\x73\x3c\xa0\xe3\x80\x30\x83\xe3\x10\x3a\x04\xee\x73\x3c\xa0\xe3\x00\x30\x83\xe3\x90\x3a\x03\xee\x72\x3c\xa0\xe3\x00\x30\x83\xe3\x10\x3a\x03\xee\x07\x3a\xa0\xe3\x00\x30\x83\xe3\x90\x3a\x02\xee\x43\x3c\xa0\xe3\xc0\x30\x83\xe3\x10\x3a\x02\xee\x43\x3c\xa0\xe3\x80\x30\x83\xe3\x90\x3a\x01\xee\x43\x3c\xa0\xe3\x00\x30\x83\xe3\x10\x3a\x01\xee\x42\x3c\xa0\xe3\x00\x30\x83\xe3\x90\x3a\x00\xee\x01\x39\xa0\xe3\x00\x30\x83\xe3\x10\x3a\x00\xee\xb0\xfe\xff\xeb\xd9\xfe\xff\xeb\xe0\xfe\xff\xeb\xea\xfe\xff\xeb\x07\xff\xff\xeb\x0f\xff\xff\xeb\x16\xff\xff\xeb\x36\xff\xff\xeb\xc0\x00\x9f\xe5\x3a\xff\xff\xeb\xbc\x00\x9f\xe5\x42\xff\xff\xeb\xb8\x00\x9f\xe5\x4a\xff\xff\xeb\x18\xff\xff\xeb\x00\xf0\x20\xe3\x04\xd0\x4b\xe2\x00\x88\xbd\xe8\x00\xf0\x20\xe3\x0c\x0b\x0a\x09\x08\x07\x06\x05\x11\x12\x13\x14\x15\x16\x17\x18\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\xe8\x3f\x00\x00\x00\x00\x00\xe0\xdf\x3f\x00\x00\x00\x00\x00\xc0\xdf\x3f\x00\x00\x00\x00\x00\x80\xdf\x3f\x00\x00\x00\x00\x00\x00\xdf\x3f\x00\x00\x00\x00\x00\x00\xde\x3f\x00\x00\x00\x00\x00\x00\xdc\x3f\x00\x00\x00\x00\x00\x00\xd8\x3f\x00\x00\x00\x00\x00\x00\xd0\x3f\x00\x00\x60\x3f\x00\x00\x00\x3f\x00\x00\x7c\x3f\x10\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01\x19\x1a\x1b\x1c\xec\x08\x00\x00\xf8\x08\x00\x00\x10\x09\x00\x00\x00\xf8\xdf\x3f\x00\xf0\xdf\x3f\x34\x12\x00\x00\xfe\xc0\xde\xc0\xde\xc0\xfe\xc0\x49\x4a\x4b\x00\x00\x00\x00\x3f\x00\x00\x40\x3f\x00\x00\x60\x3f\x00\x00\x7c\x3f\x12\x11\x10\x0f\x16\x15\x14\x13\x20\x19\x18\x17\x61\x00\x10\x0f\x14\x13\x12\x11\x62\x00\x00\x00\x00\x00\x00\x00\x1c\x1b\x1a\x19\x18\x17\x16\x15\x00\x00\x00\x00\x00\x00\xe0\x3f\x00\x00\x00\x00\x00\x00\xe8\x3f\x00\x00\x00\x00\x00\x00\xec\x3f\x00\x00\x00\x00\x00\x80\xef\x3f'}],
   'extra': {}}

BlobCcAapcs32ArmelV6HardFloatFp16Ieee = MetaBinBlob.from_dict(meta_blob_cc_aapcs32_armel_v6_hard_float_fp16_ieee)


from ...cc.source_code_analyzer import MetaSourceCode

meta_source_code_cc_aapcs32_armel_v6_hard_float_fp16_ieee = \
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
             'size': 60,
             'name': 'foo_07',
             'return_value_type': 'float',
             'return_value': 0.9375,
             'arguments': {0: ('a', 'int'),
                           1: ('x', 'float'),
                           2: ('b', 'int'),
                           3: ('y', 'double'),
                           4: ('z', 'float')},
             'call_arg_values': {0: 4, 1: 0.5, 2: 8, 3: 0.75, 4: 0.875}},
            {'address': 468,
             'size': 68,
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
            {'address': 536,
             'size': 72,
             'name': 'foo_09',
             'return_value_type': 'float',
             'return_value': 0.9375,
             'arguments': {0: ('a', 'struct struct_09_4')},
             'call_arg_values': {0: {'a': {'a': 0.5, 'b': 0.75},
                                     'wrap': {'b': {'c': 0.875,
                                                    'd': 0.984375}}}}},
            {'address': 608,
             'size': 76,
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
            {'address': 684,
             'size': 168,
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
            {'address': 852,
             'size': 32,
             'name': 'foo_12',
             'return_value_type': 'unsigned short',
             'return_value': 43981,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 884,
             'size': 44,
             'name': 'foo_13',
             'return_value_type': 'unsigned long long',
             'return_value': 18441921395520346504,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 928,
             'size': 120,
             'name': 'foo_14',
             'return_value_type': 'struct struct_14',
             'return_value': {'a': 73, 'b': 74, 'c': 75},
             'arguments': {},
             'call_arg_values': {}},
            {'address': 1048,
             'size': 36,
             'name': 'foo_15',
             'return_value_type': '__fp16',
             'return_value': 3.875,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 1084,
             'size': 32,
             'name': 'foo_16',
             'return_value_type': 'float',
             'return_value': 0.75,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 1116,
             'size': 40,
             'name': 'foo_17',
             'return_value_type': 'double',
             'return_value': 0.75,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 1156,
             'size': 92,
             'name': 'foo_18',
             'return_value_type': 'struct struct_18_wrap_l2',
             'return_value': {'a': {'a': 0.5, 'b': 0.75},
                              'wrap': {'b': {'c': 0.875, 'd': 0.984375}}},
             'arguments': {},
             'call_arg_values': {}},
            {'address': 1248,
             'size': 24,
             'name': 'foo_19',
             'return_value_type': None,
             'return_value': None,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 1272,
             'size': 40,
             'name': 'foo_20',
             'return_value_type': 'unsigned int',
             'return_value': 1,
             'arguments': {0: ('a', 'unsigned short')},
             'call_arg_values': {0: 4660}},
            {'address': 1312,
             'size': 40,
             'name': 'foo_21',
             'return_value_type': 'unsigned char*',
             'return_value': 3135158974,
             'arguments': {0: ('a', 'unsigned char*')},
             'call_arg_values': {0: 3235823870}},
            {'address': 1352,
             'size': 40,
             'name': 'foo_22',
             'return_value_type': 'unsigned char**',
             'return_value': 3133061854,
             'arguments': {0: ('a', 'unsigned char**')},
             'call_arg_values': {0: 3237920990}},
            {'address': 1392,
             'size': 872,
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
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 'struct struct_18_a { float a; float b; };\n'
                 '\n'
                 'struct struct_18_b { float c; float d; };\n'
                 '\n'
                 'struct struct_18_wrap_l1 { struct struct_18_b b; };\n'
                 '\n'
                 'struct struct_18_wrap_l2 { struct struct_18_a a; struct '
                 'struct_18_wrap_l1 wrap; };\n'
                 '\n'
                 'struct struct_18_wrap_l2 foo_18(void)\n'
                 '{\n'
                 '    return (struct struct_18_wrap_l2){\n'
                 '        .a = {.a=0.5, .b=0.75}, .wrap = {.b = {.c=0.875, '
                 '.d=0.984375}}};\n'
                 '}\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
                 '\n'
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
                 '  foo_18();\n'
                 '\n'
                 '}\n'}

MetaSourceCodeCcAapcs32ArmelV6HardFloatFp16Ieee = MetaSourceCode.from_dict(meta_source_code_cc_aapcs32_armel_v6_hard_float_fp16_ieee)

BlobCcAapcs32ArmelV6HardFloatFp16Ieee.extra.update({"cc_test_data": MetaSourceCodeCcAapcs32ArmelV6HardFloatFp16Ieee})
