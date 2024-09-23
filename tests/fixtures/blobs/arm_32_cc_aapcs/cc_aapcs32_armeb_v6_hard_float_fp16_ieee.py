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

meta_blob_cc_aapcs32_armeb_v6_hard_float_fp16_ieee = \
  {'arch_unicorn': 'arm:eb:32:1176',
   'arch_info': {'cpu_float_flag': 'FLOAT_HARD',
                 'tag_cpu_arch': 'v6KZ',
                 'tag_cpu_name': 'ARM1176JZF-S',
                 'tag_fp_arch': 'VFPv2',
                 'tag_abi_fp_16bit_format': 'IEEE754'},
   'compiler': 'GCC: (Arch Repository) 13.1.0\x00',
   'producer': 'GNU C17 13.1.0 -mthumb-interwork -mcpu=arm1176jzf-s '
               '-mbig-endian -mfpu=vfp -mfloat-abi=hard -mfp16-format=ieee '
               '-marm -march=armv6kz+fp -g -O0',
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
                  '  2c:  eb000156   bl  58c <__entry__>\n'
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
                  ' 1a4:  e24dd01c   sub  sp, sp, #28\n'
                  ' 1a8:  e50b0008   str  r0, [fp, #-8]\n'
                  ' 1ac:  ed0b0a03   vstr  s0, [fp, #-12]\n'
                  ' 1b0:  e50b1010   str  r1, [fp, #-16]\n'
                  ' 1b4:  ed0b1b07   vstr  d1, [fp, #-28]  @ 0xffffffe4\n'
                  ' 1b8:  ed4b0a05   vstr  s1, [fp, #-20]  @ 0xffffffec\n'
                  '  return 0.9375;\n'
                  ' 1bc:  e59f3010   ldr  r3, [pc, #16]  @ 1d4 <foo_07+0x38>\n'
                  ' 1c0:  ee073a90   vmov  s15, r3\n'
                  '}\n'
                  ' 1c4:  eeb00a67   vmov.f32  s0, s15\n'
                  ' 1c8:  e28bd000   add  sp, fp, #0\n'
                  ' 1cc:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 1d0:  e12fff1e   bx  lr\n'
                  ' 1d4:  3f700000   .word  0x3f700000\n'
                  '\n'
                  '000001d8 <foo_08>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'float foo_08(int a, float b, int c, double d, __fp16 e, '
                  'float f)\n'
                  '{\n'
                  ' 1d8:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 1dc:  e28db000   add  fp, sp, #0\n'
                  ' 1e0:  e24dd024   sub  sp, sp, #36  @ 0x24\n'
                  ' 1e4:  e50b0008   str  r0, [fp, #-8]\n'
                  ' 1e8:  ed0b0a03   vstr  s0, [fp, #-12]\n'
                  ' 1ec:  e50b1010   str  r1, [fp, #-16]\n'
                  ' 1f0:  ed0b1b07   vstr  d1, [fp, #-28]  @ 0xffffffe4\n'
                  ' 1f4:  ee103a90   vmov  r3, s1\n'
                  ' 1f8:  e14b31b2   strh  r3, [fp, #-18]  @ 0xffffffee\n'
                  ' 1fc:  ed0b2a08   vstr  s4, [fp, #-32]  @ 0xffffffe0\n'
                  '  return 0.9375;\n'
                  ' 200:  e59f3010   ldr  r3, [pc, #16]  @ 218 <foo_08+0x40>\n'
                  ' 204:  ee073a90   vmov  s15, r3\n'
                  '}\n'
                  ' 208:  eeb00a67   vmov.f32  s0, s15\n'
                  ' 20c:  e28bd000   add  sp, fp, #0\n'
                  ' 210:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 214:  e12fff1e   bx  lr\n'
                  ' 218:  3f700000   .word  0x3f700000\n'
                  '\n'
                  '0000021c <foo_09>:\n'
                  'struct struct_09_2 { double c; double d; };\n'
                  'struct struct_09_3 { struct struct_09_2 b; };\n'
                  'struct struct_09_4 { struct struct_09_1 a; struct '
                  'struct_09_3 wrap; };\n'
                  '\n'
                  'float foo_09(struct struct_09_4 a)\n'
                  '{\n'
                  ' 21c:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 220:  e28db000   add  fp, sp, #0\n'
                  ' 224:  e24dd024   sub  sp, sp, #36  @ 0x24\n'
                  ' 228:  eeb04b40   vmov.f64  d4, d0\n'
                  ' 22c:  eeb05b41   vmov.f64  d5, d1\n'
                  ' 230:  eeb06b42   vmov.f64  d6, d2\n'
                  ' 234:  eeb07b43   vmov.f64  d7, d3\n'
                  ' 238:  ed0b4b09   vstr  d4, [fp, #-36]  @ 0xffffffdc\n'
                  ' 23c:  ed0b5b07   vstr  d5, [fp, #-28]  @ 0xffffffe4\n'
                  ' 240:  ed0b6b05   vstr  d6, [fp, #-20]  @ 0xffffffec\n'
                  ' 244:  ed0b7b03   vstr  d7, [fp, #-12]\n'
                  '  return 0.9375;\n'
                  ' 248:  e59f3010   ldr  r3, [pc, #16]  @ 260 <foo_09+0x44>\n'
                  ' 24c:  ee073a90   vmov  s15, r3\n'
                  '}\n'
                  ' 250:  eeb00a67   vmov.f32  s0, s15\n'
                  ' 254:  e28bd000   add  sp, fp, #0\n'
                  ' 258:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 25c:  e12fff1e   bx  lr\n'
                  ' 260:  3f700000   .word  0x3f700000\n'
                  '\n'
                  '00000264 <foo_10>:\n'
                  '// force aapcs32 c2 rule vfp registers with double.\n'
                  '//##############################################################################\n'
                  'double foo_10(double x1, double x2, double x3, double x4,\n'
                  '              double x5, double x6, double x7, double x8,\n'
                  '              double x9, double x10)\n'
                  '{\n'
                  ' 264:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 268:  e28db000   add  fp, sp, #0\n'
                  ' 26c:  e24dd044   sub  sp, sp, #68  @ 0x44\n'
                  ' 270:  ed0b0b03   vstr  d0, [fp, #-12]\n'
                  ' 274:  ed0b1b05   vstr  d1, [fp, #-20]  @ 0xffffffec\n'
                  ' 278:  ed0b2b07   vstr  d2, [fp, #-28]  @ 0xffffffe4\n'
                  ' 27c:  ed0b3b09   vstr  d3, [fp, #-36]  @ 0xffffffdc\n'
                  ' 280:  ed0b4b0b   vstr  d4, [fp, #-44]  @ 0xffffffd4\n'
                  ' 284:  ed0b5b0d   vstr  d5, [fp, #-52]  @ 0xffffffcc\n'
                  ' 288:  ed0b6b0f   vstr  d6, [fp, #-60]  @ 0xffffffc4\n'
                  ' 28c:  ed0b7b11   vstr  d7, [fp, #-68]  @ 0xffffffbc\n'
                  '  return 0.25;\n'
                  ' 290:  e3a03000   mov  r3, #0\n'
                  ' 294:  e59f2010   ldr  r2, [pc, #16]  @ 2ac <foo_10+0x48>\n'
                  ' 298:  ec423b17   vmov  d7, r3, r2\n'
                  '}\n'
                  ' 29c:  eeb00b47   vmov.f64  d0, d7\n'
                  ' 2a0:  e28bd000   add  sp, fp, #0\n'
                  ' 2a4:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 2a8:  e12fff1e   bx  lr\n'
                  ' 2ac:  3fd00000   .word  0x3fd00000\n'
                  '\n'
                  '000002b0 <foo_11>:\n'
                  '//#############################################################################\n'
                  '__fp16 foo_11(__fp16 x1, __fp16 x2, __fp16 x3, __fp16 x4, '
                  '__fp16 x5, __fp16 x6,\n'
                  '              __fp16 x7, __fp16 x8, __fp16 x9, __fp16 x10, '
                  '__fp16 x11,\n'
                  '              __fp16 x12, __fp16 x13, __fp16 x14, __fp16 '
                  'x15, __fp16 x16,\n'
                  '              __fp16 x17, __fp16 x18)\n'
                  '{\n'
                  ' 2b0:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 2b4:  e28db000   add  fp, sp, #0\n'
                  ' 2b8:  e24dd024   sub  sp, sp, #36  @ 0x24\n'
                  ' 2bc:  ee103a10   vmov  r3, s0\n'
                  ' 2c0:  e14b30b6   strh  r3, [fp, #-6]\n'
                  ' 2c4:  ee103a90   vmov  r3, s1\n'
                  ' 2c8:  e14b30b8   strh  r3, [fp, #-8]\n'
                  ' 2cc:  ee113a10   vmov  r3, s2\n'
                  ' 2d0:  e14b30ba   strh  r3, [fp, #-10]\n'
                  ' 2d4:  ee113a90   vmov  r3, s3\n'
                  ' 2d8:  e14b30bc   strh  r3, [fp, #-12]\n'
                  ' 2dc:  ee123a10   vmov  r3, s4\n'
                  ' 2e0:  e14b30be   strh  r3, [fp, #-14]\n'
                  ' 2e4:  ee123a90   vmov  r3, s5\n'
                  ' 2e8:  e14b31b0   strh  r3, [fp, #-16]\n'
                  ' 2ec:  ee133a10   vmov  r3, s6\n'
                  ' 2f0:  e14b31b2   strh  r3, [fp, #-18]  @ 0xffffffee\n'
                  ' 2f4:  ee133a90   vmov  r3, s7\n'
                  ' 2f8:  e14b31b4   strh  r3, [fp, #-20]  @ 0xffffffec\n'
                  ' 2fc:  ee143a10   vmov  r3, s8\n'
                  ' 300:  e14b31b6   strh  r3, [fp, #-22]  @ 0xffffffea\n'
                  ' 304:  ee143a90   vmov  r3, s9\n'
                  ' 308:  e14b31b8   strh  r3, [fp, #-24]  @ 0xffffffe8\n'
                  ' 30c:  ee153a10   vmov  r3, s10\n'
                  ' 310:  e14b31ba   strh  r3, [fp, #-26]  @ 0xffffffe6\n'
                  ' 314:  ee153a90   vmov  r3, s11\n'
                  ' 318:  e14b31bc   strh  r3, [fp, #-28]  @ 0xffffffe4\n'
                  ' 31c:  ee163a10   vmov  r3, s12\n'
                  ' 320:  e14b31be   strh  r3, [fp, #-30]  @ 0xffffffe2\n'
                  ' 324:  ee163a90   vmov  r3, s13\n'
                  ' 328:  e14b32b0   strh  r3, [fp, #-32]  @ 0xffffffe0\n'
                  ' 32c:  ee173a10   vmov  r3, s14\n'
                  ' 330:  e14b32b2   strh  r3, [fp, #-34]  @ 0xffffffde\n'
                  ' 334:  ee173a90   vmov  r3, s15\n'
                  ' 338:  e14b32b4   strh  r3, [fp, #-36]  @ 0xffffffdc\n'
                  '  return 0.25;\n'
                  ' 33c:  e3a03b0d   mov  r3, #13312  @ 0x3400\n'
                  ' 340:  e3833000   orr  r3, r3, #0\n'
                  ' 344:  ee073a90   vmov  s15, r3\n'
                  '}\n'
                  ' 348:  eeb00a67   vmov.f32  s0, s15\n'
                  ' 34c:  e28bd000   add  sp, fp, #0\n'
                  ' 350:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 354:  e12fff1e   bx  lr\n'
                  '\n'
                  '00000358 <foo_12>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '// Return fundamental type smaller than a word.\n'
                  '//##############################################################################\n'
                  'unsigned short foo_12(void)\n'
                  '{\n'
                  ' 358:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 35c:  e28db000   add  fp, sp, #0\n'
                  '  return 0xabcd;\n'
                  ' 360:  e59f300c   ldr  r3, [pc, #12]  @ 374 <foo_12+0x1c>\n'
                  '}\n'
                  ' 364:  e1a00003   mov  r0, r3\n'
                  ' 368:  e28bd000   add  sp, fp, #0\n'
                  ' 36c:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 370:  e12fff1e   bx  lr\n'
                  ' 374:  0000abcd   .word  0x0000abcd\n'
                  '\n'
                  '00000378 <foo_13>:\n'
                  '\n'
                  '//#############################################################################\n'
                  '// Return fundamental type with double word size.\n'
                  '//#############################################################################\n'
                  'unsigned long long foo_13(void)\n'
                  '{\n'
                  ' 378:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 37c:  e28db000   add  fp, sp, #0\n'
                  '  return 0xffeeddccbbaa9988;;\n'
                  ' 380:  e28f3018   add  r3, pc, #24\n'
                  ' 384:  e1c320d0   ldrd  r2, [r3]\n'
                  '}\n'
                  ' 388:  e1a01003   mov  r1, r3\n'
                  ' 38c:  e1a00002   mov  r0, r2\n'
                  ' 390:  e28bd000   add  sp, fp, #0\n'
                  ' 394:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 398:  e12fff1e   bx  lr\n'
                  ' 39c:  e320f000   nop  {0}\n'
                  ' 3a0:  ffeeddcc   .word  0xffeeddcc\n'
                  ' 3a4:  bbaa9988   .word  0xbbaa9988\n'
                  '\n'
                  '000003a8 <foo_14>:\n'
                  '// Return aggregate lower than a word.\n'
                  '//#############################################################################\n'
                  'struct struct_14 { unsigned char a; unsigned char b; '
                  'unsigned char c; };\n'
                  '\n'
                  'struct struct_14 foo_14(void)\n'
                  '{\n'
                  ' 3a8:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 3ac:  e28db000   add  fp, sp, #0\n'
                  ' 3b0:  e24dd00c   sub  sp, sp, #12\n'
                  "  return (struct struct_14){.a='I', .b='J', .c='K'};\n"
                  ' 3b4:  e59f2074   ldr  r2, [pc, #116]  @ 430 <foo_14+0x88>\n'
                  ' 3b8:  e24b3008   sub  r3, fp, #8\n'
                  ' 3bc:  e5922000   ldr  r2, [r2]\n'
                  ' 3c0:  e1a02422   lsr  r2, r2, #8\n'
                  ' 3c4:  e1a01002   mov  r1, r2\n'
                  ' 3c8:  e5c31002   strb  r1, [r3, #2]\n'
                  ' 3cc:  e1a02422   lsr  r2, r2, #8\n'
                  ' 3d0:  e1a01002   mov  r1, r2\n'
                  ' 3d4:  e5c31001   strb  r1, [r3, #1]\n'
                  ' 3d8:  e1a02422   lsr  r2, r2, #8\n'
                  ' 3dc:  e5c32000   strb  r2, [r3]\n'
                  ' 3e0:  e3a03000   mov  r3, #0\n'
                  ' 3e4:  e55b2008   ldrb  r2, [fp, #-8]\n'
                  ' 3e8:  e6ef2072   uxtb  r2, r2\n'
                  ' 3ec:  e3c334ff   bic  r3, r3, #-16777216  @ 0xff000000\n'
                  ' 3f0:  e1a02c02   lsl  r2, r2, #24\n'
                  ' 3f4:  e1823003   orr  r3, r2, r3\n'
                  ' 3f8:  e55b2007   ldrb  r2, [fp, #-7]\n'
                  ' 3fc:  e6ef2072   uxtb  r2, r2\n'
                  ' 400:  e3c338ff   bic  r3, r3, #16711680  @ 0xff0000\n'
                  ' 404:  e1a02802   lsl  r2, r2, #16\n'
                  ' 408:  e1823003   orr  r3, r2, r3\n'
                  ' 40c:  e55b2006   ldrb  r2, [fp, #-6]\n'
                  ' 410:  e6ef2072   uxtb  r2, r2\n'
                  ' 414:  e3c33cff   bic  r3, r3, #65280  @ 0xff00\n'
                  ' 418:  e1a02402   lsl  r2, r2, #8\n'
                  ' 41c:  e1823003   orr  r3, r2, r3\n'
                  '}\n'
                  ' 420:  e1a00003   mov  r0, r3\n'
                  ' 424:  e28bd000   add  sp, fp, #0\n'
                  ' 428:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 42c:  e12fff1e   bx  lr\n'
                  ' 430:  000008f8   .word  0x000008f8\n'
                  '\n'
                  '00000434 <foo_15>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  '__fp16 foo_15(void)\n'
                  '{\n'
                  ' 434:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 438:  e28db000   add  fp, sp, #0\n'
                  '  return 3.875;\n'
                  ' 43c:  e3a03c43   mov  r3, #17152  @ 0x4300\n'
                  ' 440:  e38330c0   orr  r3, r3, #192  @ 0xc0\n'
                  ' 444:  ee073a90   vmov  s15, r3\n'
                  '}\n'
                  ' 448:  eeb00a67   vmov.f32  s0, s15\n'
                  ' 44c:  e28bd000   add  sp, fp, #0\n'
                  ' 450:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 454:  e12fff1e   bx  lr\n'
                  '\n'
                  '00000458 <foo_16>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'float foo_16(void)\n'
                  '{\n'
                  ' 458:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 45c:  e28db000   add  fp, sp, #0\n'
                  '  return 0.75;\n'
                  ' 460:  e3a035fd   mov  r3, #1061158912  @ 0x3f400000\n'
                  ' 464:  ee073a90   vmov  s15, r3\n'
                  '}\n'
                  ' 468:  eeb00a67   vmov.f32  s0, s15\n'
                  ' 46c:  e28bd000   add  sp, fp, #0\n'
                  ' 470:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 474:  e12fff1e   bx  lr\n'
                  '\n'
                  '00000478 <foo_17>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'double foo_17(void)\n'
                  '{\n'
                  ' 478:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 47c:  e28db000   add  fp, sp, #0\n'
                  '  return 0.75;\n'
                  ' 480:  e3a03000   mov  r3, #0\n'
                  ' 484:  e59f2010   ldr  r2, [pc, #16]  @ 49c <foo_17+0x24>\n'
                  ' 488:  ec423b17   vmov  d7, r3, r2\n'
                  '}\n'
                  ' 48c:  eeb00b47   vmov.f64  d0, d7\n'
                  ' 490:  e28bd000   add  sp, fp, #0\n'
                  ' 494:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 498:  e12fff1e   bx  lr\n'
                  ' 49c:  3fe80000   .word  0x3fe80000\n'
                  '\n'
                  '000004a0 <foo_18>:\n'
                  'struct struct_18_wrap_l1 { struct struct_18_b b; };\n'
                  '\n'
                  'struct struct_18_wrap_l2 { struct struct_18_a a; struct '
                  'struct_18_wrap_l1 wrap; };\n'
                  '\n'
                  'struct struct_18_wrap_l2 foo_18(void)\n'
                  '{\n'
                  ' 4a0:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 4a4:  e28db000   add  fp, sp, #0\n'
                  ' 4a8:  e24dd034   sub  sp, sp, #52  @ 0x34\n'
                  '    return (struct struct_18_wrap_l2){\n'
                  ' 4ac:  e59f3044   ldr  r3, [pc, #68]  @ 4f8 <foo_18+0x58>\n'
                  ' 4b0:  e24bc014   sub  ip, fp, #20\n'
                  ' 4b4:  e893000f   ldm  r3, {r0, r1, r2, r3}\n'
                  ' 4b8:  e88c000f   stm  ip, {r0, r1, r2, r3}\n'
                  ' 4bc:  e51b0014   ldr  r0, [fp, #-20]  @ 0xffffffec\n'
                  ' 4c0:  e51b1010   ldr  r1, [fp, #-16]\n'
                  ' 4c4:  e51b200c   ldr  r2, [fp, #-12]\n'
                  ' 4c8:  e51b3008   ldr  r3, [fp, #-8]\n'
                  ' 4cc:  ee060a10   vmov  s12, r0\n'
                  ' 4d0:  ee061a90   vmov  s13, r1\n'
                  ' 4d4:  ee072a10   vmov  s14, r2\n'
                  ' 4d8:  ee073a90   vmov  s15, r3\n'
                  '        .a = {.a=0.5, .b=0.75}, .wrap = {.b = {.c=0.875, '
                  '.d=0.984375}}};\n'
                  '}\n'
                  ' 4dc:  eeb00a46   vmov.f32  s0, s12\n'
                  ' 4e0:  eef00a66   vmov.f32  s1, s13\n'
                  ' 4e4:  eeb01a47   vmov.f32  s2, s14\n'
                  ' 4e8:  eef01a67   vmov.f32  s3, s15\n'
                  ' 4ec:  e28bd000   add  sp, fp, #0\n'
                  ' 4f0:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 4f4:  e12fff1e   bx  lr\n'
                  ' 4f8:  000008fc   .word  0x000008fc\n'
                  '\n'
                  '000004fc <foo_19>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'void foo_19(void)\n'
                  '{\n'
                  ' 4fc:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 500:  e28db000   add  fp, sp, #0\n'
                  '}\n'
                  ' 504:  e320f000   nop  {0}\n'
                  ' 508:  e28bd000   add  sp, fp, #0\n'
                  ' 50c:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 510:  e12fff1e   bx  lr\n'
                  '\n'
                  '00000514 <foo_20>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '// Argument with size lower than a word.\n'
                  '//##############################################################################\n'
                  'unsigned int foo_20(unsigned short a)\n'
                  '{\n'
                  ' 514:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 518:  e28db000   add  fp, sp, #0\n'
                  ' 51c:  e24dd00c   sub  sp, sp, #12\n'
                  ' 520:  e1a03000   mov  r3, r0\n'
                  ' 524:  e14b30b6   strh  r3, [fp, #-6]\n'
                  '    return 1;\n'
                  ' 528:  e3a03001   mov  r3, #1\n'
                  '}\n'
                  ' 52c:  e1a00003   mov  r0, r3\n'
                  ' 530:  e28bd000   add  sp, fp, #0\n'
                  ' 534:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 538:  e12fff1e   bx  lr\n'
                  '\n'
                  '0000053c <foo_21>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'unsigned char * foo_21(unsigned char * a)\n'
                  '{\n'
                  ' 53c:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 540:  e28db000   add  fp, sp, #0\n'
                  ' 544:  e24dd00c   sub  sp, sp, #12\n'
                  ' 548:  e50b0008   str  r0, [fp, #-8]\n'
                  '    return (unsigned char *) 0xBADEBABE;\n'
                  ' 54c:  e59f300c   ldr  r3, [pc, #12]  @ 560 <foo_21+0x24>\n'
                  '}\n'
                  ' 550:  e1a00003   mov  r0, r3\n'
                  ' 554:  e28bd000   add  sp, fp, #0\n'
                  ' 558:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 55c:  e12fff1e   bx  lr\n'
                  ' 560:  badebabe   .word  0xbadebabe\n'
                  '\n'
                  '00000564 <foo_22>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '//\n'
                  '//##############################################################################\n'
                  'unsigned char ** foo_22(unsigned char ** a)\n'
                  '{\n'
                  ' 564:  e52db004   push  {fp}    @ (str fp, [sp, #-4]!)\n'
                  ' 568:  e28db000   add  fp, sp, #0\n'
                  ' 56c:  e24dd00c   sub  sp, sp, #12\n'
                  ' 570:  e50b0008   str  r0, [fp, #-8]\n'
                  '    return (unsigned char **) 0xBABEBADE;\n'
                  ' 574:  e59f300c   ldr  r3, [pc, #12]  @ 588 <foo_22+0x24>\n'
                  '}\n'
                  ' 578:  e1a00003   mov  r0, r3\n'
                  ' 57c:  e28bd000   add  sp, fp, #0\n'
                  ' 580:  e49db004   pop  {fp}    @ (ldr fp, [sp], #4)\n'
                  ' 584:  e12fff1e   bx  lr\n'
                  ' 588:  babebade   .word  0xbabebade\n'
                  '\n'
                  '0000058c <__entry__>:\n'
                  '\n'
                  '//##############################################################################\n'
                  '// Entry Point\n'
                  '//##############################################################################\n'
                  'void __entry__(void)\n'
                  '{\n'
                  ' 58c:  e92d4800   push  {fp, lr}\n'
                  ' 590:  e28db004   add  fp, sp, #4\n'
                  ' 594:  e24dd068   sub  sp, sp, #104  @ 0x68\n'
                  '  cc_call_test_wrapper();\n'
                  ' 598:  ebfffea6   bl  38 <cc_call_test_wrapper>\n'
                  '\n'
                  '  foo_01(0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10);\n'
                  ' 59c:  e59f3320   ldr  r3, [pc, #800]  @ 8c4 '
                  '<__entry__+0x338>\n'
                  ' 5a0:  e59f2320   ldr  r2, [pc, #800]  @ 8c8 '
                  '<__entry__+0x33c>\n'
                  ' 5a4:  e59f1320   ldr  r1, [pc, #800]  @ 8cc '
                  '<__entry__+0x340>\n'
                  ' 5a8:  e59f0320   ldr  r0, [pc, #800]  @ 8d0 '
                  '<__entry__+0x344>\n'
                  ' 5ac:  ebfffead   bl  68 <foo_01>\n'
                  '\n'
                  '  foo_02(0x01020304, 0x05060708090A0B0C);\n'
                  ' 5b0:  e28f3fa6   add  r3, pc, #664  @ 0x298\n'
                  ' 5b4:  e1c320d0   ldrd  r2, [r3]\n'
                  ' 5b8:  e59f0310   ldr  r0, [pc, #784]  @ 8d0 '
                  '<__entry__+0x344>\n'
                  ' 5bc:  ebfffeb6   bl  9c <foo_02>\n'
                  '\n'
                  '  foo_03(0x0807060504030201, 0x100F0E0D0C0B0A09,\n'
                  ' 5c0:  e59f330c   ldr  r3, [pc, #780]  @ 8d4 '
                  '<__entry__+0x348>\n'
                  ' 5c4:  e58d3018   str  r3, [sp, #24]\n'
                  ' 5c8:  e3a0304a   mov  r3, #74  @ 0x4a\n'
                  ' 5cc:  e58d3014   str  r3, [sp, #20]\n'
                  ' 5d0:  e3a0304b   mov  r3, #75  @ 0x4b\n'
                  ' 5d4:  e58d3010   str  r3, [sp, #16]\n'
                  ' 5d8:  e28f3f9e   add  r3, pc, #632  @ 0x278\n'
                  ' 5dc:  e1c320d0   ldrd  r2, [r3]\n'
                  ' 5e0:  e1cd20f8   strd  r2, [sp, #8]\n'
                  ' 5e4:  e3a03041   mov  r3, #65  @ 0x41\n'
                  ' 5e8:  e58d3000   str  r3, [sp]\n'
                  ' 5ec:  e28f3f9b   add  r3, pc, #620  @ 0x26c\n'
                  ' 5f0:  e1c320d0   ldrd  r2, [r3]\n'
                  ' 5f4:  e28f1f9b   add  r1, pc, #620  @ 0x26c\n'
                  ' 5f8:  e1c100d0   ldrd  r0, [r1]\n'
                  ' 5fc:  ebfffeb5   bl  d8 <foo_03>\n'
                  "         'A', 0x1817161514131211, 'K', 'J', 0x1c1b1a19);\n"
                  '\n'
                  '  foo_04(1, 3, (struct struct_04){.a=0x0f101112, '
                  '.b=0x13141516, .c=0x17181920});\n'
                  ' 600:  e59f22d0   ldr  r2, [pc, #720]  @ 8d8 '
                  '<__entry__+0x34c>\n'
                  ' 604:  e24b3010   sub  r3, fp, #16\n'
                  ' 608:  e8920007   ldm  r2, {r0, r1, r2}\n'
                  ' 60c:  e8830007   stm  r3, {r0, r1, r2}\n'
                  ' 610:  e51b3008   ldr  r3, [fp, #-8]\n'
                  ' 614:  e58d3000   str  r3, [sp]\n'
                  ' 618:  e24b3010   sub  r3, fp, #16\n'
                  ' 61c:  e893000c   ldm  r3, {r2, r3}\n'
                  ' 620:  e3a01003   mov  r1, #3\n'
                  ' 624:  e3a00001   mov  r0, #1\n'
                  ' 628:  ebfffeb8   bl  110 <foo_04>\n'
                  '\n'
                  '  foo_05((struct struct_05)\n'
                  "        {.a='a', .b=0x0f10, .c=0x11121314, .d='b', "
                  '.e=0x15161718191a1b1c});\n'
                  ' 62c:  e59f32a8   ldr  r3, [pc, #680]  @ 8dc '
                  '<__entry__+0x350>\n'
                  ' 630:  e24bc02c   sub  ip, fp, #44  @ 0x2c\n'
                  ' 634:  e1a0e003   mov  lr, r3\n'
                  ' 638:  e8be000f   ldm  lr!, {r0, r1, r2, r3}\n'
                  ' 63c:  e8ac000f   stmia  ip!, {r0, r1, r2, r3}\n'
                  ' 640:  e89e0003   ldm  lr, {r0, r1}\n'
                  ' 644:  e88c0003   stm  ip, {r0, r1}\n'
                  '  foo_05((struct struct_05)\n'
                  ' 648:  e1a0200d   mov  r2, sp\n'
                  ' 64c:  e24b301c   sub  r3, fp, #28\n'
                  ' 650:  e8930003   ldm  r3, {r0, r1}\n'
                  ' 654:  e8820003   stm  r2, {r0, r1}\n'
                  ' 658:  e24b302c   sub  r3, fp, #44  @ 0x2c\n'
                  ' 65c:  e893000f   ldm  r3, {r0, r1, r2, r3}\n'
                  ' 660:  ebfffeb8   bl  148 <foo_05>\n'
                  '\n'
                  "  foo_06((struct struct_06){.a='a'});\n"
                  ' 664:  e3a03061   mov  r3, #97  @ 0x61\n'
                  ' 668:  e1a00003   mov  r0, r3\n'
                  ' 66c:  e1a00c00   lsl  r0, r0, #24\n'
                  ' 670:  ebfffebf   bl  174 <foo_06>\n'
                  ' 674:  e1a00c40   asr  r0, r0, #24\n'
                  '\n'
                  '  foo_07(4, 0.5, 8, 0.75, 0.875);\n'
                  ' 678:  eddf0a8e   vldr  s1, [pc, #568]  @ 8b8 '
                  '<__entry__+0x32c>\n'
                  ' 67c:  ed9f1b7b   vldr  d1, [pc, #492]  @ 870 '
                  '<__entry__+0x2e4>\n'
                  ' 680:  e3a01008   mov  r1, #8\n'
                  ' 684:  ed9f0a8c   vldr  s0, [pc, #560]  @ 8bc '
                  '<__entry__+0x330>\n'
                  ' 688:  e3a00004   mov  r0, #4\n'
                  ' 68c:  ebfffec2   bl  19c <foo_07>\n'
                  '\n'
                  '  foo_08(4, 0.5, 8, 0.75, 0.875, 0.984375);\n'
                  ' 690:  ed9f2a8a   vldr  s4, [pc, #552]  @ 8c0 '
                  '<__entry__+0x334>\n'
                  ' 694:  e3a03c3b   mov  r3, #15104  @ 0x3b00\n'
                  ' 698:  e3833000   orr  r3, r3, #0\n'
                  ' 69c:  ee003a90   vmov  s1, r3\n'
                  ' 6a0:  ed9f1b72   vldr  d1, [pc, #456]  @ 870 '
                  '<__entry__+0x2e4>\n'
                  ' 6a4:  e3a01008   mov  r1, #8\n'
                  ' 6a8:  ed9f0a83   vldr  s0, [pc, #524]  @ 8bc '
                  '<__entry__+0x330>\n'
                  ' 6ac:  e3a00004   mov  r0, #4\n'
                  ' 6b0:  ebfffec8   bl  1d8 <foo_08>\n'
                  '\n'
                  '  foo_09((struct struct_09_4){.a={.a=0.5, .b=0.75},\n'
                  ' 6b4:  e59f3224   ldr  r3, [pc, #548]  @ 8e0 '
                  '<__entry__+0x354>\n'
                  ' 6b8:  e24bc04c   sub  ip, fp, #76  @ 0x4c\n'
                  ' 6bc:  e1a0e003   mov  lr, r3\n'
                  ' 6c0:  e8be000f   ldm  lr!, {r0, r1, r2, r3}\n'
                  ' 6c4:  e8ac000f   stmia  ip!, {r0, r1, r2, r3}\n'
                  ' 6c8:  e89e000f   ldm  lr, {r0, r1, r2, r3}\n'
                  ' 6cc:  e88c000f   stm  ip, {r0, r1, r2, r3}\n'
                  ' 6d0:  ed1b4b13   vldr  d4, [fp, #-76]  @ 0xffffffb4\n'
                  ' 6d4:  ed1b5b11   vldr  d5, [fp, #-68]  @ 0xffffffbc\n'
                  ' 6d8:  ed1b6b0f   vldr  d6, [fp, #-60]  @ 0xffffffc4\n'
                  ' 6dc:  ed1b7b0d   vldr  d7, [fp, #-52]  @ 0xffffffcc\n'
                  ' 6e0:  eeb00b44   vmov.f64  d0, d4\n'
                  ' 6e4:  eeb01b45   vmov.f64  d1, d5\n'
                  ' 6e8:  eeb02b46   vmov.f64  d2, d6\n'
                  ' 6ec:  eeb03b47   vmov.f64  d3, d7\n'
                  ' 6f0:  ebfffec9   bl  21c <foo_09>\n'
                  '                              .wrap={.b={.c=0.875, '
                  '.d=0.984375}}});\n'
                  '\n'
                  '  foo_10(0.25, 0.375, 0.4375, 0.46875, 0.484375, 0.4921875, '
                  '0.49609375,\n'
                  ' 6f4:  e3a03000   mov  r3, #0\n'
                  ' 6f8:  e59f21e4   ldr  r2, [pc, #484]  @ 8e4 '
                  '<__entry__+0x358>\n'
                  ' 6fc:  e1cd20f8   strd  r2, [sp, #8]\n'
                  ' 700:  e3a03000   mov  r3, #0\n'
                  ' 704:  e59f21dc   ldr  r2, [pc, #476]  @ 8e8 '
                  '<__entry__+0x35c>\n'
                  ' 708:  e1cd20f0   strd  r2, [sp]\n'
                  ' 70c:  ed9f7b59   vldr  d7, [pc, #356]  @ 878 '
                  '<__entry__+0x2ec>\n'
                  ' 710:  ed9f6b5a   vldr  d6, [pc, #360]  @ 880 '
                  '<__entry__+0x2f4>\n'
                  ' 714:  ed9f5b5b   vldr  d5, [pc, #364]  @ 888 '
                  '<__entry__+0x2fc>\n'
                  ' 718:  ed9f4b5c   vldr  d4, [pc, #368]  @ 890 '
                  '<__entry__+0x304>\n'
                  ' 71c:  ed9f3b5d   vldr  d3, [pc, #372]  @ 898 '
                  '<__entry__+0x30c>\n'
                  ' 720:  ed9f2b5e   vldr  d2, [pc, #376]  @ 8a0 '
                  '<__entry__+0x314>\n'
                  ' 724:  ed9f1b5f   vldr  d1, [pc, #380]  @ 8a8 '
                  '<__entry__+0x31c>\n'
                  ' 728:  ed9f0b60   vldr  d0, [pc, #384]  @ 8b0 '
                  '<__entry__+0x324>\n'
                  ' 72c:  ebfffecc   bl  264 <foo_10>\n'
                  '         0.498046875, 0.4990234375, 0.49951171875);\n'
                  '\n'
                  '  foo_11(2, 3, 3.5, 3.75, 3.875, 8192, 12288, 14336, 15360, '
                  '15872, 16128, 512,\n'
                  ' 730:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 734:  e38330f0   orr  r3, r3, #240  @ 0xf0\n'
                  ' 738:  e1cd30b4   strh  r3, [sp, #4]\n'
                  ' 73c:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 740:  e38330e0   orr  r3, r3, #224  @ 0xe0\n'
                  ' 744:  e1cd30b0   strh  r3, [sp]\n'
                  ' 748:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 74c:  e38330c0   orr  r3, r3, #192  @ 0xc0\n'
                  ' 750:  ee073a90   vmov  s15, r3\n'
                  ' 754:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 758:  e3833080   orr  r3, r3, #128  @ 0x80\n'
                  ' 75c:  ee073a10   vmov  s14, r3\n'
                  ' 760:  e3a03c63   mov  r3, #25344  @ 0x6300\n'
                  ' 764:  e3833000   orr  r3, r3, #0\n'
                  ' 768:  ee063a90   vmov  s13, r3\n'
                  ' 76c:  e3a03c62   mov  r3, #25088  @ 0x6200\n'
                  ' 770:  e3833000   orr  r3, r3, #0\n'
                  ' 774:  ee063a10   vmov  s12, r3\n'
                  ' 778:  e3a03a06   mov  r3, #24576  @ 0x6000\n'
                  ' 77c:  e3833000   orr  r3, r3, #0\n'
                  ' 780:  ee053a90   vmov  s11, r3\n'
                  ' 784:  e3a03c73   mov  r3, #29440  @ 0x7300\n'
                  ' 788:  e38330e0   orr  r3, r3, #224  @ 0xe0\n'
                  ' 78c:  ee053a10   vmov  s10, r3\n'
                  ' 790:  e3a03c73   mov  r3, #29440  @ 0x7300\n'
                  ' 794:  e38330c0   orr  r3, r3, #192  @ 0xc0\n'
                  ' 798:  ee043a90   vmov  s9, r3\n'
                  ' 79c:  e3a03c73   mov  r3, #29440  @ 0x7300\n'
                  ' 7a0:  e3833080   orr  r3, r3, #128  @ 0x80\n'
                  ' 7a4:  ee043a10   vmov  s8, r3\n'
                  ' 7a8:  e3a03c73   mov  r3, #29440  @ 0x7300\n'
                  ' 7ac:  e3833000   orr  r3, r3, #0\n'
                  ' 7b0:  ee033a90   vmov  s7, r3\n'
                  ' 7b4:  e3a03c72   mov  r3, #29184  @ 0x7200\n'
                  ' 7b8:  e3833000   orr  r3, r3, #0\n'
                  ' 7bc:  ee033a10   vmov  s6, r3\n'
                  ' 7c0:  e3a03a07   mov  r3, #28672  @ 0x7000\n'
                  ' 7c4:  e3833000   orr  r3, r3, #0\n'
                  ' 7c8:  ee023a90   vmov  s5, r3\n'
                  ' 7cc:  e3a03c43   mov  r3, #17152  @ 0x4300\n'
                  ' 7d0:  e38330c0   orr  r3, r3, #192  @ 0xc0\n'
                  ' 7d4:  ee023a10   vmov  s4, r3\n'
                  ' 7d8:  e3a03c43   mov  r3, #17152  @ 0x4300\n'
                  ' 7dc:  e3833080   orr  r3, r3, #128  @ 0x80\n'
                  ' 7e0:  ee013a90   vmov  s3, r3\n'
                  ' 7e4:  e3a03c43   mov  r3, #17152  @ 0x4300\n'
                  ' 7e8:  e3833000   orr  r3, r3, #0\n'
                  ' 7ec:  ee013a10   vmov  s2, r3\n'
                  ' 7f0:  e3a03c42   mov  r3, #16896  @ 0x4200\n'
                  ' 7f4:  e3833000   orr  r3, r3, #0\n'
                  ' 7f8:  ee003a90   vmov  s1, r3\n'
                  ' 7fc:  e3a03901   mov  r3, #16384  @ 0x4000\n'
                  ' 800:  e3833000   orr  r3, r3, #0\n'
                  ' 804:  ee003a10   vmov  s0, r3\n'
                  ' 808:  ebfffea8   bl  2b0 <foo_11>\n'
                  '         768, 896, 960, 992, 1008, 1016);\n'
                  '\n'
                  '  foo_12();\n'
                  ' 80c:  ebfffed1   bl  358 <foo_12>\n'
                  '  foo_13();\n'
                  ' 810:  ebfffed8   bl  378 <foo_13>\n'
                  '  foo_14();\n'
                  ' 814:  ebfffee3   bl  3a8 <foo_14>\n'
                  '  foo_15();\n'
                  ' 818:  ebffff05   bl  434 <foo_15>\n'
                  '  foo_16();\n'
                  ' 81c:  ebffff0d   bl  458 <foo_16>\n'
                  '  foo_17();\n'
                  ' 820:  ebffff14   bl  478 <foo_17>\n'
                  '  foo_19();\n'
                  ' 824:  ebffff34   bl  4fc <foo_19>\n'
                  '  foo_20(0x1234);\n'
                  ' 828:  e59f00bc   ldr  r0, [pc, #188]  @ 8ec '
                  '<__entry__+0x360>\n'
                  ' 82c:  ebffff38   bl  514 <foo_20>\n'
                  '  foo_21((unsigned char *) 0xC0DEC0FE);\n'
                  ' 830:  e59f00b8   ldr  r0, [pc, #184]  @ 8f0 '
                  '<__entry__+0x364>\n'
                  ' 834:  ebffff40   bl  53c <foo_21>\n'
                  '  foo_22((unsigned char **) 0xC0FEC0DE);\n'
                  ' 838:  e59f00b4   ldr  r0, [pc, #180]  @ 8f4 '
                  '<__entry__+0x368>\n'
                  ' 83c:  ebffff48   bl  564 <foo_22>\n'
                  '\n'
                  '#ifdef WITH_FP_HARD\n'
                  '  foo_18();\n'
                  ' 840:  ebffff16   bl  4a0 <foo_18>\n'
                  '#endif\n'
                  '}\n'
                  ' 844:  e320f000   nop  {0}\n'
                  ' 848:  e24bd004   sub  sp, fp, #4\n'
                  ' 84c:  e8bd8800   pop  {fp, pc}\n'
                  ' 850:  05060708   .word  0x05060708\n'
                  ' 854:  090a0b0c   .word  0x090a0b0c\n'
                  ' 858:  18171615   .word  0x18171615\n'
                  ' 85c:  14131211   .word  0x14131211\n'
                  ' 860:  100f0e0d   .word  0x100f0e0d\n'
                  ' 864:  0c0b0a09   .word  0x0c0b0a09\n'
                  ' 868:  08070605   .word  0x08070605\n'
                  ' 86c:  04030201   .word  0x04030201\n'
                  ' 870:  3fe80000   .word  0x3fe80000\n'
                  ' 874:  00000000   .word  0x00000000\n'
                  ' 878:  3fdfe000   .word  0x3fdfe000\n'
                  ' 87c:  00000000   .word  0x00000000\n'
                  ' 880:  3fdfc000   .word  0x3fdfc000\n'
                  ' 884:  00000000   .word  0x00000000\n'
                  ' 888:  3fdf8000   .word  0x3fdf8000\n'
                  ' 88c:  00000000   .word  0x00000000\n'
                  ' 890:  3fdf0000   .word  0x3fdf0000\n'
                  ' 894:  00000000   .word  0x00000000\n'
                  ' 898:  3fde0000   .word  0x3fde0000\n'
                  ' 89c:  00000000   .word  0x00000000\n'
                  ' 8a0:  3fdc0000   .word  0x3fdc0000\n'
                  ' 8a4:  00000000   .word  0x00000000\n'
                  ' 8a8:  3fd80000   .word  0x3fd80000\n'
                  ' 8ac:  00000000   .word  0x00000000\n'
                  ' 8b0:  3fd00000   .word  0x3fd00000\n'
                  ' 8b4:  00000000   .word  0x00000000\n'
                  ' 8b8:  3f600000   .word  0x3f600000\n'
                  ' 8bc:  3f000000   .word  0x3f000000\n'
                  ' 8c0:  3f7c0000   .word  0x3f7c0000\n'
                  ' 8c4:  0d0e0f10   .word  0x0d0e0f10\n'
                  ' 8c8:  090a0b0c   .word  0x090a0b0c\n'
                  ' 8cc:  05060708   .word  0x05060708\n'
                  ' 8d0:  01020304   .word  0x01020304\n'
                  ' 8d4:  1c1b1a19   .word  0x1c1b1a19\n'
                  ' 8d8:  0000090c   .word  0x0000090c\n'
                  ' 8dc:  00000918   .word  0x00000918\n'
                  ' 8e0:  00000930   .word  0x00000930\n'
                  ' 8e4:  3fdff800   .word  0x3fdff800\n'
                  ' 8e8:  3fdff000   .word  0x3fdff000\n'
                  ' 8ec:  00001234   .word  0x00001234\n'
                  ' 8f0:  c0dec0fe   .word  0xc0dec0fe\n'
                  ' 8f4:  c0fec0de   .word  0xc0fec0de\n',
   'mapped_blobs': [{'loading_address': 0,
                     'blob': b'\xea\x00\x00\x06\xea\xff\xff\xfe\xea\xff\xff\xfe\xea\xff\xff\xfe\xea\xff\xff\xfe\xea\xff\xff\xfe\xea\xff\xff\xfe\xea\xff\xff\xfe\xe3\xc0\x00\x80\xe1\x29\xf0\x00\xe3\xa0\xd9\x01\xeb\x00\x01\x56\xe1\xa0\x00\x00\xea\xff\xff\xfe\xe9\x2d\x5f\xf0\xe5\x9f\x40\x1c\xe5\x2d\x40\x04\xe1\xa0\x00\x00\xe1\xa0\x00\x00\xe1\xa0\x00\x00\xe1\xa0\x00\x00\xe1\xa0\x00\x00\xe4\x9d\x00\x04\xe8\xbd\x9f\xf0\xbe\xef\xba\xbe\x00\x00\x00\x00\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x14\xe5\x0b\x00\x08\xe5\x0b\x10\x0c\xe5\x0b\x20\x10\xe5\x0b\x30\x14\xe5\x9f\x30\x0c\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x01\x02\x03\x04\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x14\xe5\x0b\x00\x08\xe1\x4b\x21\xf4\xe2\x8f\x30\x18\xe1\xc3\x20\xd0\xe1\xa0\x10\x03\xe1\xa0\x00\x02\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xe3\x20\xf0\x00\x01\x02\x03\x04\x05\x06\x07\x08\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x14\xe1\x4b\x00\xfc\xe1\x4b\x21\xf4\xe2\x8f\x30\x14\xe1\xc3\x20\xd0\xe1\xa0\x10\x03\xe1\xa0\x00\x02\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x01\x02\x03\x04\x05\x06\x07\x08\xe2\x4d\xd0\x08\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x0c\xe5\x0b\x00\x08\xe5\x0b\x10\x0c\xe2\x8b\x10\x04\xe8\x81\x00\x0c\xe3\xa0\x30\x01\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe2\x8d\xd0\x08\xe1\x2f\xff\x1e\xe2\x4d\xd0\x10\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x8b\xc0\x04\xe8\x8c\x00\x0f\xe3\xa0\x30\x01\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe2\x8d\xd0\x10\xe1\x2f\xff\x1e\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x0c\xe5\x0b\x00\x08\xe3\xa0\x30\x41\xe1\xa0\x00\x03\xe1\xa0\x0c\x00\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x1c\xe5\x0b\x00\x08\xed\x0b\x0a\x03\xe5\x0b\x10\x10\xed\x0b\x1b\x07\xed\x4b\x0a\x05\xe5\x9f\x30\x10\xee\x07\x3a\x90\xee\xb0\x0a\x67\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x3f\x70\x00\x00\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x24\xe5\x0b\x00\x08\xed\x0b\x0a\x03\xe5\x0b\x10\x10\xed\x0b\x1b\x07\xee\x10\x3a\x90\xe1\x4b\x31\xb2\xed\x0b\x2a\x08\xe5\x9f\x30\x10\xee\x07\x3a\x90\xee\xb0\x0a\x67\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x3f\x70\x00\x00\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x24\xee\xb0\x4b\x40\xee\xb0\x5b\x41\xee\xb0\x6b\x42\xee\xb0\x7b\x43\xed\x0b\x4b\x09\xed\x0b\x5b\x07\xed\x0b\x6b\x05\xed\x0b\x7b\x03\xe5\x9f\x30\x10\xee\x07\x3a\x90\xee\xb0\x0a\x67\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x3f\x70\x00\x00\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x44\xed\x0b\x0b\x03\xed\x0b\x1b\x05\xed\x0b\x2b\x07\xed\x0b\x3b\x09\xed\x0b\x4b\x0b\xed\x0b\x5b\x0d\xed\x0b\x6b\x0f\xed\x0b\x7b\x11\xe3\xa0\x30\x00\xe5\x9f\x20\x10\xec\x42\x3b\x17\xee\xb0\x0b\x47\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x3f\xd0\x00\x00\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x24\xee\x10\x3a\x10\xe1\x4b\x30\xb6\xee\x10\x3a\x90\xe1\x4b\x30\xb8\xee\x11\x3a\x10\xe1\x4b\x30\xba\xee\x11\x3a\x90\xe1\x4b\x30\xbc\xee\x12\x3a\x10\xe1\x4b\x30\xbe\xee\x12\x3a\x90\xe1\x4b\x31\xb0\xee\x13\x3a\x10\xe1\x4b\x31\xb2\xee\x13\x3a\x90\xe1\x4b\x31\xb4\xee\x14\x3a\x10\xe1\x4b\x31\xb6\xee\x14\x3a\x90\xe1\x4b\x31\xb8\xee\x15\x3a\x10\xe1\x4b\x31\xba\xee\x15\x3a\x90\xe1\x4b\x31\xbc\xee\x16\x3a\x10\xe1\x4b\x31\xbe\xee\x16\x3a\x90\xe1\x4b\x32\xb0\xee\x17\x3a\x10\xe1\x4b\x32\xb2\xee\x17\x3a\x90\xe1\x4b\x32\xb4\xe3\xa0\x3b\x0d\xe3\x83\x30\x00\xee\x07\x3a\x90\xee\xb0\x0a\x67\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe5\x9f\x30\x0c\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x00\x00\xab\xcd\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x8f\x30\x18\xe1\xc3\x20\xd0\xe1\xa0\x10\x03\xe1\xa0\x00\x02\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xe3\x20\xf0\x00\xff\xee\xdd\xcc\xbb\xaa\x99\x88\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x0c\xe5\x9f\x20\x74\xe2\x4b\x30\x08\xe5\x92\x20\x00\xe1\xa0\x24\x22\xe1\xa0\x10\x02\xe5\xc3\x10\x02\xe1\xa0\x24\x22\xe1\xa0\x10\x02\xe5\xc3\x10\x01\xe1\xa0\x24\x22\xe5\xc3\x20\x00\xe3\xa0\x30\x00\xe5\x5b\x20\x08\xe6\xef\x20\x72\xe3\xc3\x34\xff\xe1\xa0\x2c\x02\xe1\x82\x30\x03\xe5\x5b\x20\x07\xe6\xef\x20\x72\xe3\xc3\x38\xff\xe1\xa0\x28\x02\xe1\x82\x30\x03\xe5\x5b\x20\x06\xe6\xef\x20\x72\xe3\xc3\x3c\xff\xe1\xa0\x24\x02\xe1\x82\x30\x03\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x00\x00\x08\xf8\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe3\xa0\x3c\x43\xe3\x83\x30\xc0\xee\x07\x3a\x90\xee\xb0\x0a\x67\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe3\xa0\x35\xfd\xee\x07\x3a\x90\xee\xb0\x0a\x67\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe3\xa0\x30\x00\xe5\x9f\x20\x10\xec\x42\x3b\x17\xee\xb0\x0b\x47\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x3f\xe8\x00\x00\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x34\xe5\x9f\x30\x44\xe2\x4b\xc0\x14\xe8\x93\x00\x0f\xe8\x8c\x00\x0f\xe5\x1b\x00\x14\xe5\x1b\x10\x10\xe5\x1b\x20\x0c\xe5\x1b\x30\x08\xee\x06\x0a\x10\xee\x06\x1a\x90\xee\x07\x2a\x10\xee\x07\x3a\x90\xee\xb0\x0a\x46\xee\xf0\x0a\x66\xee\xb0\x1a\x47\xee\xf0\x1a\x67\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\x00\x00\x08\xfc\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe3\x20\xf0\x00\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x0c\xe1\xa0\x30\x00\xe1\x4b\x30\xb6\xe3\xa0\x30\x01\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x0c\xe5\x0b\x00\x08\xe5\x9f\x30\x0c\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xba\xde\xba\xbe\xe5\x2d\xb0\x04\xe2\x8d\xb0\x00\xe2\x4d\xd0\x0c\xe5\x0b\x00\x08\xe5\x9f\x30\x0c\xe1\xa0\x00\x03\xe2\x8b\xd0\x00\xe4\x9d\xb0\x04\xe1\x2f\xff\x1e\xba\xbe\xba\xde\xe9\x2d\x48\x00\xe2\x8d\xb0\x04\xe2\x4d\xd0\x68\xeb\xff\xfe\xa6\xe5\x9f\x33\x20\xe5\x9f\x23\x20\xe5\x9f\x13\x20\xe5\x9f\x03\x20\xeb\xff\xfe\xad\xe2\x8f\x3f\xa6\xe1\xc3\x20\xd0\xe5\x9f\x03\x10\xeb\xff\xfe\xb6\xe5\x9f\x33\x0c\xe5\x8d\x30\x18\xe3\xa0\x30\x4a\xe5\x8d\x30\x14\xe3\xa0\x30\x4b\xe5\x8d\x30\x10\xe2\x8f\x3f\x9e\xe1\xc3\x20\xd0\xe1\xcd\x20\xf8\xe3\xa0\x30\x41\xe5\x8d\x30\x00\xe2\x8f\x3f\x9b\xe1\xc3\x20\xd0\xe2\x8f\x1f\x9b\xe1\xc1\x00\xd0\xeb\xff\xfe\xb5\xe5\x9f\x22\xd0\xe2\x4b\x30\x10\xe8\x92\x00\x07\xe8\x83\x00\x07\xe5\x1b\x30\x08\xe5\x8d\x30\x00\xe2\x4b\x30\x10\xe8\x93\x00\x0c\xe3\xa0\x10\x03\xe3\xa0\x00\x01\xeb\xff\xfe\xb8\xe5\x9f\x32\xa8\xe2\x4b\xc0\x2c\xe1\xa0\xe0\x03\xe8\xbe\x00\x0f\xe8\xac\x00\x0f\xe8\x9e\x00\x03\xe8\x8c\x00\x03\xe1\xa0\x20\x0d\xe2\x4b\x30\x1c\xe8\x93\x00\x03\xe8\x82\x00\x03\xe2\x4b\x30\x2c\xe8\x93\x00\x0f\xeb\xff\xfe\xb8\xe3\xa0\x30\x61\xe1\xa0\x00\x03\xe1\xa0\x0c\x00\xeb\xff\xfe\xbf\xe1\xa0\x0c\x40\xed\xdf\x0a\x8e\xed\x9f\x1b\x7b\xe3\xa0\x10\x08\xed\x9f\x0a\x8c\xe3\xa0\x00\x04\xeb\xff\xfe\xc2\xed\x9f\x2a\x8a\xe3\xa0\x3c\x3b\xe3\x83\x30\x00\xee\x00\x3a\x90\xed\x9f\x1b\x72\xe3\xa0\x10\x08\xed\x9f\x0a\x83\xe3\xa0\x00\x04\xeb\xff\xfe\xc8\xe5\x9f\x32\x24\xe2\x4b\xc0\x4c\xe1\xa0\xe0\x03\xe8\xbe\x00\x0f\xe8\xac\x00\x0f\xe8\x9e\x00\x0f\xe8\x8c\x00\x0f\xed\x1b\x4b\x13\xed\x1b\x5b\x11\xed\x1b\x6b\x0f\xed\x1b\x7b\x0d\xee\xb0\x0b\x44\xee\xb0\x1b\x45\xee\xb0\x2b\x46\xee\xb0\x3b\x47\xeb\xff\xfe\xc9\xe3\xa0\x30\x00\xe5\x9f\x21\xe4\xe1\xcd\x20\xf8\xe3\xa0\x30\x00\xe5\x9f\x21\xdc\xe1\xcd\x20\xf0\xed\x9f\x7b\x59\xed\x9f\x6b\x5a\xed\x9f\x5b\x5b\xed\x9f\x4b\x5c\xed\x9f\x3b\x5d\xed\x9f\x2b\x5e\xed\x9f\x1b\x5f\xed\x9f\x0b\x60\xeb\xff\xfe\xcc\xe3\xa0\x3c\x63\xe3\x83\x30\xf0\xe1\xcd\x30\xb4\xe3\xa0\x3c\x63\xe3\x83\x30\xe0\xe1\xcd\x30\xb0\xe3\xa0\x3c\x63\xe3\x83\x30\xc0\xee\x07\x3a\x90\xe3\xa0\x3c\x63\xe3\x83\x30\x80\xee\x07\x3a\x10\xe3\xa0\x3c\x63\xe3\x83\x30\x00\xee\x06\x3a\x90\xe3\xa0\x3c\x62\xe3\x83\x30\x00\xee\x06\x3a\x10\xe3\xa0\x3a\x06\xe3\x83\x30\x00\xee\x05\x3a\x90\xe3\xa0\x3c\x73\xe3\x83\x30\xe0\xee\x05\x3a\x10\xe3\xa0\x3c\x73\xe3\x83\x30\xc0\xee\x04\x3a\x90\xe3\xa0\x3c\x73\xe3\x83\x30\x80\xee\x04\x3a\x10\xe3\xa0\x3c\x73\xe3\x83\x30\x00\xee\x03\x3a\x90\xe3\xa0\x3c\x72\xe3\x83\x30\x00\xee\x03\x3a\x10\xe3\xa0\x3a\x07\xe3\x83\x30\x00\xee\x02\x3a\x90\xe3\xa0\x3c\x43\xe3\x83\x30\xc0\xee\x02\x3a\x10\xe3\xa0\x3c\x43\xe3\x83\x30\x80\xee\x01\x3a\x90\xe3\xa0\x3c\x43\xe3\x83\x30\x00\xee\x01\x3a\x10\xe3\xa0\x3c\x42\xe3\x83\x30\x00\xee\x00\x3a\x90\xe3\xa0\x39\x01\xe3\x83\x30\x00\xee\x00\x3a\x10\xeb\xff\xfe\xa8\xeb\xff\xfe\xd1\xeb\xff\xfe\xd8\xeb\xff\xfe\xe3\xeb\xff\xff\x05\xeb\xff\xff\x0d\xeb\xff\xff\x14\xeb\xff\xff\x34\xe5\x9f\x00\xbc\xeb\xff\xff\x38\xe5\x9f\x00\xb8\xeb\xff\xff\x40\xe5\x9f\x00\xb4\xeb\xff\xff\x48\xeb\xff\xff\x16\xe3\x20\xf0\x00\xe2\x4b\xd0\x04\xe8\xbd\x88\x00\x05\x06\x07\x08\x09\x0a\x0b\x0c\x18\x17\x16\x15\x14\x13\x12\x11\x10\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01\x3f\xe8\x00\x00\x00\x00\x00\x00\x3f\xdf\xe0\x00\x00\x00\x00\x00\x3f\xdf\xc0\x00\x00\x00\x00\x00\x3f\xdf\x80\x00\x00\x00\x00\x00\x3f\xdf\x00\x00\x00\x00\x00\x00\x3f\xde\x00\x00\x00\x00\x00\x00\x3f\xdc\x00\x00\x00\x00\x00\x00\x3f\xd8\x00\x00\x00\x00\x00\x00\x3f\xd0\x00\x00\x00\x00\x00\x00\x3f\x60\x00\x00\x3f\x00\x00\x00\x3f\x7c\x00\x00\x0d\x0e\x0f\x10\x09\x0a\x0b\x0c\x05\x06\x07\x08\x01\x02\x03\x04\x1c\x1b\x1a\x19\x00\x00\x09\x0c\x00\x00\x09\x18\x00\x00\x09\x30\x3f\xdf\xf8\x00\x3f\xdf\xf0\x00\x00\x00\x12\x34\xc0\xde\xc0\xfe\xc0\xfe\xc0\xde\x49\x4a\x4b\x00\x3f\x00\x00\x00\x3f\x40\x00\x00\x3f\x60\x00\x00\x3f\x7c\x00\x00\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x61\x00\x0f\x10\x11\x12\x13\x14\x62\x00\x00\x00\x00\x00\x00\x00\x15\x16\x17\x18\x19\x1a\x1b\x1c\x3f\xe0\x00\x00\x00\x00\x00\x00\x3f\xe8\x00\x00\x00\x00\x00\x00\x3f\xec\x00\x00\x00\x00\x00\x00\x3f\xef\x80\x00\x00\x00\x00\x00'}],
   'extra': {}}

BlobCcAapcs32ArmebV6HardFloatFp16Ieee = MetaBinBlob.from_dict(meta_blob_cc_aapcs32_armeb_v6_hard_float_fp16_ieee)


from ...cc.source_code_analyzer import MetaSourceCode

meta_source_code_cc_aapcs32_armeb_v6_hard_float_fp16_ieee = \
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
            {'address': 472,
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
            {'address': 540,
             'size': 72,
             'name': 'foo_09',
             'return_value_type': 'float',
             'return_value': 0.9375,
             'arguments': {0: ('a', 'struct struct_09_4')},
             'call_arg_values': {0: {'a': {'a': 0.5, 'b': 0.75},
                                     'wrap': {'b': {'c': 0.875,
                                                    'd': 0.984375}}}}},
            {'address': 612,
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
            {'address': 688,
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
            {'address': 856,
             'size': 32,
             'name': 'foo_12',
             'return_value_type': 'unsigned short',
             'return_value': 43981,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 888,
             'size': 48,
             'name': 'foo_13',
             'return_value_type': 'unsigned long long',
             'return_value': 18441921395520346504,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 936,
             'size': 140,
             'name': 'foo_14',
             'return_value_type': 'struct struct_14',
             'return_value': {'a': 73, 'b': 74, 'c': 75},
             'arguments': {},
             'call_arg_values': {}},
            {'address': 1076,
             'size': 36,
             'name': 'foo_15',
             'return_value_type': '__fp16',
             'return_value': 3.875,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 1112,
             'size': 32,
             'name': 'foo_16',
             'return_value_type': 'float',
             'return_value': 0.75,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 1144,
             'size': 40,
             'name': 'foo_17',
             'return_value_type': 'double',
             'return_value': 0.75,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 1184,
             'size': 92,
             'name': 'foo_18',
             'return_value_type': 'struct struct_18_wrap_l2',
             'return_value': {'a': {'a': 0.5, 'b': 0.75},
                              'wrap': {'b': {'c': 0.875, 'd': 0.984375}}},
             'arguments': {},
             'call_arg_values': {}},
            {'address': 1276,
             'size': 24,
             'name': 'foo_19',
             'return_value_type': None,
             'return_value': None,
             'arguments': {},
             'call_arg_values': {}},
            {'address': 1300,
             'size': 40,
             'name': 'foo_20',
             'return_value_type': 'unsigned int',
             'return_value': 1,
             'arguments': {0: ('a', 'unsigned short')},
             'call_arg_values': {0: 4660}},
            {'address': 1340,
             'size': 40,
             'name': 'foo_21',
             'return_value_type': 'unsigned char*',
             'return_value': 3135158974,
             'arguments': {0: ('a', 'unsigned char*')},
             'call_arg_values': {0: 3235823870}},
            {'address': 1380,
             'size': 40,
             'name': 'foo_22',
             'return_value_type': 'unsigned char**',
             'return_value': 3133061854,
             'arguments': {0: ('a', 'unsigned char**')},
             'call_arg_values': {0: 3237920990}},
            {'address': 1420,
             'size': 876,
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

MetaSourceCodeCcAapcs32ArmebV6HardFloatFp16Ieee = MetaSourceCode.from_dict(meta_source_code_cc_aapcs32_armeb_v6_hard_float_fp16_ieee)

BlobCcAapcs32ArmebV6HardFloatFp16Ieee.extra.update({"cc_test_data": MetaSourceCodeCcAapcs32ArmebV6HardFloatFp16Ieee})
