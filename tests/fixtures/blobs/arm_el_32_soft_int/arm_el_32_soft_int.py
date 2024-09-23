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

meta_blob_arm_el_32_soft_int = \
  {'arch_unicorn': 'arm:el:32:926',
   'arch_info': {'cpu_float_flag': 'FLOAT_SOFT',
                 'tag_cpu_arch': 'v5TEJ',
                 'tag_cpu_name': 'ARM926EJ-S',
                 'tag_fp_arch': None,
                 'tag_abi_fp_16bit_format': 'IEEE754'},
   'compiler': None,
   'producer': None,
   'emu_start': 0,
   'emu_end': 84,
   'mem_map': [{'name': 'rom', 'perm': 'rx', 'base_address': 0, 'size': 4096}],
   'disassembly': '\n'
                  'main.elf:     file format elf32-littlearm\n'
                  '\n'
                  '\n'
                  'Disassembly of section .text:\n'
                  '\n'
                  '00000000 <__INTERRUPT_VECTOR_TABLE__>:\n'
                  '   0:  ea000006   b  20 <__reset_handler__>\n'
                  '   4:  eafffffe   b  4 <PERM_W>\n'
                  '   8:  ea00000b   b  3c <__swi_handler__>\n'
                  '   c:  eafffffe   b  c <__mem_map_area_rom+0x2>\n'
                  '  10:  eafffffe   b  10 <MODE_USR>\n'
                  '  14:  eafffffe   b  14 <MODE_SVC+0x1>\n'
                  '  18:  eafffffe   b  18 <MODE_ABT+0x1>\n'
                  '  1c:  eafffffe   b  1c <MODE_UND+0x1>\n'
                  '\n'
                  '00000020 <__reset_handler__>:\n'
                  '  20:  e3a020d3   mov  r2, #211  @ 0xd3\n'
                  '  24:  e3a0dc02   mov  sp, #512  @ 0x200\n'
                  '  28:  e121f002   msr  CPSR_c, r2\n'
                  '  2c:  e3a020d0   mov  r2, #208  @ 0xd0\n'
                  '  30:  e3a0dc03   mov  sp, #768  @ 0x300\n'
                  '  34:  e121f002   msr  CPSR_c, r2\n'
                  '  38:  ea000002   b  48 <__entry__>\n'
                  '\n'
                  '0000003c <__swi_handler__>:\n'
                  '  3c:  e92d5fff   push  {r0, r1, r2, r3, r4, r5, r6, r7, '
                  'r8, r9, sl, fp, ip, lr}\n'
                  '  40:  e1a00000   nop      @ (mov r0, r0)\n'
                  '  44:  e8fd9fff   ldm  sp!, {r0, r1, r2, r3, r4, r5, r6, '
                  'r7, r8, r9, sl, fp, ip, pc}^\n'
                  '\n'
                  '00000048 <__entry__>:\n'
                  '  48:  e1a00000   nop      @ (mov r0, r0)\n'
                  '  4c:  ef000000   svc  0x00000000\n'
                  '  50:  e1a00000   nop      @ (mov r0, r0)\n'
                  '\n'
                  '00000054 <emu_end>:\n'
                  '  54:  e1a00000   nop      @ (mov r0, r0)\n',
   'mapped_blobs': [{'loading_address': 0,
                     'blob': b'\x06\x00\x00\xea\xfe\xff\xff\xea\x0b\x00\x00\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xd3\x20\xa0\xe3\x02\xdc\xa0\xe3\x02\xf0\x21\xe1\xd0\x20\xa0\xe3\x03\xdc\xa0\xe3\x02\xf0\x21\xe1\x02\x00\x00\xea\xff\x5f\x2d\xe9\x00\x00\xa0\xe1\xff\x9f\xfd\xe8\x00\x00\xa0\xe1\x00\x00\x00\xef\x00\x00\xa0\xe1\x00\x00\xa0\xe1'}],
   'extra': {}}

BlobArmEl32SoftInt = MetaBinBlob.from_dict(meta_blob_arm_el_32_soft_int)
