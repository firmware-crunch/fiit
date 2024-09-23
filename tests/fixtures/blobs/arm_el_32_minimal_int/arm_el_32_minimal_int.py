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

meta_blob_arm_el_32_minimal_int = \
  {'arch_unicorn': 'arm:el:32:926',
   'arch_info': {'cpu_float_flag': 'FLOAT_SOFT',
                 'tag_cpu_arch': 'v5TEJ',
                 'tag_cpu_name': 'ARM926EJ-S',
                 'tag_fp_arch': None,
                 'tag_abi_fp_16bit_format': 'IEEE754'},
   'compiler': None,
   'producer': None,
   'emu_start': 0,
   'emu_end': 156,
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
                  '   8:  eafffffe   b  8 <PERM_X>\n'
                  '   c:  eafffffe   b  c <__mem_map_area_rom+0x2>\n'
                  '  10:  eafffffe   b  10 <MODE_USR>\n'
                  '  14:  eafffffe   b  14 <MODE_SVC+0x1>\n'
                  '  18:  ea00000c   b  50 <__irq_handler__>\n'
                  '  1c:  ea00000f   b  60 <__fiq_handler__>\n'
                  '\n'
                  '00000020 <__reset_handler__>:\n'
                  '  20:  e3a020d1   mov  r2, #209  @ 0xd1\n'
                  '  24:  e121f002   msr  CPSR_c, r2\n'
                  '  28:  e3a0dc03   mov  sp, #768  @ 0x300\n'
                  '  2c:  e3a020d2   mov  r2, #210  @ 0xd2\n'
                  '  30:  e121f002   msr  CPSR_c, r2\n'
                  '  34:  e3a0db01   mov  sp, #1024  @ 0x400\n'
                  '  38:  e3a020d3   mov  r2, #211  @ 0xd3\n'
                  '  3c:  e3a0dc02   mov  sp, #512  @ 0x200\n'
                  '  40:  e121f002   msr  CPSR_c, r2\n'
                  '  44:  eb000009   bl  70 <enable_irq>\n'
                  '  48:  eb00000c   bl  80 <enable_fiq>\n'
                  '  4c:  ea00000f   b  90 <__entry__>\n'
                  '\n'
                  '00000050 <__irq_handler__>:\n'
                  '  50:  e24ee004   sub  lr, lr, #4\n'
                  '  54:  e92d500f   push  {r0, r1, r2, r3, ip, lr}\n'
                  '  58:  e1a00000   nop      @ (mov r0, r0)\n'
                  '  5c:  e8fd900f   ldm  sp!, {r0, r1, r2, r3, ip, pc}^\n'
                  '\n'
                  '00000060 <__fiq_handler__>:\n'
                  '  60:  e24ee004   sub  lr, lr, #4\n'
                  '  64:  e92d500f   push  {r0, r1, r2, r3, ip, lr}\n'
                  '  68:  e1a00000   nop      @ (mov r0, r0)\n'
                  '  6c:  e8fd900f   ldm  sp!, {r0, r1, r2, r3, ip, pc}^\n'
                  '\n'
                  '00000070 <enable_irq>:\n'
                  '  70:  e10f1000   mrs  r1, CPSR\n'
                  '  74:  e3c11080   bic  r1, r1, #128  @ 0x80\n'
                  '  78:  e121f001   msr  CPSR_c, r1\n'
                  '  7c:  e12fff1e   bx  lr\n'
                  '\n'
                  '00000080 <enable_fiq>:\n'
                  '  80:  e10f1000   mrs  r1, CPSR\n'
                  '  84:  e3c11040   bic  r1, r1, #64  @ 0x40\n'
                  '  88:  e121f001   msr  CPSR_c, r1\n'
                  '  8c:  e12fff1e   bx  lr\n'
                  '\n'
                  '00000090 <__entry__>:\n'
                  '  90:  e1a00000   nop      @ (mov r0, r0)\n'
                  '  94:  e1a00000   nop      @ (mov r0, r0)\n'
                  '  98:  e1a00000   nop      @ (mov r0, r0)\n'
                  '\n'
                  '0000009c <emu_end>:\n'
                  '  9c:  e1a00000   nop      @ (mov r0, r0)\n',
   'mapped_blobs': [{'loading_address': 0,
                     'blob': b'\x06\x00\x00\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\x0c\x00\x00\xea\x0f\x00\x00\xea\xd1\x20\xa0\xe3\x02\xf0\x21\xe1\x03\xdc\xa0\xe3\xd2\x20\xa0\xe3\x02\xf0\x21\xe1\x01\xdb\xa0\xe3\xd3\x20\xa0\xe3\x02\xdc\xa0\xe3\x02\xf0\x21\xe1\x09\x00\x00\xeb\x0c\x00\x00\xeb\x0f\x00\x00\xea\x04\xe0\x4e\xe2\x0f\x50\x2d\xe9\x00\x00\xa0\xe1\x0f\x90\xfd\xe8\x04\xe0\x4e\xe2\x0f\x50\x2d\xe9\x00\x00\xa0\xe1\x0f\x90\xfd\xe8\x00\x10\x0f\xe1\x80\x10\xc1\xe3\x01\xf0\x21\xe1\x1e\xff\x2f\xe1\x00\x10\x0f\xe1\x40\x10\xc1\xe3\x01\xf0\x21\xe1\x1e\xff\x2f\xe1\x00\x00\xa0\xe1\x00\x00\xa0\xe1\x00\x00\xa0\xe1\x00\x00\xa0\xe1'}],
   'extra': {}}

BlobArmEl32MinimalInt = MetaBinBlob.from_dict(meta_blob_arm_el_32_minimal_int)
