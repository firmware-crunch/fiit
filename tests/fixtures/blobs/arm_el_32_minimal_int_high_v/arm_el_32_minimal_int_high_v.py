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

meta_blob_arm_el_32_minimal_int_high_v = \
  {'arch_unicorn': 'arm:el:32:926',
   'arch_info': {'cpu_float_flag': 'FLOAT_SOFT',
                 'tag_cpu_arch': 'v5TEJ',
                 'tag_cpu_name': 'ARM926EJ-S',
                 'tag_fp_arch': None,
                 'tag_abi_fp_16bit_format': 'IEEE754'},
   'compiler': None,
   'producer': None,
   'emu_start': 4294901760,
   'emu_end': 4294901916,
   'mem_map': [{'name': 'rom',
                'perm': 'rx',
                'base_address': 4294901760,
                'size': 4096}],
   'disassembly': '\n'
                  'main.elf:     file format elf32-littlearm\n'
                  '\n'
                  '\n'
                  'Disassembly of section .text:\n'
                  '\n'
                  'ffff0000 <__INTERRUPT_VECTOR_TABLE__>:\n'
                  'ffff0000:  ea000006   b  ffff0020 <__reset_handler__>\n'
                  'ffff0004:  eafffffe   b  ffff0004 '
                  '<__INTERRUPT_VECTOR_TABLE__+0x4>\n'
                  'ffff0008:  eafffffe   b  ffff0008 '
                  '<__INTERRUPT_VECTOR_TABLE__+0x8>\n'
                  'ffff000c:  eafffffe   b  ffff000c '
                  '<__INTERRUPT_VECTOR_TABLE__+0xc>\n'
                  'ffff0010:  eafffffe   b  ffff0010 '
                  '<__INTERRUPT_VECTOR_TABLE__+0x10>\n'
                  'ffff0014:  eafffffe   b  ffff0014 '
                  '<__INTERRUPT_VECTOR_TABLE__+0x14>\n'
                  'ffff0018:  ea00000c   b  ffff0050 <__irq_handler__>\n'
                  'ffff001c:  ea00000f   b  ffff0060 <__fiq_handler__>\n'
                  '\n'
                  'ffff0020 <__reset_handler__>:\n'
                  'ffff0020:  e3a020d1   mov  r2, #209  @ 0xd1\n'
                  'ffff0024:  e121f002   msr  CPSR_c, r2\n'
                  'ffff0028:  e59fd070   ldr  sp, [pc, #112]  @ ffff00a0 '
                  '<emu_end+0x4>\n'
                  'ffff002c:  e3a020d2   mov  r2, #210  @ 0xd2\n'
                  'ffff0030:  e121f002   msr  CPSR_c, r2\n'
                  'ffff0034:  e59fd068   ldr  sp, [pc, #104]  @ ffff00a4 '
                  '<emu_end+0x8>\n'
                  'ffff0038:  e3a020d3   mov  r2, #211  @ 0xd3\n'
                  'ffff003c:  e59fd064   ldr  sp, [pc, #100]  @ ffff00a8 '
                  '<emu_end+0xc>\n'
                  'ffff0040:  e121f002   msr  CPSR_c, r2\n'
                  'ffff0044:  eb000009   bl  ffff0070 <enable_irq>\n'
                  'ffff0048:  eb00000c   bl  ffff0080 <enable_fiq>\n'
                  'ffff004c:  ea00000f   b  ffff0090 <__entry__>\n'
                  '\n'
                  'ffff0050 <__irq_handler__>:\n'
                  'ffff0050:  e24ee004   sub  lr, lr, #4\n'
                  'ffff0054:  e92d500f   push  {r0, r1, r2, r3, ip, lr}\n'
                  'ffff0058:  e1a00000   nop      @ (mov r0, r0)\n'
                  'ffff005c:  e8fd900f   ldm  sp!, {r0, r1, r2, r3, ip, pc}^\n'
                  '\n'
                  'ffff0060 <__fiq_handler__>:\n'
                  'ffff0060:  e24ee004   sub  lr, lr, #4\n'
                  'ffff0064:  e92d500f   push  {r0, r1, r2, r3, ip, lr}\n'
                  'ffff0068:  e1a00000   nop      @ (mov r0, r0)\n'
                  'ffff006c:  e8fd900f   ldm  sp!, {r0, r1, r2, r3, ip, pc}^\n'
                  '\n'
                  'ffff0070 <enable_irq>:\n'
                  'ffff0070:  e10f1000   mrs  r1, CPSR\n'
                  'ffff0074:  e3c11080   bic  r1, r1, #128  @ 0x80\n'
                  'ffff0078:  e121f001   msr  CPSR_c, r1\n'
                  'ffff007c:  e12fff1e   bx  lr\n'
                  '\n'
                  'ffff0080 <enable_fiq>:\n'
                  'ffff0080:  e10f1000   mrs  r1, CPSR\n'
                  'ffff0084:  e3c11040   bic  r1, r1, #64  @ 0x40\n'
                  'ffff0088:  e121f001   msr  CPSR_c, r1\n'
                  'ffff008c:  e12fff1e   bx  lr\n'
                  '\n'
                  'ffff0090 <__entry__>:\n'
                  'ffff0090:  e1a00000   nop      @ (mov r0, r0)\n'
                  'ffff0094:  e1a00000   nop      @ (mov r0, r0)\n'
                  'ffff0098:  e1a00000   nop      @ (mov r0, r0)\n'
                  '\n'
                  'ffff009c <emu_end>:\n'
                  'ffff009c:  e1a00000   nop      @ (mov r0, r0)\n'
                  'ffff00a0:  ffff0300   .word  0xffff0300\n'
                  'ffff00a4:  ffff0400   .word  0xffff0400\n'
                  'ffff00a8:  ffff0200   .word  0xffff0200\n',
   'mapped_blobs': [{'loading_address': 4294901760,
                     'blob': b'\x06\x00\x00\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\xfe\xff\xff\xea\x0c\x00\x00\xea\x0f\x00\x00\xea\xd1\x20\xa0\xe3\x02\xf0\x21\xe1\x70\xd0\x9f\xe5\xd2\x20\xa0\xe3\x02\xf0\x21\xe1\x68\xd0\x9f\xe5\xd3\x20\xa0\xe3\x64\xd0\x9f\xe5\x02\xf0\x21\xe1\x09\x00\x00\xeb\x0c\x00\x00\xeb\x0f\x00\x00\xea\x04\xe0\x4e\xe2\x0f\x50\x2d\xe9\x00\x00\xa0\xe1\x0f\x90\xfd\xe8\x04\xe0\x4e\xe2\x0f\x50\x2d\xe9\x00\x00\xa0\xe1\x0f\x90\xfd\xe8\x00\x10\x0f\xe1\x80\x10\xc1\xe3\x01\xf0\x21\xe1\x1e\xff\x2f\xe1\x00\x10\x0f\xe1\x40\x10\xc1\xe3\x01\xf0\x21\xe1\x1e\xff\x2f\xe1\x00\x00\xa0\xe1\x00\x00\xa0\xe1\x00\x00\xa0\xe1\x00\x00\xa0\xe1\x00\x03\xff\xff\x00\x04\xff\xff\x00\x02\xff\xff'}],
   'extra': {}}

BlobArmEl32MinimalIntHighV = MetaBinBlob.from_dict(meta_blob_arm_el_32_minimal_int_high_v)
