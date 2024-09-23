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

meta_blob_arm_el_32_multi_block = \
  {'arch_unicorn': 'arm:el:32:926',
   'arch_info': {'cpu_float_flag': 'FLOAT_SOFT',
                 'tag_cpu_arch': 'v5TEJ',
                 'tag_cpu_name': 'ARM926EJ-S',
                 'tag_fp_arch': None,
                 'tag_abi_fp_16bit_format': 'IEEE754'},
   'compiler': None,
   'producer': None,
   'emu_start': 0,
   'emu_end': 80,
   'mem_map': [{'name': 'rom', 'perm': 'rwx', 'base_address': 0, 'size': 4096}],
   'disassembly': '\n'
                  'main.elf:     file format elf32-littlearm\n'
                  '\n'
                  '\n'
                  'Disassembly of section .text:\n'
                  '\n'
                  '00000000 <__main__>:\n'
                  '   0:  e3a00001   mov  r0, #1\n'
                  '   4:  e3a01001   mov  r1, #1\n'
                  '   8:  e1500001   cmp  r0, r1\n'
                  '   c:  1afffffe   bne  c <PERM_X+0x4>\n'
                  '\n'
                  '00000010 <block_2>:\n'
                  '  10:  e3a00002   mov  r0, #2\n'
                  '  14:  e3a01002   mov  r1, #2\n'
                  '  18:  e1500001   cmp  r0, r1\n'
                  '  1c:  1afffffe   bne  1c <block_2+0xc>\n'
                  '\n'
                  '00000020 <block_3>:\n'
                  '  20:  e3a00003   mov  r0, #3\n'
                  '  24:  e3a01003   mov  r1, #3\n'
                  '  28:  e1500001   cmp  r0, r1\n'
                  '  2c:  1afffffe   bne  2c <block_3+0xc>\n'
                  '\n'
                  '00000030 <block_4>:\n'
                  '  30:  e3a00004   mov  r0, #4\n'
                  '  34:  e3a01004   mov  r1, #4\n'
                  '  38:  e1500001   cmp  r0, r1\n'
                  '  3c:  1afffffe   bne  3c <block_4+0xc>\n'
                  '\n'
                  '00000040 <block_5>:\n'
                  '  40:  e3a00005   mov  r0, #5\n'
                  '  44:  e3a01005   mov  r1, #5\n'
                  '  48:  e1500001   cmp  r0, r1\n'
                  '  4c:  1afffffe   bne  4c <block_5+0xc>\n'
                  '\n'
                  '00000050 <emu_end>:\n'
                  '  50:  e1a00000   nop      @ (mov r0, r0)\n',
   'mapped_blobs': [{'loading_address': 0,
                     'blob': b'\x01\x00\xa0\xe3\x01\x10\xa0\xe3\x01\x00\x50\xe1\xfe\xff\xff\x1a\x02\x00\xa0\xe3\x02\x10\xa0\xe3\x01\x00\x50\xe1\xfe\xff\xff\x1a\x03\x00\xa0\xe3\x03\x10\xa0\xe3\x01\x00\x50\xe1\xfe\xff\xff\x1a\x04\x00\xa0\xe3\x04\x10\xa0\xe3\x01\x00\x50\xe1\xfe\xff\xff\x1a\x05\x00\xa0\xe3\x05\x10\xa0\xe3\x01\x00\x50\xe1\xfe\xff\xff\x1a\x00\x00\xa0\xe1'}],
   'extra': {}}

BlobArmEl32MultiBlock = MetaBinBlob.from_dict(meta_blob_arm_el_32_multi_block)
