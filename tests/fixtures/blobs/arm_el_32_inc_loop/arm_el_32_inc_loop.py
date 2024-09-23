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

meta_blob_arm_el_32_inc_loop = \
  {'arch_unicorn': 'arm:el:32:926',
   'arch_info': {'cpu_float_flag': 'FLOAT_SOFT',
                 'tag_cpu_arch': 'v5TEJ',
                 'tag_cpu_name': 'ARM926EJ-S',
                 'tag_fp_arch': None,
                 'tag_abi_fp_16bit_format': 'IEEE754'},
   'compiler': None,
   'producer': None,
   'emu_start': 0,
   'emu_end': 24,
   'mem_map': [{'name': 'rom', 'perm': 'rx', 'base_address': 0, 'size': 4096}],
   'disassembly': '\n'
                  'main.elf:     file format elf32-littlearm\n'
                  '\n'
                  '\n'
                  'Disassembly of section .text:\n'
                  '\n'
                  '00000000 <__main__>:\n'
                  '   0:  e3a00000   mov  r0, #0\n'
                  '   4:  eaffffff   b  8 <block_2>\n'
                  '\n'
                  '00000008 <block_2>:\n'
                  '   8:  e2800001   add  r0, r0, #1\n'
                  '   c:  e350000a   cmp  r0, #10\n'
                  '  10:  1afffffc   bne  8 <block_2>\n'
                  '\n'
                  '00000014 <block_3>:\n'
                  '  14:  e3a01001   mov  r1, #1\n'
                  '\n'
                  '00000018 <emu_end>:\n'
                  '  18:  e1a00000   nop      @ (mov r0, r0)\n',
   'mapped_blobs': [{'loading_address': 0,
                     'blob': b'\x00\x00\xa0\xe3\xff\xff\xff\xea\x01\x00\x80\xe2\x0a\x00\x50\xe3\xfc\xff\xff\x1a\x01\x10\xa0\xe3\x00\x00\xa0\xe1'}],
   'extra': {}}

BlobArmEl32IncLoop = MetaBinBlob.from_dict(meta_blob_arm_el_32_inc_loop)
