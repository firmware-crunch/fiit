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

meta_blob_arm_el_32_read_write_loop = \
  {'arch_unicorn': 'arm:el:32:926',
   'arch_info': {'cpu_float_flag': 'FLOAT_SOFT',
                 'tag_cpu_arch': 'v5TEJ',
                 'tag_cpu_name': 'ARM926EJ-S',
                 'tag_fp_arch': None,
                 'tag_abi_fp_16bit_format': 'IEEE754'},
   'compiler': None,
   'producer': None,
   'emu_start': 0,
   'emu_end': 32,
   'mem_map': [{'name': 'rom', 'perm': 'rx', 'base_address': 0, 'size': 4096}],
   'disassembly': '\n'
                  'main.elf:     file format elf32-littlearm\n'
                  '\n'
                  '\n'
                  'Disassembly of section .text:\n'
                  '\n'
                  '00000000 <__main__>:\n'
                  '   0:  e3a00020   mov  r0, #32\n'
                  '   4:  e3a03000   mov  r3, #0\n'
                  '\n'
                  '00000008 <block_2>:\n'
                  '   8:  e5902000   ldr  r2, [r0]\n'
                  '   c:  e5802000   str  r2, [r0]\n'
                  '  10:  e2833001   add  r3, r3, #1\n'
                  '  14:  e3a0400a   mov  r4, #10\n'
                  '  18:  e1530004   cmp  r3, r4\n'
                  '  1c:  1afffff9   bne  8 <block_2>\n'
                  '\n'
                  '00000020 <emu_end>:\n'
                  '  20:  e1a00000   nop      @ (mov r0, r0)\n',
   'mapped_blobs': [{'loading_address': 0,
                     'blob': b'\x20\x00\xa0\xe3\x00\x30\xa0\xe3\x00\x20\x90\xe5\x00\x20\x80\xe5\x01\x30\x83\xe2\x0a\x40\xa0\xe3\x04\x00\x53\xe1\xf9\xff\xff\x1a\x00\x00\xa0\xe1'}],
   'extra': {}}

BlobArmEl32ReadWriteLoop = MetaBinBlob.from_dict(meta_blob_arm_el_32_read_write_loop)
