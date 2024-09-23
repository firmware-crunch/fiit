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

meta_blob_arm_el_32_mem_fetch_unmapped = \
  {'arch_unicorn': 'arm:el:32:926',
   'arch_info': {'cpu_float_flag': 'FLOAT_SOFT',
                 'tag_cpu_arch': 'v5TEJ',
                 'tag_cpu_name': 'ARM926EJ-S',
                 'tag_fp_arch': None,
                 'tag_abi_fp_16bit_format': 'IEEE754'},
   'compiler': None,
   'producer': None,
   'emu_start': 131072,
   'emu_end': 131080,
   'mem_map': [{'name': 'rom',
                'perm': 'rx',
                'base_address': 131072,
                'size': 4096}],
   'disassembly': '\n'
                  'main.elf:     file format elf32-littlearm\n'
                  '\n'
                  '\n'
                  'Disassembly of section .text:\n'
                  '\n'
                  '00020000 <__main__>:\n'
                  '   20000:  e3a008ff   mov  r0, #16711680  @ 0xff0000\n'
                  '   20004:  e12fff10   bx  r0\n'
                  '\n'
                  '00020008 <emu_end>:\n'
                  '   20008:  e1a00000   nop      @ (mov r0, r0)\n',
   'mapped_blobs': [{'loading_address': 131072,
                     'blob': b'\xff\x08\xa0\xe3\x10\xff\x2f\xe1\x00\x00\xa0\xe1'}],
   'extra': {}}

BlobArmEl32MemFetchUnmapped = MetaBinBlob.from_dict(meta_blob_arm_el_32_mem_fetch_unmapped)
