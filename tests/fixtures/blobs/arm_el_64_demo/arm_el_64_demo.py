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

meta_blob_arm_el_64_demo = \
  {'arch_unicorn': 'arm:el:64:default',
   'arch_info': {},
   'compiler': None,
   'producer': None,
   'emu_start': 0,
   'emu_end': 8,
   'mem_map': [{'name': 'rom', 'perm': 'rx', 'base_address': 0, 'size': 4096}],
   'disassembly': '\n'
                  'main.elf:     file format elf64-littleaarch64\n'
                  '\n'
                  '\n'
                  'Disassembly of section .text:\n'
                  '\n'
                  '0000000000000000 <__main__>:\n'
                  '   0:  aa0103e0   mov  x0, x1\n'
                  '   4:  d340f820   ubfx  x0, x1, #0, #63\n'
                  '\n'
                  '0000000000000008 <emu_end>:\n'
                  '   8:  aa0003e0   mov  x0, x0\n',
   'mapped_blobs': [{'loading_address': 0,
                     'blob': b'\xe0\x03\x01\xaa\x20\xf8\x40\xd3\xe0\x03\x00\xaa'}],
   'extra': {}}

BlobArmEl64Demo = MetaBinBlob.from_dict(meta_blob_arm_el_64_demo)
