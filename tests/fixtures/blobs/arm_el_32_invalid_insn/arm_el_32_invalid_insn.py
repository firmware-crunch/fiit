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

arm_el_32_invalid_insn = \
    {'arch_unicorn': 'arm:el:32:default',
     'arch_info': {},
     'compiler': '',
     'producer': '',
     'emu_start': 0,
     'emu_end': 8,
     'mem_map': [{'name': 'rom', 'perm': 'rx', 'base_address': 0, 'size': 4096}],
     'disassembly': (
        'mov r0, #32\n'
        '0xffffffff\n\n'
        '.data\n'
        '    .word 0xdeadc0de\n'),
     'mapped_blobs': [{'loading_address': 0,
                       'blob': b'\x20\x00\xa0\xe3\xff\xff\xff\xff\xde\xc0\xad\xde'}]}


BlobArmEl32InvalidInsn = MetaBinBlob(**arm_el_32_invalid_insn)
