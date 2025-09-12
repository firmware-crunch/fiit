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

from typing import List


from capstone import *


from ..emu.emu_types import ADDRESS_FORMAT


CAPSTONE_CONFIG = {
    # processor : endian : size : variant

    ############################################################################
    # x86
    ############################################################################
    'i8086:el:16:default': (CS_ARCH_X86, CS_MODE_16),
    'x86:el:32:default': (CS_ARCH_X86, CS_MODE_32),
    'x86:el:64:default': (CS_ARCH_X86, CS_MODE_64),

    ############################################################################
    # ARM
    ############################################################################
    'arm:el:32:default': (CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN),
    'arm:eb:32:default': (CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_BIG_ENDIAN),
    'arm:el:64:default': (CS_ARCH_ARM64, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN),
    'arm:eb:64:default': (CS_ARCH_ARM64, CS_MODE_ARM | CS_MODE_BIG_ENDIAN),

    ############################################################################
    # MIPS
    ############################################################################
    'mips:el:32:default': (CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN),
    'mips:eb:32:default': (CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN),
    'mips:el:64:default': (CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN),
    'mips:eb:64:default': (CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN),

    ############################################################################
    # PPC
    ############################################################################
    'ppc:eb:32:default': (CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN),
    'ppc:eb:64:default': (CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN),

    ############################################################################
    # SPARC
    ############################################################################
    'sparc:eb:32:default': (CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN),
    'sparc:eb:64:default': (CS_ARCH_SPARC, CS_MODE_V9 | CS_MODE_BIG_ENDIAN),

    ############################################################################
    # m68k
    ############################################################################
    'm68k:eb:32:default': (CS_ARCH_M68K, CS_MODE_BIG_ENDIAN),
}


class DisassemblerCapstone:
    def __init__(self, arch: str):
        self._arch = arch
        self._bit_size = int(arch.split(':')[2])
        self._addr_format = ADDRESS_FORMAT[self._bit_size]
        self._md = Cs(*CAPSTONE_CONFIG[arch])
        self._md.detail = True

    def disassemble_mem_range(self, code: bytearray, start_addr: int,
                              count: int = 1) -> List[str]:
        out: List[str] = []
        for insn in self._md.disasm(code, start_addr, count):
            out.append(f'{self._addr_format(insn.address)}:\t'
                       f'{"".join([f"{b:02x}" for b in insn.bytes]):<20}\t'
                       f'{insn.mnemonic}\t'
                       f'{insn.op_str}')
        return out
