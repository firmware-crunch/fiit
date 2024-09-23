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

import struct
from typing import Callable, cast, Literal, List, Union, Dict, Tuple

import unicorn
from unicorn.unicorn_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *
from unicorn.sparc_const import *
from unicorn.m68k_const import *


REG_ARM32 = {
    UC_ARM_REG_R0: 'r0',
    UC_ARM_REG_R1: 'r1',
    UC_ARM_REG_R2: 'r2',
    UC_ARM_REG_R3: 'r3',
    UC_ARM_REG_R4: 'r4',
    UC_ARM_REG_R5: 'r5',
    UC_ARM_REG_R6: 'r6',
    UC_ARM_REG_R7: 'r7',
    UC_ARM_REG_R8: 'r8',
    UC_ARM_REG_R9: 'r9',
    UC_ARM_REG_R10: 'r10',
    UC_ARM_REG_FP: 'r11',
    UC_ARM_REG_IP: 'r12',
    UC_ARM_REG_SP: 'sp',
    UC_ARM_REG_LR: 'lr',
    UC_ARM_REG_PC: 'pc',
    UC_ARM_REG_CPSR: 'cpsr'
}

REG_ARM64 = {
    UC_ARM64_REG_X0: 'x0',
    UC_ARM64_REG_X1: 'x1',
    UC_ARM64_REG_X2: 'x2',
    UC_ARM64_REG_X3: 'x3',
    UC_ARM64_REG_X4: 'x4',
    UC_ARM64_REG_X5: 'x5',
    UC_ARM64_REG_X6: 'x6',
    UC_ARM64_REG_X7: 'x7',
    UC_ARM64_REG_X8: 'x8',
    UC_ARM64_REG_X9: 'x9',
    UC_ARM64_REG_X10: 'x10',
    UC_ARM64_REG_X11: 'x11',
    UC_ARM64_REG_X12: 'x12',
    UC_ARM64_REG_X13: 'x13',
    UC_ARM64_REG_X14: 'x14',
    UC_ARM64_REG_X15: 'x15',
    UC_ARM64_REG_X16: 'x16',
    UC_ARM64_REG_X17: 'x17',
    UC_ARM64_REG_X18: 'x18',
    UC_ARM64_REG_X19: 'x19',
    UC_ARM64_REG_X20: 'x20',
    UC_ARM64_REG_X21: 'x21',
    UC_ARM64_REG_X22: 'x22',
    UC_ARM64_REG_X23: 'x23',
    UC_ARM64_REG_X24: 'x24',
    UC_ARM64_REG_X25: 'x25',
    UC_ARM64_REG_X26: 'x26',
    UC_ARM64_REG_X27: 'x27',
    UC_ARM64_REG_X28: 'x28',
    UC_ARM64_REG_PC: 'pc',
    UC_ARM64_REG_SP: 'sp',
    UC_ARM64_REG_FP: 'fp',
    UC_ARM64_REG_LR: 'lr',
    UC_ARM64_REG_NZCV: 'nzcv',
    UC_ARM_REG_CPSR: 'cpsr'
}

REG_8086 = {
    UC_X86_REG_IP: 'ip',
    UC_X86_REG_DI: 'di',
    UC_X86_REG_SI: 'si',
    UC_X86_REG_AX: 'ax',
    UC_X86_REG_BX: 'bx',
    UC_X86_REG_CX: 'cx',
    UC_X86_REG_DX: 'dx',
    UC_X86_REG_SP: 'sp',
    UC_X86_REG_BP: 'bp',
    UC_X86_REG_EFLAGS: 'eflags',
    UC_X86_REG_CS: 'cs',
    UC_X86_REG_GS: 'gs',
    UC_X86_REG_FS: 'fs',
    UC_X86_REG_SS: 'ss',
    UC_X86_REG_DS: 'ds',
    UC_X86_REG_ES: 'es'
}

REG_x86 = {
    UC_X86_REG_EAX: 'eax',
    UC_X86_REG_ECX: 'ecx',
    UC_X86_REG_EDX: 'edx',
    UC_X86_REG_EBX: 'ebx',
    UC_X86_REG_ESP: 'esp',
    UC_X86_REG_EBP: 'ebp',
    UC_X86_REG_ESI: 'esi',
    UC_X86_REG_EDI: 'edi',
    UC_X86_REG_EIP: 'eip',
    UC_X86_REG_EFLAGS: 'eflags',
    UC_X86_REG_CS: 'cs',
    UC_X86_REG_SS: 'ss',
    UC_X86_REG_DS: 'ds',
    UC_X86_REG_ES: 'es',
    UC_X86_REG_FS: 'fs',
    UC_X86_REG_GS: 'gs'
}

REG_x86_x64 = {
    UC_X86_REG_RAX: 'rax',
    UC_X86_REG_RBX: 'rbx',
    UC_X86_REG_RCX: 'rcx',
    UC_X86_REG_RDX: 'rdx',
    UC_X86_REG_RSI: 'rsi',
    UC_X86_REG_RDI: 'rdi',
    UC_X86_REG_RBP: 'rbp',
    UC_X86_REG_RSP: 'rsp',
    UC_X86_REG_R8: 'r8',
    UC_X86_REG_R9: 'r9',
    UC_X86_REG_R10: 'r10',
    UC_X86_REG_R11: 'r11',
    UC_X86_REG_R12: 'r12',
    UC_X86_REG_R13: 'r13',
    UC_X86_REG_R14: 'r14',
    UC_X86_REG_R15: 'r15',
    UC_X86_REG_RIP: 'rip',
    UC_X86_REG_EFLAGS: 'rflags',
    UC_X86_REG_CS: 'cs',
    UC_X86_REG_SS: 'ss',
    UC_X86_REG_DS: 'ds',
    UC_X86_REG_ES: 'es',
    UC_X86_REG_FS: 'fs',
    UC_X86_REG_GS: 'gs'
}

REG_MIPS = {
    UC_MIPS_REG_ZERO: '0',
    UC_MIPS_REG_AT: 'at',
    UC_MIPS_REG_V0: 'v0',
    UC_MIPS_REG_V1: 'v1',
    UC_MIPS_REG_A0: 'a0',
    UC_MIPS_REG_A1: 'a1',
    UC_MIPS_REG_A2: 'a2',
    UC_MIPS_REG_A3: 'a3',
    UC_MIPS_REG_T0: 't0',
    UC_MIPS_REG_T1: 't1',
    UC_MIPS_REG_T2: 't2',
    UC_MIPS_REG_T3: 't3',
    UC_MIPS_REG_T4: 't4',
    UC_MIPS_REG_T5: 't5',
    UC_MIPS_REG_T6: 't6',
    UC_MIPS_REG_T7: 't7',
    UC_MIPS_REG_S0: 's0',
    UC_MIPS_REG_S1: 's1',
    UC_MIPS_REG_S2: 's2',
    UC_MIPS_REG_S3: 's3',
    UC_MIPS_REG_S4: 's4',
    UC_MIPS_REG_S5: 's5',
    UC_MIPS_REG_S6: 's6',
    UC_MIPS_REG_S7: 's7',
    UC_MIPS_REG_T8: 't8',
    UC_MIPS_REG_T9: 't9',
    UC_MIPS_REG_K0: 'k0',
    UC_MIPS_REG_K1: 'k1',
    UC_MIPS_REG_GP: 'gp',
    UC_MIPS_REG_SP: 'sp',
    UC_MIPS_REG_S8: 's8',
    UC_MIPS_REG_RA: 'ra',
    UC_MIPS_REG_LO: 'lo',
    UC_MIPS_REG_HI: 'hi',
    UC_MIPS_REG_PC: 'pc'
}


BIT_SIZE_8 = 8
BIT_SIZE_16 = 16
BIT_SIZE_32 = 32
BIT_SIZE_64 = 64


ENDIAN_BIG = 'big'
ENDIAN_LITTLE = 'little'


UNICORN_PROC = {
    # processor : endian : size : variant

    ############################################################################
    # x86
    ############################################################################
    'i8086:el:16:default': {
        'processor': UC_ARCH_X86,
        'processor_mode': (UC_ARCH_X86, UC_MODE_16),
        'endian': ENDIAN_LITTLE,
        'size': BIT_SIZE_16,
        'variant': (),
        'registers': REG_8086,
        'program_counter': UC_X86_REG_IP,
    },
    'x86:el:32:default': {
        'processor': UC_ARCH_X86,
        'processor_mode': (UC_ARCH_X86, UC_MODE_32),
        'endian': ENDIAN_LITTLE,
        'size': BIT_SIZE_32,
        'variant': (),
        'registers': REG_x86,
        'program_counter': UC_X86_REG_EIP,
    },
    'x86:el:64:default': {
        'processor': UC_ARCH_X86,
        'processor_mode': (UC_ARCH_X86, UC_MODE_64),
        'endian': ENDIAN_LITTLE,
        'size': BIT_SIZE_32,
        'variant': (),
        'registers': REG_x86_x64,
        'program_counter': UC_X86_REG_RIP,
    },

    ############################################################################
    # ARM
    ############################################################################
    'arm:el:32:default': {
        'processor': UC_ARCH_ARM,
        'processor_mode': (UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_LITTLE_ENDIAN),
        'endian': ENDIAN_LITTLE,
        'size': BIT_SIZE_32,
        'variant': (),
        'registers': REG_ARM32,
        'program_counter': UC_ARM_REG_PC,
    },
    'arm:eb:32:default': {
        'processor': UC_ARCH_ARM,
        'processor_mode': (UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_BIG_ENDIAN),
        'endian': ENDIAN_BIG,
        'size': BIT_SIZE_32,
        'variant': (),
        'registers': REG_ARM32,
        'program_counter': UC_ARM_REG_PC,
    },
    'arm:el:32:926': {
        'processor': UC_ARCH_ARM,
        'processor_mode': (UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_LITTLE_ENDIAN),
        'endian': ENDIAN_LITTLE,
        'size': BIT_SIZE_32,
        'variant': (UC_MODE_ARM926,),
        'registers': REG_ARM32,
        'program_counter': UC_ARM_REG_PC,
    },
    'arm:eb:32:926': {
        'processor': UC_ARCH_ARM,
        'processor_mode': (UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_BIG_ENDIAN),
        'endian': ENDIAN_BIG,
        'size': BIT_SIZE_32,
        'variant': (UC_MODE_ARM926,),
        'registers': REG_ARM32,
        'program_counter': UC_ARM_REG_PC,
    },
    'arm:el:64:default': {
        'processor': UC_ARCH_ARM64,
        'processor_mode': (UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN),
        'endian': ENDIAN_LITTLE,
        'size': BIT_SIZE_64,
        'variant': (),
        'registers': REG_ARM64,
        'program_counter': UC_ARM64_REG_PC,
    },
    'arm:eb:64:default': {
        'processor': UC_ARCH_ARM64,
        'processor_mode': (UC_MODE_ARM, UC_MODE_BIG_ENDIAN),
        'endian': ENDIAN_BIG,
        'size': BIT_SIZE_64,
        'variant': (),
        'registers': REG_ARM64,
        'program_counter': UC_ARM64_REG_PC,
    },

    ############################################################################
    # MIPS
    ############################################################################
    'mips:el:32:default': {
        'processor': UC_ARCH_MIPS,
        'processor_mode': (UC_MODE_MIPS32, UC_MODE_LITTLE_ENDIAN),
        'endian': ENDIAN_LITTLE,
        'size': BIT_SIZE_32,
        'variant': (),
        'registers': REG_MIPS,
        'program_counter': UC_MIPS_REG_PC,
    },
    'mips:eb:32:default': {
        'processor': UC_ARCH_MIPS,
        'processor_mode': (UC_MODE_MIPS32, UC_MODE_BIG_ENDIAN),
        'endian': ENDIAN_BIG,
        'size': BIT_SIZE_32,
        'variant': (),
        'registers': REG_MIPS,
        'program_counter': UC_MIPS_REG_PC,
    },
    'mips:el:64:default': {
        'processor': UC_ARCH_MIPS,
        'processor_mode': (UC_MODE_MIPS64, UC_MODE_LITTLE_ENDIAN),
        'endian': ENDIAN_LITTLE,
        'size': BIT_SIZE_64,
        'variant': (),
        'registers': REG_MIPS,
        'program_counter': UC_MIPS_REG_PC,
    },
    'mips:eb:64:default': {
        'processor': UC_ARCH_MIPS,
        'processor_mode': (UC_MODE_MIPS64, UC_MODE_BIG_ENDIAN),
        'endian': ENDIAN_BIG,
        'size': BIT_SIZE_64,
        'variant': (),
        'registers': REG_MIPS,
        'program_counter': UC_MIPS_REG_PC,
    },

    ############################################################################
    # PPC
    ############################################################################
    'ppc:eb:32:default': {
        'processor': UC_ARCH_PPC,
        'processor_mode': (UC_MODE_PPC32, UC_MODE_BIG_ENDIAN),
        'endian': ENDIAN_BIG,
        'size': BIT_SIZE_32,
        'variant': (),
        'registers': None,
        'program_counter': None,
    },
    'ppc:eb:64:default': {
        'processor': UC_ARCH_PPC,
        'processor_mode': (UC_MODE_PPC64, UC_MODE_BIG_ENDIAN),
        'endian': ENDIAN_BIG,
        'size': BIT_SIZE_64,
        'variant': (),
        'registers': None,
        'program_counter': None,
    },

    ############################################################################
    # SPARC
    ############################################################################
    'sparc:eb:32:default': {
        'processor': UC_ARCH_SPARC,
        'processor_mode': (UC_MODE_SPARC32, UC_MODE_BIG_ENDIAN),
        'endian': ENDIAN_BIG,
        'size': BIT_SIZE_32,
        'variant': (),
        'registers': None,
        'program_counter': UC_SPARC_REG_PC,
    },
    'sparc:eb:64:default': {
        'processor': UC_ARCH_SPARC,
        'processor_mode': (UC_MODE_SPARC64, UC_MODE_BIG_ENDIAN),
        'endian': ENDIAN_BIG,
        'size': BIT_SIZE_64,
        'variant': (),
        'registers': None,
        'program_counter': UC_SPARC_REG_PC,
    },

    ############################################################################
    # m68k
    ############################################################################
    'm68k:eb:32:default': {
        'processor': UC_ARCH_M68K,
        'processor_mode': (UC_MODE_BIG_ENDIAN,),
        'endian': ENDIAN_BIG,
        'size': BIT_SIZE_32,
        'variant': (),
        'registers': None,
        'program_counter': UC_M68K_REG_PC,
    },
}


ARCH_MODE_MAP_PC_CODE = {
    UC_ARCH_ARM: UC_ARM_REG_PC,
    UC_ARCH_ARM64: UC_ARM64_REG_PC,
    UC_ARCH_MIPS: UC_MIPS_REG_PC,
    UC_ARCH_X86: UC_X86_REG_EIP,
    UC_ARCH_SPARC: UC_SPARC_REG_PC,
    UC_ARCH_M68K: UC_M68K_REG_PC,
}


class ArchUnicorn:
    @staticmethod
    def get_all_arch() -> List[str]:
        return list(UNICORN_PROC.keys())

    @staticmethod
    def get_mem_bit_size(arch: str) -> Literal[8, 16, 32, 64]:
        return UNICORN_PROC[arch]['size']

    @staticmethod
    def get_unicorn_arch_config(arch: str) -> Tuple[int, int]:
        proc = UNICORN_PROC[arch]['processor']
        all_modes = (UNICORN_PROC[arch]['processor_mode']
                     + UNICORN_PROC[arch]['variant'])
        proc_mode = 0

        for m in all_modes:
            proc_mode |= m

        return proc, proc_mode

    @staticmethod
    def get_unicorn_registers(arch_string: str) -> Dict[str, int]:
        return {v: k for k, v in UNICORN_PROC[arch_string]['registers'].items()}

    @staticmethod
    def get_unicorn_pc_code(unicorn_arch_code: int) -> int:
        return ARCH_MODE_MAP_PC_CODE[unicorn_arch_code]

    @classmethod
    def get_arch_str_by_uc(cls, uc: unicorn.Uc) -> Union[str, None]:
        for arch in UNICORN_PROC:
            proc, proc_mode = cls.get_unicorn_arch_config(arch)
            if proc & uc._arch and uc._mode == proc_mode:
                return arch

    @staticmethod
    def get_endian_by_uc(uc: unicorn.Uc) -> str:
        return ENDIAN_BIG if uc._mode & UC_MODE_BIG_ENDIAN else ENDIAN_LITTLE

    @classmethod
    def get_mem_bit_size_by_uc(cls, uc: unicorn.Uc) -> Literal[8, 16, 32, 64]:
        for arch in UNICORN_PROC:
            test_proc = UNICORN_PROC[arch]['processor']
            test_endian = UNICORN_PROC[arch]['endian']

            if test_proc & uc._arch and cls.get_endian_by_uc(uc) == test_endian:
                return UNICORN_PROC[arch]['size']

    @staticmethod
    def get_unicorn_endianness(unicorn_mode: int) -> str:
        return (ENDIAN_BIG if (unicorn_mode & UC_MODE_BIG_ENDIAN)
                else ENDIAN_LITTLE)

    @classmethod
    def get_generic_arch_str_by_uc(cls, uc: unicorn.Uc) -> Union[str, None]:
        for arch in UNICORN_PROC:
            test_proc = UNICORN_PROC[arch]['processor']
            test_endian = UNICORN_PROC[arch]['endian']

            if test_proc & uc._arch and cls.get_endian_by_uc(uc) == test_endian:
                cpu, endian, size, _ = arch.split(':')
                return f'{cpu}:{endian}:{size}'


class MemoryFormatter:
    def __init__(self, endian: Literal['big', 'little']):
        self._endian = '<' if endian == 'little' else '>'
        self._format_8 = f'{self._endian}B'
        self._format_16 = f'{self._endian}H'
        self._format_32 = f'{self._endian}I'
        self._format_64 = f'{self._endian}Q'


class MemoryReader(MemoryFormatter):
    def __init__(self, uc: unicorn.Uc, endian: Literal['big', 'little']):
        MemoryFormatter.__init__(self, endian)
        self._uc = uc
        self._int_reader = {
            8: self.read_uint8, 16: self.read_uint16, 32: self.read_uint32,
            64: self.read_uint64}

    def get_int_reader(self, bit_size) -> Callable:
        return self._int_reader[bit_size]

    def _read(self, address: int, size: int) -> int:
        return self._uc.mem_read(address, size)

    def read_uint8(self, address: int) -> int:
        return cast(
            int, struct.unpack(self._format_8, self._read(address, 1))[0])

    def read_uint16(self, address: int) -> int:
        return cast(
            int, struct.unpack(self._format_16, self._read(address, 2))[0])

    def read_uint32(self, address: int) -> int:
        return cast(
            int, struct.unpack(self._format_32, self._read(address, 4))[0])

    def read_uint64(self, address: int) -> int:
        return cast(
            int, struct.unpack(self._format_64, self._read(address, 8))[0])

    @staticmethod
    def get_field(x: int, bit_offset: int, bit_width: int) -> int:
        return (x >> bit_offset) & ((1 << bit_width) - 1)


class MemoryWriter(MemoryFormatter):
    def __init__(self, uc: unicorn.Uc, endian: Literal['big', 'little']):
        MemoryFormatter.__init__(self, endian)
        self._uc = uc
        self._int_reader = {
            8: self.write_uint8, 16: self.write_uint16, 32: self.write_uint32,
            64: self.write_uint64}

    def get_int_writer(self, bit_size) -> Callable:
        return self._int_reader[bit_size]

    def _write(self, address: int, data: bytes) -> None:
        return self._uc.mem_write(address, data)

    def write_uint8(self, address: int, value: int) -> None:
        self._write(address, struct.pack(self._format_8, value))

    def write_uint16(self, address: int, value: int) -> None:
        self._write(address, struct.pack(self._format_16, value))

    def write_uint32(self, address: int, value: int) -> None:
        self._write(address, struct.pack(self._format_32, value))

    def write_uint64(self, address: int, value: int) -> None:
        self._write(address, struct.pack(self._format_64, value))

    @staticmethod
    def set_field(x: int, value: int, bit_offset: int, bit_width: int) -> int:
        return (x & ~(((1 << bit_width) - 1) << bit_offset)) \
               | (value << bit_offset)


def _hook_code_fix_issue_972(a, b, c, d):
    pass

handler_hook_code_fix_issue_972: Union[int, None] = None

def unicorn_fix_issue_972(uc):
    """
    Dirty workaround to get correct PC value in memory access hook.
    This introduce a big overhead, since each instruction is hooked.
    See design bug, not solved in unicorn 2:
    - https://github.com/unicorn-engine/unicorn/pull/1257 : Fix issue with some memory hooks and PC register
    - https://github.com/unicorn-engine/unicorn/issues/972 : ARM - Wrong PC in data hook
    """
    global handler_hook_code_fix_issue_972

    if (_hook_code_fix_issue_972 not in [e[0] for e in uc._callbacks.values()]
            and handler_hook_code_fix_issue_972 is None):
        handler_hook_code_fix_issue_972 = \
            uc.hook_add(UC_HOOK_CODE, _hook_code_fix_issue_972, 0, 1)
