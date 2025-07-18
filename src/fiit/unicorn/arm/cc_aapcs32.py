################################################################################
#
# Copyright 2022-2025 Vincent Dary
#
# This file is part of fiit.
#
# fiit is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# fiit is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# fiit. If not, see <https://www.gnu.org/licenses/>.
#
################################################################################

import struct
import ctypes
from typing import Type, cast, List, Dict, Union

from unicorn import Uc
from unicorn.unicorn_const import UC_MODE_BIG_ENDIAN
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
    UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9,
    UC_ARM_REG_R10, UC_ARM_REG_FP, UC_ARM_REG_IP, UC_ARM_REG_SP, UC_ARM_REG_LR,
    UC_ARM_REG_PC, UC_ARM_REG_CPSR,
    UC_ARM_REG_S0, UC_ARM_REG_S1, UC_ARM_REG_S2, UC_ARM_REG_S3, UC_ARM_REG_S4,
    UC_ARM_REG_S5, UC_ARM_REG_S6, UC_ARM_REG_S7, UC_ARM_REG_S8, UC_ARM_REG_S9,
    UC_ARM_REG_S10, UC_ARM_REG_S11, UC_ARM_REG_S12, UC_ARM_REG_S13,
    UC_ARM_REG_S14, UC_ARM_REG_S15,
    UC_ARM_REG_D0, UC_ARM_REG_D1, UC_ARM_REG_D2, UC_ARM_REG_D3, UC_ARM_REG_D4,
    UC_ARM_REG_D5, UC_ARM_REG_D6, UC_ARM_REG_D7)

from ..arch_unicorn import ArchUnicorn
from fiit.core.ctypes import configure_ctypes
from fiit.core.ctypes.ctypes_base import (
    CBaseType, FunctionSpec, Struct, Float, Double, IntegralType,
    FundBaseType, ArgSpec)
from fiit.core.ctypes.arch_arm import Fp16
from fiit.core.cc_base import (
    CallingConvention, CpuContext, FuncArg, ReturnValue)


class CallingConventionARM(CallingConvention):
    NAME = 'aapcs32'
    REGS = {
        'r0': UC_ARM_REG_R0, 'r1': UC_ARM_REG_R1, 'r2': UC_ARM_REG_R2,
        'r3': UC_ARM_REG_R3, 'r4': UC_ARM_REG_R4, 'r5': UC_ARM_REG_R5,
        'r6': UC_ARM_REG_R6, 'r7': UC_ARM_REG_R7, 'r8': UC_ARM_REG_R8,
        'r9': UC_ARM_REG_R9, 'r10': UC_ARM_REG_R10, 'r11': UC_ARM_REG_FP,
        'r12': UC_ARM_REG_IP, 'sp': UC_ARM_REG_SP, 'lr': UC_ARM_REG_LR,
        'pc': UC_ARM_REG_PC, 'cpsr': UC_ARM_REG_CPSR,

        'S0': UC_ARM_REG_S0, 'S1': UC_ARM_REG_S1, 'S2': UC_ARM_REG_S2,
        'S3': UC_ARM_REG_S3, 'S4': UC_ARM_REG_S4, 'S5': UC_ARM_REG_S5,
        'S6': UC_ARM_REG_S6, 'S7': UC_ARM_REG_S7, 'S8': UC_ARM_REG_S8,
        'S9': UC_ARM_REG_S9, 'S10': UC_ARM_REG_S10, 'S11': UC_ARM_REG_S11,
        'S12': UC_ARM_REG_S12, 'S13': UC_ARM_REG_S13, 'S14': UC_ARM_REG_S14,
        'S15': UC_ARM_REG_S15,

        'D0': UC_ARM_REG_D0, 'D1': UC_ARM_REG_D1, 'D2': UC_ARM_REG_D2,
        'D3': UC_ARM_REG_D3, 'D4': UC_ARM_REG_D4, 'D5': UC_ARM_REG_D5,
        'D6': UC_ARM_REG_D6, 'D7': UC_ARM_REG_D7
    }

    def __init__(
        self,
        uc: Uc,
        ctypes_options: Dict[str, str] = None,
        hard_fp: bool = False
    ):
        self._uc = uc

        self._is_big_endian = uc._mode & UC_MODE_BIG_ENDIAN
        self._type_code_int32_str = '>I' if self._is_big_endian else '<I'
        self._type_code_int64 = '>Q' if self._is_big_endian else '<Q'

        self._hard_fp = hard_fp

        self._ncrn = 0
        self._sp = 0
        self._nsaa = 0

        self._vfp_s_alloc: List[int] = []

        ########################################################################
        # C Types
        ########################################################################
        configure_ctypes(
            ArchUnicorn.get_generic_arch_str_by_uc(uc),
            [globals()],
            ctypes_options)

    def _read_reg(self, reg: str) -> bytes:
        return struct.pack(self._type_code_int32_str,
                           self._uc.reg_read(self.REGS[reg]))

    def _write_reg(self, reg: str, value: bytes):
        self._uc.reg_write(self.REGS[reg],
                           struct.unpack(self._type_code_int32_str, value)[0])

    def _read_reg_64(self, reg: str) -> bytes:
        return struct.pack(self._type_code_int64,
                           self._uc.reg_read(self.REGS[reg]))

    def _write_reg_64(self, reg: str, value: bytes):
        self._uc.reg_write(self.REGS[reg],
                           struct.unpack(self._type_code_int64, value)[0])

    def get_return_address(self) -> int:
        return self._uc.reg_read(self.REGS['lr'])

    def set_pc(self, address: int):
        self._uc.reg_write(self.REGS['pc'], address)

    def get_cpu_context(self) -> CpuContext:
        cpu_context = CpuContext()
        for str_reg, const_reg in self.REGS.items():
            setattr(cpu_context, str_reg, self._uc.reg_read(const_reg))
        return cpu_context

    def _is_aggregate_vfp_cprc(self, aggregate: Type[Struct]) \
            -> Union[Type[Fp16], Type[Float], Type[Double], None]:
        if len(aggregate._fields_) > 0:
            base_type = None
            for _, field_type in aggregate._fields_:
                if issubclass(field_type, Struct):
                    field_type = cast(Type[Struct], field_type)
                    field_type = self._is_aggregate_vfp_cprc(field_type)
                if field_type not in [Fp16, Float, Double]:
                    return None
                if not base_type:
                    base_type = field_type
                if field_type != base_type:
                    return None
            if ctypes.sizeof(aggregate) // ctypes.sizeof(base_type) > 4:
                return None
            return base_type
        # FIXME : return None not checked

    def _is_vfp_cprc(self, arg_type: Type[CBaseType]) \
            -> Union[Type[CBaseType], None]:
        """Argument type is VFP co-processor Register Candidate (CPRC)."""
        if arg_type in [Fp16, Float, Double]:
            return arg_type
        elif issubclass(arg_type, Struct):
            return self._is_aggregate_vfp_cprc(arg_type)

    def _alloc_vfp_regs(self, base_type: Type[CBaseType], arg_type_size: int):
        if base_type in [Fp16, Float]:
            reg_count, slot_count = 16, arg_type_size//ctypes.sizeof(base_type)
        elif base_type == Double:
            reg_count, slot_count = 8, arg_type_size//8
        else:
            raise ValueError('VFP alloc fail due to unsupported type.')

        for i in range(0, reg_count):
            alloc_regs, format_regs = [], []
            for j in range(i, i + slot_count):
                if base_type in [Float, Fp16]:
                    if j in self._vfp_s_alloc:
                        break
                    alloc_regs.append(j)
                    format_regs.append(f'S{j}')
                elif base_type == Double:
                    sreg_part1 = j * 2
                    sreg_part2 = sreg_part1 + 1
                    if (sreg_part1 in self._vfp_s_alloc
                            or sreg_part2 in self._vfp_s_alloc):
                        break
                    alloc_regs.extend((sreg_part1, sreg_part2))
                    format_regs.append(f'D{j}')

            if len(format_regs) == slot_count:
                for reg_id in alloc_regs:
                    self._vfp_s_alloc.append(reg_id)
                return format_regs

    def _stage_a(self, spec: FunctionSpec):
        """ Stage A: Initialization """
        self._ncrn = 0                                  # A.1

        if self._hard_fp and not spec.is_variadic:      # A.2.vfp
            self._vfp_s_alloc = []

        self._sp = self._uc.reg_read(self.REGS['sp'])
        self._nsaa = self._sp                           # A.3

        # A.4: Only if composite type higher than 4 bytes. (6.4 Result Return)
        if ((spec.return_value_type
             and issubclass(spec.return_value_type, Struct))
                and (ctypes.sizeof(spec.return_value_type) > 4)):
            self._ncrn = 1

    @staticmethod
    def _stage_b(spec: FunctionSpec):
        """ Stage B: Pre-padding and extension of arguments
         skipped rules:
         - B.1 : handle before at prototype declaration.
         - B.5 : implemented in argument spec
        """
        for arg in spec.arguments:
            rounded_size = arg.size

            if issubclass(arg.type, IntegralType) and arg.size < 4:        # B.2
                rounded_size = 4
            elif issubclass(arg.type, Fp16):
                rounded_size = 4
            elif issubclass(arg.type, Struct):                             # B.4
                mod = rounded_size % 4
                if mod > 0:
                    rounded_size += 4 - mod

            arg.word_size = rounded_size // 4

    def _read_stack_arg(self, type_size: int, align: int, word_size: int) \
            -> bytes:
        if align == 8:                                                     # C.7
            self._nsaa = ((self._nsaa + 7) // 8) * 8
        else:
            self._nsaa = ((self._nsaa + 3) // 4) * 4

        value = self._uc.mem_read(self._nsaa, word_size * 4)               # C.8
        self._nsaa += type_size
        return bytes(value)

    def _stage_c_read(self, spec: FunctionSpec) -> List[FuncArg]:
        """ Stage C: Assignment of arguments to registers and stack """
        args = []
        for arg_idx, arg in enumerate(spec.arguments):
            values = []

            if (self._hard_fp and not spec.is_variadic
                    and (base_type := self._is_vfp_cprc(arg.type))):
                if regs := self._alloc_vfp_regs(base_type, arg.size):  # C.1.vfp
                    for reg_str in regs:
                        if reg_str.startswith('S'):
                            values.append(self._read_reg(reg_str))
                        elif reg_str.startswith('D'):
                            values.append(self._read_reg_64(reg_str))
                else:                                                  # C.2.vfp
                    values.append(self._read_stack_arg(
                        arg.size, arg.align, arg.word_size)[:arg.size])
            else:
                if arg.align == 8:                                         # C.3
                    self._ncrn = ((self._ncrn + 1) // 2) * 2
                    # ncrn = (ncrn + 1) & -2

                if arg.word_size <= (4 - self._ncrn):                      # C.4
                    for i in range(0, arg.word_size):
                        values.append(self._read_reg(f'r{self._ncrn}'))
                        self._ncrn += 1
                elif self._ncrn < 4 and self._nsaa == self._sp:            # C.5
                    for i in range(0, arg.word_size):
                        if self._ncrn < 4:
                            values.append(self._read_reg(f'r{self._ncrn}'))
                            self._ncrn += 1
                        else:
                            values.append(
                                self._uc.mem_read(self._nsaa,
                                                  (arg.word_size-i)*4))
                            break
                else:   # C.7 , C.8
                    values.append(
                        self._read_stack_arg(arg.size, arg.align,
                                             arg.word_size))

            if((issubclass(arg.type, Fp16) and not self._hard_fp
                    and self._nsaa != self._sp)):                      # see B.2
                value = arg.type.from_buffer_copy(b''.join(values)[:arg.size])
            else:
                if self._is_big_endian and issubclass(arg.type, FundBaseType):
                    bytes_value = b''.join(values)[-arg.size:]
                else:
                    bytes_value = b''.join(values)[:arg.size]
                value = arg.type.from_buffer_copy(bytes_value)

            args.append(FuncArg(arg_idx, value, spec, self.set_arguments,
                                arg.name))
        return args

    def _write_stack_arg(self, arg_type: ArgSpec, value: Union[bytes, None]):
        if arg_type.align == 8:                                            # C.7
            self._nsaa = ((self._nsaa + 7) // 8) * 8
        else:
            self._nsaa = ((self._nsaa + 3) // 4) * 4

        if value:
            if (arg_type.size < 4 and self._is_big_endian
                    and not issubclass(arg_type.type, Fp16)):
                addr_to_w = self._nsaa + (4 - arg_type.size)
            else:
                addr_to_w = self._nsaa

            self._uc.mem_write(addr_to_w, value)                           # C.8

        self._nsaa += arg_type.size

    def _fp16_pad(self, fp16: bytes) -> bytes:
        # Todo factoring with _pad()
        if self._is_big_endian:
            return b'\x00\x00' + fp16
        else:
            return fp16 + b'\x00\x00'

    def _pad(self, value: bytes, value_type: Type[CBaseType]) -> bytes:
        pad = b'\x00' * (4 - len(value))
        if not self._is_big_endian or issubclass(value_type, Struct):
            return value + pad
        else:
            return pad + value

    def _stage_c_write(self, spec: FunctionSpec,
                       arg_values: Dict[int, CBaseType]) -> int:
        for arg_idx, arg in enumerate(spec.arguments):
            arg_value = arg_values.get(arg_idx)
            raw_value = arg_value._raw_ if arg_value else None

            if (self._hard_fp and not spec.is_variadic
                    and (base_type := self._is_vfp_cprc(arg.type))):
                if regs := self._alloc_vfp_regs(base_type, arg.size):  # C.1.vfp
                    if raw_value:
                        base_type_size = ctypes.sizeof(base_type)
                        for i, reg_str in enumerate(regs):
                            offset = base_type_size*i
                            v_part = raw_value[offset:offset+base_type_size]
                            if reg_str.startswith('S'):
                                if issubclass(base_type, Fp16):
                                    v_part = self._fp16_pad(v_part)
                                self._write_reg(reg_str,  v_part)
                            elif reg_str.startswith('D'):
                                self._write_reg_64(reg_str, v_part)
                else:                                                  # C.2.vfp
                    self._write_stack_arg(arg, raw_value)
            else:
                if arg.align == 8:                                         # C.3
                    self._ncrn = ((self._ncrn + 1) // 2) * 2
                    # ncrn = (ncrn + 1) & -2

                if arg.word_size <= (4 - self._ncrn):                      # C.4
                    for i in range(0, arg.word_size):
                        if raw_value:
                            off = 4 * i
                            to_w = raw_value[off:off+4]
                            if len(to_w) < 4:
                                if issubclass(arg.type, Fp16):
                                    to_w = self._fp16_pad(to_w)
                                else:
                                    to_w = self._pad(to_w, arg.type)
                            self._write_reg(f'r{self._ncrn}', to_w)
                        self._ncrn += 1
                elif self._ncrn < 4 and self._nsaa == self._sp:            # C.5
                    for i in range(0, arg.word_size):
                        if self._ncrn < 4:
                            if raw_value:
                                off = 4 * i
                                to_w = raw_value[off:off + 4]
                                # Due to C.4 word size is necessary > 4
                                # so len(to_w) can't be <4
                                # if len(to_w) < 4:
                                #     if issubclass(arg.type, Fp16):
                                #         to_w = self._fp16_pad(to_w)
                                #     else:
                                #         to_w = self._pad(to_w, arg.type)
                                self._write_reg(f'r{self._ncrn}', to_w)
                            self._ncrn += 1
                        else:
                            if raw_value:
                                self._uc.mem_write(self._nsaa, raw_value[4*i:])
                            self._nsaa += 4 * (arg.word_size - i)
                            break

                else:   # C.7 , C.8
                    self._write_stack_arg(arg, raw_value)
        return self._nsaa

    def get_arguments(self, spec: FunctionSpec) -> List[FuncArg]:
        if not spec.arguments:
            return []
        self._stage_a(spec)
        self._stage_b(spec)
        return self._stage_c_read(spec)

    def set_arguments(self, spec: FunctionSpec,
                      arg_values: Dict[int, CBaseType]):
        if not spec.arguments:
            return
        self._stage_a(spec)
        self._stage_b(spec)
        self._stage_c_write(spec, arg_values)

    def call(self, spec: FunctionSpec, arg_values: Dict[int, CBaseType]) \
            -> Union[CBaseType, None]:
        """ experimental """
        context = self._uc.context_save()

        # Get needed stack space
        self._stage_a(spec)
        self._stage_b(spec)
        nsaa = self._stage_c_write(spec, {})

        # Set stack space for function arguments
        sp = self._uc.reg_read(UC_ARM_REG_SP)

        new_stack = (sp - (nsaa - sp))
        if new_stack % 8 != 0:
            new_stack -= 8 - (new_stack % 8)

        self._uc.reg_write(UC_ARM_REG_SP, new_stack)

        # Write function arguments
        self._stage_a(spec)
        self._stage_b(spec)
        self._stage_c_write(spec, arg_values)

        # Subroutine call
        pc = self._uc.reg_read(UC_ARM_REG_PC)
        cpsr_t = (self._uc.reg_read(UC_ARM_REG_CPSR) >> 5) & 1
        self._uc.reg_write(UC_ARM_REG_LR, pc | cpsr_t)
        self._uc.reg_write(UC_ARM_REG_PC, spec.address)

        # Evict current block from qemu cache to catch function return address
        # in the nested emulation
        self._uc.ctl_remove_cache(pc, pc + 4)

        self._uc.emu_start(spec.address, pc)

        if ret_value := self.get_return_value(spec):
            ret = ret_value.value
        else:
            ret = None

        self._uc.context_restore(context)

        return ret

    def get_return_value(self, spec: FunctionSpec) -> Union[ReturnValue, None]:
        if spec.return_value_type is None:
            return None

        value = b''
        type_size = ctypes.sizeof(spec.return_value_type)

        if (self._hard_fp and not spec.is_variadic
                and (base_type := self._is_vfp_cprc(spec.return_value_type))):
            base_type_size = ctypes.sizeof(base_type)
            nb_slots = type_size // base_type_size
            values = []
            for i in range(0, nb_slots):
                if base_type == Double:
                    v_part = self._read_reg_64(f'D{i}')
                else:
                    v_part = self._read_reg(f'S{i}')
                    if self._is_big_endian:  # FPp16
                        v_part = v_part[-base_type_size:]
                    else:
                        v_part = v_part[:base_type_size]
                values.append(v_part)
            value = b''.join(values)
        elif issubclass(spec.return_value_type, FundBaseType) and type_size <= 4:
            value = self._read_reg('r0')
            if self._is_big_endian:
                value = value[-type_size:]
        elif issubclass(spec.return_value_type, FundBaseType) and type_size == 8:
            value = b''.join([self._read_reg('r0'), self._read_reg('r1')])
        elif issubclass(spec.return_value_type, Struct) and type_size <= 4:
            value = self._read_reg('r0')[:type_size]

        return ReturnValue(spec.return_value_type.from_buffer_copy(value),
                           spec, self.set_return_value)

    def set_return_value(self, spec: FunctionSpec, value: CBaseType):
        if spec.return_value_type is None:
            return

        type_size = ctypes.sizeof(spec.return_value_type)
        raw_value = value._raw_

        if (self._hard_fp and not spec.is_variadic
                and (base_type := self._is_vfp_cprc(spec.return_value_type))):
            base_type_size = ctypes.sizeof(base_type)
            nb_slots = type_size // base_type_size
            for i in range(0, nb_slots):
                offset = base_type_size * i
                v_part = raw_value[offset:offset+base_type_size]
                if base_type == Double:
                    self._write_reg_64(f'D{i}', v_part)
                else:
                    if issubclass(base_type, Fp16):
                        v_part = self._fp16_pad(v_part)
                    self._write_reg(f'S{i}', v_part)
        elif issubclass(spec.return_value_type, FundBaseType) and type_size <= 4:
            if issubclass(spec.return_value_type, Fp16):
                to_w = self._fp16_pad(raw_value)
            else:
                pad = b'\x00' * (4 - len(raw_value))
                if self._is_big_endian:
                    to_w = pad + raw_value
                else:
                    to_w = raw_value + pad
            self._write_reg('r0', to_w)
        elif issubclass(spec.return_value_type, FundBaseType) and type_size == 8:
            self._write_reg('r0', raw_value[:4])
            self._write_reg('r1', raw_value[4:8])
        elif issubclass(spec.return_value_type, Struct) and type_size <= 4:
            # TODO factorize
            self._write_reg('r0', raw_value + (b'\x00' * (4 - len(raw_value))))
