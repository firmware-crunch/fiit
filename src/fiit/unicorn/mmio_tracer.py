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

import logging, tempfile, os, datetime
from random import randrange
from dataclasses import dataclass
from typing import (
    Dict, List, Set, Union, TypedDict, Optional, Literal, Callable, Any, cast,
    Tuple)

import seaborn

import plotext

from tabulate import tabulate

from cmsis_svd.model import SVDRegister, SVDField, SVDEnumeratedValue

import IPython
from IPython.core import magic
from IPython.core.magic_arguments import (
    argument, magic_arguments, parse_argstring)

from unicorn import Uc
from unicorn.unicorn_const import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE

from fiit.core.emulator_types import ADDRESS_FORMAT
from fiit.core.cmsis_svd import SvdIndex, SvdLoader
from fiit.core.shell import Shell
from .arch_unicorn import (
    ArchUnicorn, MemoryReader, unicorn_fix_issue_972)
from .dbg import UnicornDbg, DBG_EVENT_WATCHPOINT


###############################################################################
# MMIO
###############################################################################

class RegisterField:
    def __init__(self, bit_offset: int, bit_width: int):
        self.bit_offset = bit_offset
        self.bit_width = bit_width


def get_field(x: int, bit_offset: int, bit_width: int) -> int:
    return (x >> bit_offset) & ((1 << bit_width) - 1)


###############################################################################
# MMIO Access Filter
###############################################################################

CodeAddress = int
RegisterAddress = int

RegisterAddressFieldsMap = Dict[RegisterAddress, List[RegisterField]]

SvdPeripheralName = str
SvdRegisterName = str
SvdFieldName = str

SvdPeripheralRegisterTree = Dict[SvdPeripheralName, Set[SvdRegisterName]]
SvdPeripheralRegisterFieldTree = Dict[
    SvdPeripheralName, Dict[SvdRegisterName, Set[SvdFieldName]]]


class MmioFilter:
    # Numeric Filter expression
    exp_keep_addr_from = '(f in self._filter_keep_from_address)'

    exp_exclude_addr_from = '(f not in self._filter_exclude_from_address)'

    exp_keep_addr = '(a in self._filter_keep_address)'

    exp_exclude_addr = '(a not in self._filter_exclude_address)'

    exp_state_change = \
        '((c != n) ' \
        ' if a in self._filter_register_state_change ' \
        ' else True)'

    exp_field_change = \
        '(self._check_fields_change(c, n, fields)' \
        ' if (fields := self._filter_field_state_change.get(a)) ' \
        ' else True)'

    # SVD Filter Expression
    exp_svd_state_change = \
        '((c != n) ' \
        'if a in self._svd_filter_register_state_change ' \
        'else True)'

    exp_svd_field_change = \
        '(self._check_fields_change(c, n, fields) ' \
        ' if (fields := self._svd_filter_field_state_change.get(a)) ' \
        ' else True)'

    exp_check_svd_register_exist = \
        '(svd_register ' \
        'if (svd_register := self._svd_address_index.get(a)) ' \
        'else False)'

    def __init__(
            self,
            filter_keep_from_address: Set[CodeAddress] = None,
            filter_exclude_from_address: Set[CodeAddress] = None,

            filter_keep_address: Set[RegisterAddress] = None,
            filter_exclude_address: Set[RegisterAddress] = None,
            filter_register_state_change: Set[RegisterAddress] = None,
            filter_field_state_change: RegisterAddressFieldsMap = None,

            svd_filter_peripheral_keep: Set[SvdPeripheralName] = None,
            svd_filter_register_keep: SvdPeripheralRegisterTree = None,
            svd_filter_peripheral_exclude: Set[SvdPeripheralName] = None,
            svd_filter_register_exclude: SvdPeripheralRegisterTree = None,
            svd_filter_register_state_change: SvdPeripheralRegisterTree = None,
            svd_filter_field_state_change: SvdPeripheralRegisterFieldTree = None,

            svd_index: SvdIndex = None,
    ):
        ##########################################
        # Numeric Filters
        ##########################################
        self._filter_keep_from_address = set(filter_keep_from_address or [])
        self._filter_exclude_from_address = set(filter_exclude_from_address or [])
        self._filter_keep_address = set(filter_keep_address or [])
        self._filter_exclude_address = set(filter_exclude_address or [])
        self._filter_register_state_change = set(filter_register_state_change or [])
        self._filter_field_state_change = filter_field_state_change or {}

        self._read_predicate = None
        self._write_predicate = None

        self.build_numeric_filter()

        ##########################################
        # SVD Filters
        ##########################################
        self.svd_filter_peripheral_keep = svd_filter_peripheral_keep
        self.svd_filter_register_keep = svd_filter_register_keep
        self.svd_filter_peripheral_exclude = svd_filter_peripheral_exclude
        self.svd_filter_register_exclude = svd_filter_register_exclude
        self.svd_filter_register_state_change = svd_filter_register_state_change
        self.svd_filter_field_state_change = svd_filter_field_state_change
        self.svd_index = svd_index
        self._svd_read_predicate = None
        self._svd_write_predicate = None

        if self.svd_index:
            self._svd_address_index = self.svd_index.get_address_index()
            self._svd_filter_register_state_change: Set[int] = set()
            self._svd_filter_field_state_change: RegisterAddressFieldsMap = dict()
            self.build_svd_filters()

    def build_numeric_filter(self):
        r_filters, w_filters = [], []

        if self._filter_keep_from_address:
            r_filters.append(self.exp_keep_addr_from)
            w_filters.append(self.exp_keep_addr_from)
        if self._filter_exclude_from_address:
            r_filters.append(self.exp_exclude_addr_from)
            w_filters.append(self.exp_exclude_addr_from)
        if self._filter_keep_address:
            r_filters.append(self.exp_keep_addr)
            w_filters.append(self.exp_keep_addr)
        if self._filter_exclude_address:
            r_filters.append(self.exp_exclude_addr)
            w_filters.append(self.exp_exclude_addr)
        if self._filter_register_state_change:
            w_filters.append(self.exp_state_change)
        if self._filter_field_state_change:
            w_filters.append(self.exp_field_change)
        if r_filters:
            self._read_predicate = eval(f'lambda self, a, f, c: '
                                        f'{" and ".join(r_filters)}')
        else:
            self._read_predicate = eval(f'lambda self, a, f, c: True')

        if w_filters:
            self._write_predicate = eval(f'lambda self, a, f, c, n: '
                                         f'{" and ".join(w_filters)}')
        else:
            self._write_predicate = eval(f'lambda self, a, f, c, n: True')

    def build_svd_filters(self):
        if not self.svd_index or self.svd_index.get_register_count() == 0:
            self._svd_read_predicate = None
            self._svd_write_predicate = None
            return

        self._svd_address_index = self.svd_index.get_address_index()
        self._svd_filter_register_state_change = set()
        self._svd_filter_field_state_change = dict()

        svd_r_filter, svd_w_filter = list(), list()
        keep_addr, exclude_addr = set(), set()

        if self.svd_filter_peripheral_keep:
            for periph in self.svd_filter_peripheral_keep:
                keep_addr.update(
                    self.svd_index.get_all_peripheral_register_address(periph))

        if self.svd_filter_register_keep:
            for periph, regs in self.svd_filter_register_keep.items():
                for reg in regs:
                    keep_addr.add(self.svd_index.get_register_address(periph, reg))

        if keep_addr:
            for address in list(self._svd_address_index.keys()):
                if address not in keep_addr:
                    del self._svd_address_index[address]

        if self.svd_filter_peripheral_exclude:
            for periph in self.svd_filter_peripheral_exclude:
                exclude_addr.update(
                    self.svd_index.get_all_peripheral_register_address(periph))

        if self.svd_filter_register_exclude:
            for periph, regs in self.svd_filter_register_exclude.items():
                for reg in regs:
                    exclude_addr.add(
                        self.svd_index.get_register_address(periph, reg))

        if exclude_addr:
            for address in list(self._svd_address_index.keys()):
                if address in exclude_addr:
                    del self._svd_address_index[address]

        if self.svd_filter_register_state_change:
            svd_w_filter.append(self.exp_svd_state_change)
            for periph, regs in self.svd_filter_register_state_change.items():
                for reg in regs:
                    addr = self.svd_index.get_register_address(periph, reg)
                    self._svd_filter_register_state_change.add(addr)

        if self.svd_filter_field_state_change:
            svd_w_filter.append(self.exp_svd_field_change)
            for periph, regs_dict in self.svd_filter_field_state_change.items():
                for reg, fields in regs_dict.items():
                    svd_register = self.svd_index.get_svd_register(periph, reg)
                    self._svd_filter_field_state_change.setdefault(
                        svd_register.parent.base_address
                        + svd_register.address_offset, [])
                    for field in fields:
                        addr = svd_register.parent.base_address \
                               + svd_register.address_offset
                        svd_field = list(filter(lambda f: f.name == field,
                                                svd_register.fields))[0]
                        self._svd_filter_field_state_change[addr].append(svd_field)

        if self._filter_keep_from_address:
            svd_w_filter.append(self.exp_keep_addr_from)
            svd_r_filter.append(self.exp_keep_addr_from)

        if self._filter_exclude_from_address:
            svd_w_filter.append(self.exp_exclude_addr_from)
            svd_r_filter.append(self.exp_exclude_addr_from)

        svd_r_filter.append(self.exp_check_svd_register_exist)
        svd_w_filter.append(self.exp_check_svd_register_exist)

        self._svd_read_predicate = eval(f'lambda self, a, f, c: '
                                        f'{" and ".join(svd_r_filter)}')
        self._svd_write_predicate = eval(f'lambda self, a, f, c, n: '
                                         f'{" and ".join(svd_w_filter)}')

    def build_filters(self):
        self.build_numeric_filter()
        self.build_svd_filters()

    @staticmethod
    def _check_fields_change(
            current_state: int, new_state: int,
            svd_fields: Union[Set[RegisterField], Set[SVDRegister]]) -> bool:
        for field in svd_fields:
            if get_field(current_state, field.bit_offset, field.bit_width) \
                    != get_field(new_state, field.bit_offset, field.bit_width):
                return True
        return False

    def read_predicate(self, address: int, from_address: int,
                       current_state: int) -> bool:
        return self._read_predicate(self, address, from_address, current_state)

    def write_predicate(self, address: int, from_address: int,
                        current_state: int, new_state: int) -> bool:
        return self._write_predicate(
            self, address, from_address, current_state, new_state)

    def svd_read_predicate(self, address: int, from_address: int,
                           current_state: int) -> Union[SVDRegister, None]:
        return self._svd_read_predicate(
                self, address, from_address, current_state)

    def svd_write_predicate(self, address: int, from_address: int,
                            current_state: int, new_state: int
                            ) -> Union[SVDRegister, bool]:
        return self._svd_write_predicate(
                self, address, from_address, current_state, new_state)

    def svd_filter_is_active(self) -> bool:
        if (self._svd_read_predicate is not None
                and self._svd_write_predicate is not None):
            return True
        else:
            return False

    def exclude_from_address_add(self, addresses: List[int]):
        self._filter_exclude_from_address.update(addresses)


###############################################################################
# MMIO Monitored Memory
###############################################################################

class WatchMemoryRangeDict(TypedDict):
    begin: int
    end: int
    access: Optional[Literal['r', 'w', 'rw']]
    name: Optional[str]


class WatchRegisterDict(TypedDict):
    address: int
    access: Optional[Literal['r', 'w', 'rw']]
    name: Optional[str]


class WatchSvdPeripheralDict(TypedDict):
    svd_peripheral: str
    access: Optional[Literal['r', 'w', 'rw']]


class WatchSvdRegisterDict(TypedDict):
    svd_peripheral: str
    svd_register: str
    access: Optional[Literal['r', 'w', 'rw']]


@dataclass
class WatchMemoryRange:
    begin: int
    end: int
    access: Literal['r', 'w', 'rw'] = 'rw'
    name: str = ''


@dataclass
class WatchRegister:
    address: int
    access: Literal['r', 'w', 'rw'] = 'rw'
    name: str = ''


class MonitoredMemory:
    def __init__(
        self,
        register_bit_size: int,
        memory_ranges: List[WatchMemoryRangeDict] = None,
        registers: List[WatchRegisterDict] = None,
        svd_peripherals: List[WatchSvdPeripheralDict] = None,
        svd_registers: List[WatchSvdRegisterDict] = None,
        svd_index: SvdIndex = None
    ):

        self.ranges: List[WatchMemoryRange] = []
        self.registers: List[WatchRegister] = []
        self.svd_reg_addresses: Set[int] = set()
        self._register_bit_size = register_bit_size

        if memory_ranges:
            self.ranges.extend([WatchMemoryRange(**mr) for mr in memory_ranges])

        if registers:
            self.registers.extend([WatchRegister(**r) for r in registers])

        if svd_index:
            self.svd_reg_addresses = svd_index.get_all_register_address()
            self._add_svd_peripheral_memory(svd_peripherals or [], svd_index)
            self._add_svd_register(svd_registers or [], svd_index)

        self._register_unicity_check()
        self._registers_and_ranges_overlap_check()
        self._ranges_overlap_check()

    def _add_svd_register(
        self, svd_registers: List[WatchSvdRegisterDict], svd_index: SvdIndex
    ):
        for register in svd_registers:
            svd_reg = svd_index.get_svd_register(
                register['svd_peripheral'], register['svd_register'])
            svd_periph = svd_index.get_svd_peripheral(
                register['svd_peripheral'])
            self.registers.append(WatchRegister(
                # svd_reg.parent.base_address + svd_reg.address_offset,
                svd_periph.base_address + svd_reg.address_offset,
                register['access'], register['svd_peripheral']))

    def _add_svd_peripheral_memory(
        self,
        svd_peripherals: List[WatchSvdPeripheralDict],
        svd_index: SvdIndex
    ):
        for periph in svd_peripherals:
            addresses = sorted(
                svd_index.get_all_peripheral_register_address(periph['svd_peripheral']))
            if len(addresses):
                # Get register size from SVD data can be not safe
                # end = addresses[-1] + (svd_register.bit_size // 8)
                # svd_register = \
                # svd_index.get_svd_register_by_address(addresses[-1])
                begin = addresses[0]
                end = addresses[-1] + self._register_bit_size // 8
                self.ranges.append(
                    WatchMemoryRange(begin, end, periph['access'],
                                     periph['svd_peripheral']))

    def _register_unicity_check(self):
        for register_i in self.registers:
            for register_j in self.registers:
                if register_i.address == register_j.address \
                        and id(register_i) != id(register_j):
                    raise ValueError(
                        f'Monitored register {register_i.address:#x} '
                        f'({register_i.name}) is duplicates with monitored '
                        f'register {register_j.address:#x} ({register_j.name}).'
                    )

    def _registers_and_ranges_overlap_check(self):
        for register in self.registers:
            for mm_range in self.ranges:
                if mm_range.begin <= register.address <= mm_range.end:
                    raise ValueError(
                        f'Monitored register at {register.address:#x} '
                        f'({register.name}) overlaps monitored memory range '
                        f'[{mm_range.begin:#x}-{mm_range.end:#x}] '
                        f'({mm_range.name})')

    def _ranges_overlap_check(self):
        self.ranges.sort(key=lambda x: x.begin)
        for i in range(1, len(self.ranges)):
            if self.ranges[i-1].end > self.ranges[i].begin:
                raise ValueError(
                    f'Monitored memory range [{self.ranges[i-1].begin:#x}-'
                    f'{self.ranges[i-1].end:#x}] ({self.ranges[i-1].name}) '
                    f'overlaps range [{self.ranges[i].begin:#x}-'
                    f'{self.ranges[i].end:#x}] ({self.ranges[i].name}).')


###############################################################################
# MMIO Interceptor
###############################################################################

class MmioInterceptor:
    def __init__(
        self,
        uc: Uc,
        monitored_memory: MonitoredMemory,
        read_callbacks: List[Callable[[int, int, int], None]] = None,
        write_callbacks: List[Callable[[int, int, int, int], None]] = None,
        svd_read_callbacks: List[Callable[[int, int, int, SVDRegister], None]] = None,
        svd_write_callbacks: List[Callable[[int, int, int, int, SVDRegister], None]] = None,
        mmio_filters: dict = None,
        svd_index: SvdIndex = None
    ):
        ########################################################################
        # Architecture Configuration
        ########################################################################
        self._uc = uc
        self._pc_code = ArchUnicorn.get_unicorn_pc_code(self._uc._arch)
        endian = ArchUnicorn.get_endian_by_uc(uc)
        self._register_bit_size = ArchUnicorn.get_mem_bit_size_by_uc(self._uc)
        self._mmio_reader = MemoryReader(self._uc, endian).get_int_reader(
                self._register_bit_size)

        ########################################################################
        # Monitored Memory
        ########################################################################
        self.monitored_memory = monitored_memory

        ########################################################################
        # Filter
        ########################################################################
        filter_conf = mmio_filters or {}
        self.filter = MmioFilter(**filter_conf, svd_index=svd_index)

        ########################################################################
        # Internal Hook Definitions
        ########################################################################
        self._read_callbacks = read_callbacks or list()
        self._write_callbacks = write_callbacks or list()
        self._svd_read_callbacks = svd_read_callbacks or list()
        self._svd_write_callbacks = svd_write_callbacks or list()

        if self.filter.svd_filter_is_active():
            self._active_read_hook = self._hook_svd_read
            self._active_write_hook = self._hook_svd_write
        else:
            self._active_read_hook = self._hook_read_filter
            self._active_write_hook = self._hook_write_filter


        #######################################################################
        # Hook Installation
        #######################################################################
        for mm_range in self.monitored_memory.ranges:
            self._install_hooks(mm_range.access, mm_range.begin, mm_range.end)

        for reg in self.monitored_memory.registers:
            self._install_hooks(reg.access, reg.address, reg.address)

        # Dirty workaround to get correct PC value in memory access hook.
        # See design bug, not solved in unicorn 2:
        # - https://github.com/unicorn-engine/unicorn/pull/1257 :
        # Fix issue with some memory hooks and PC register
        # - https://github.com/unicorn-engine/unicorn/issues/972 :
        # ARM - Wrong PC in data hook
        unicorn_fix_issue_972(self._uc)

    def _install_hooks(
        self, access: Literal['r', 'w', 'rw'], begin: int, end: int
    ):
        for access_type in access:
            if access_type == 'r':
                self._uc.hook_add(UC_HOOK_MEM_READ, self._hook_read_wrapper,
                                  begin=begin, end=end)
            elif access_type == 'w':
                self._uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_write_wrapper,
                                  begin=begin, end=end)

    def _hook_read_wrapper(self, uc: Uc, access: int, address: int, size: int,
                           value: int, current_run: Any):
        # Workaround: mmio read because unicorn pass 0 as value
        self._active_read_hook(address, self._uc.reg_read(self._pc_code),
                               self._mmio_reader(address))

    def _hook_write_wrapper(
        self, uc: Uc, access: int, address: int, size: int, value: int, run: Any
    ):
        self._active_write_hook(address, self._uc.reg_read(self._pc_code),
                                self._mmio_reader(address), value)

    def _hook_svd_read(self, address: int, pc: int, state: int):
        if reg := self.filter.svd_read_predicate(address, pc, state):
            for cb in self._svd_read_callbacks:
                cb(address, pc, state, reg)
        elif address not in self.monitored_memory.svd_reg_addresses:
            for cb in self._read_callbacks:
                cb(address, pc, state)

    def _hook_svd_write(self, address: int, pc: int, state: int, new_state: int):
        if reg := self.filter.svd_write_predicate(address, pc, state, new_state):
            for cb in self._svd_write_callbacks:
                cb(address, pc, state, new_state, reg)
        elif address not in self.monitored_memory.svd_reg_addresses:
            for cb in self._write_callbacks:
                cb(address, pc, state, new_state)

    def _hook_read_filter(self, address: int, pc: int, state: int):
        if self.filter.read_predicate(address, pc, state):
            for cb in self._read_callbacks:
                cb(address, pc, state)

    def _hook_write_filter(
        self, address: int, pc: int, state: int, new_state: int
    ):
        if self.filter.write_predicate(address, pc, state, new_state):
            for cb in self._write_callbacks:
                cb(address, pc, state, new_state)


################################################################################
# MMIO Logger
################################################################################

class MmioLogger:
    def __init__(
        self,
        mem_bit_size: int,
        monitored_memory: MonitoredMemory,
        logger_name: str,
        log_show_field_states: bool = True,
    ):
        self._py_log = logging.getLogger(logger_name)
        self._log_show_field_states = log_show_field_states

        reg_bit_size = mem_bit_size
        self._mmio_addr_f = ADDRESS_FORMAT[reg_bit_size]
        self._mem_addr_f = ADDRESS_FORMAT[reg_bit_size]
        self._monitored_memory = monitored_memory

    def _format_mem_area_name(self, address: int) -> str:
        for mem_range in self._monitored_memory.ranges:
            if mem_range.begin <= address <= mem_range.end:
                return mem_range.name
        return '-'

    def format_read_access(self, address: int, pc: int, state: int) -> str:
        return (
            f'{self._format_mem_area_name(address)}'
            f' : access read at {self._mem_addr_f(address)}'
            f' from {self._mem_addr_f(pc)}'
            f' : {self._mmio_addr_f(state)}')

    def log_read_access(self, address: int, pc: int, state: int):
        self._py_log.info(self.format_read_access(address, pc, state))

    def format_write_access(
        self, address: int, pc: int, state: int, new_state: int
    ) -> str:
        return (
            f'{self._format_mem_area_name(address)}'
            f' : access write at {self._mem_addr_f(address)}'
            f' from {self._mem_addr_f(pc)}'
            f' : {self._mmio_addr_f(state)}'
            f' -> {self._mmio_addr_f(new_state)}')

    def log_write_access(
        self, address: int, pc: int, state: int, new_state: int
    ):
        self._py_log.info(self.format_write_access(address, pc, state, new_state))

    @staticmethod
    def _get_info_field_state(
        state: int, reg: SVDRegister
    ) -> List[Tuple[SVDField, int, str, str]]:
        field_states_info = []

        for field in reg.fields:
            field_state = get_field(state, field.bit_offset, field.bit_width)
            state_name = ''
            state_desc = ''

            for enum_val in cast(SVDField, field).enumerated_values:
                enum_val = cast(SVDEnumeratedValue, enum_val)
                if enum_val.value == field_state:
                    state_name = enum_val.name
                    state_desc = enum_val.description

            field_states_info.append(
                (field, field_state, state_name, state_desc))

        return field_states_info

    @classmethod
    def _get_info_field_states_read(cls, state: int, reg: SVDRegister) -> str:
        field_states_info = []
        state_info = cls._get_info_field_state(state, reg)

        for field, field_state, state_name, state_desc in state_info:
            field_states_info.append(
                f'{reg.parent.name or "-"}'
                f' : {reg.name or "-"} '
                f' : [{field.bit_offset}'
                f':{field.bit_offset + field.bit_width - 1}]'
                f' : {field.name or "-"} ({field.description or "-"})'
                f' : {state_name or "-"} ({state_desc or "-"})'
                f' : {field_state:#x}')

        return '\n'.join(field_states_info)

    @classmethod
    def _get_info_field_states_write(
        cls, state: int, new_state: int, reg: SVDRegister
    ) -> str:
        field_states_info = []
        state_info = cls._get_info_field_state(new_state, reg)

        for field, field_state, state_name, state_desc in state_info:
            previous_state = get_field(state, field.bit_offset, field.bit_width)

            log_value_field = (
                f'{previous_state:#x} -> {field_state:#x} (field value change)'
                if previous_state != field_state
                else f'{field_state:#x}')

            field_states_info.append(
                f'{reg.parent.name or "-"}'
                f' : {reg.name or "-"} '
                f' : [{field.bit_offset}'
                f':{field.bit_offset + field.bit_width - 1}]'
                f' : {field.name or "-"} ({field.description or "-"})'
                f' : {state_name or "-"} ({state_desc or "-"})'
                f' : {log_value_field}')

        return '\n'.join(field_states_info)

    def format_svd_read_access(
        self, address: int, pc: int, state: int, reg: SVDRegister
    ) -> str:
        state_info = (f'\n{self._get_info_field_states_read(state, reg)}'
                      if self._log_show_field_states else '')

        return (
            f'{reg.parent.name or "-"}'
            f' : {reg.name or "-"} '
            f' : {reg.description or "-"}'
            f' : access read at {self._mem_addr_f(address)} '
            f' from {self._mem_addr_f(pc)}'
            f' : {self._mmio_addr_f(state)}{state_info}')

    def log_svd_read_access(
        self, address: int, pc: int, state: int, reg: SVDRegister
    ):
        self._py_log.info(self.format_svd_read_access(address, pc, state, reg))

    def format_svd_write_access(
        self, address: int, pc: int, state: int, new_state: int, reg: SVDRegister
    ) -> str:
        state_info = (
            f'\n{self._get_info_field_states_write(state, new_state, reg)}'
            if self._log_show_field_states else '')

        log_value_field = (
            f'{self._mmio_addr_f(state)} '
            f'-> {self._mmio_addr_f(new_state)}{state_info} (register value change)'
            if state != new_state else
            f'{self._mmio_addr_f(state)}')

        return (
            f'{reg.parent.name or "-"}'
            f' : {reg.name or "-"} '
            f' : {reg.description or "-"}'
            f' : access write at {self._mem_addr_f(address)} '
            f' from {self._mem_addr_f(pc)}'
            f' : {log_value_field}')

    def log_svd_write_access(
        self, address: int, pc: int, state: int, new_state: int, reg: SVDRegister
    ):
        self._py_log.info(self.format_svd_write_access(
            address, pc, state, new_state, reg))


################################################################################
# MMIO Tracer
################################################################################

@dataclass
class MmioAccessCount:
    address: int
    svd: Optional[SVDRegister] = None
    read: int = 0
    write: int = 0
    change: int = 0


class MmioTraceAccessCount:
    def __init__(self):
        self._raw_counter: Dict[int, MmioAccessCount] = dict()
        self._svd_counter: Dict[str, Dict[str, MmioAccessCount]] = dict()

    def inc_raw_counter_read(self, address: int):
        self._raw_counter.setdefault(address, MmioAccessCount(address)).read += 1

    def inc_raw_counter_write(self, address: int):
        self._raw_counter.setdefault(address, MmioAccessCount(address)).write += 1

    def inc_raw_counter_change(self, address: int):
        self._raw_counter.setdefault(address, MmioAccessCount(address)).change += 1

    def _get_svd_counter(self, reg: SVDRegister) -> MmioAccessCount:
        periph = self._svd_counter.setdefault(reg.parent.name, dict())
        counter = MmioAccessCount(
            reg.parent.base_address+reg.address_offset, svd=reg)
        return periph.setdefault(reg.name, counter)

    def inc_svd_counter_read(self, reg: SVDRegister):
        self._get_svd_counter(reg).read += 1

    def inc_svd_counter_write(self, reg: SVDRegister):
        self._get_svd_counter(reg).write += 1

    def inc_svd_counter_change(self, reg: SVDRegister):
        self._get_svd_counter(reg).change += 1

    def reg_count(self):
        count = len(self._raw_counter)
        for periph_name in self._svd_counter:
            count += len(self._svd_counter[periph_name])
        return count

    def periph_count(self) -> int:
        return len(self._svd_counter)

    def get_all_registers(self) -> List[Union[int, SVDRegister]]:
        all_reg = list()

        for periph_name in self._svd_counter:
            for reg_name in self._svd_counter[periph_name]:
                all_reg.append(self._svd_counter[periph_name][reg_name].svd)

        all_reg += list(self._raw_counter.keys())
        return all_reg

    def get_all_peripherals(self) -> List[str]:
        return list(self._svd_counter.keys())

    def get_all_counters(self):
        all_counter: List[MmioAccessCount] = list()

        for periph_name in self._svd_counter:
            for reg_name in self._svd_counter[periph_name]:
                all_counter.append(self._svd_counter[periph_name][reg_name])

        all_counter.extend(list(self._raw_counter.values()))
        return all_counter


@dataclass
class MmioReadRecord:
    address: int
    pc: int
    state: int
    svd: Optional[SVDRegister] = None


@dataclass
class MmioWriteRecord:
    address: int
    pc: int
    state: int
    new_state: int
    svd: Optional[SVDRegister] = None


class MmioDataTrace:
    """ """
    def __init__(self):
        self.access_count = MmioTraceAccessCount()
        self.access_timeline: List[Union[MmioReadRecord, MmioWriteRecord]] = list()

    def record_read_access(self, address: int, pc: int, state: int):
        self.access_count.inc_raw_counter_read(address)
        self.access_timeline.append(MmioReadRecord(address, pc, state))

    def record_write_access(
        self, address: int, pc: int, state: int, new_state: int
    ):
        if state != new_state:
            self.access_count.inc_raw_counter_change(address)
        else:
            self.access_count.inc_raw_counter_write(address)

        self.access_timeline.append(
            MmioWriteRecord(address, pc, state, new_state))

    def record_svd_read_access(
        self, address: int, pc: int, state: int, reg: SVDRegister
    ):
        self.access_count.inc_svd_counter_read(reg)
        self.access_timeline.append(MmioReadRecord(address, pc, state, reg))

    def record_svd_write_access(
        self, address: int, pc: int, state: int, new_state: int, reg: SVDRegister
    ):
        if state != new_state:
            self.access_count.inc_svd_counter_change(reg)
        else:
            self.access_count.inc_svd_counter_write(reg)

        self.access_timeline.append(
            MmioWriteRecord(address, pc, state, new_state, reg))

    def mmio_access_count(self) -> int:
        return len(self.access_timeline)

    def mmio_access_stats_to_str(self, multi_bar=False) -> str:
        all_regs = list()
        change_percent = list()
        write_percent = list()
        read_percent = list()

        for counter in self.access_count.get_all_counters():
            if counter.svd is not None:
                all_regs.append(f'{counter.svd.parent.name}:{counter.svd.name}')
                change_percent.append(counter.change)
                write_percent.append(counter.write)
                read_percent.append(counter.read)

        plotext.clear_data()
        plot_args = (all_regs, [read_percent, write_percent, change_percent])
        plot_kwargs = dict(
            width=150, labels=['read', 'write', 'write with change'],
            title='MMIO Access Statistics')

        if len(all_regs) == 0:
            return ''
        elif not multi_bar:
            plotext.simple_stacked_bar(*plot_args, **plot_kwargs)
        elif multi_bar:
            plotext.simple_multiple_bar(*plot_args, **plot_kwargs)

        return plotext.build()

    @staticmethod
    def _color_generator(
        nb: int, color_style: str
    ) -> List[Tuple[int, int, int]]:
        color_conv = lambda x: round(min(max(x, 0.0), 1.0) * 255)

        if color_style == 'hls' or color_style == 'husl':
            colors = [
                (color_conv(c[0]), color_conv(c[1]), color_conv(c[2]))
                for c in seaborn.color_palette(color_style, nb)]
        else:
            colors = list()
            for i in range(0, nb):
                while True:
                    gen_color = (randrange(255), randrange(255), randrange(255))
                    if gen_color not in colors:
                        colors.append(gen_color)
                        break

        return colors

    def mmio_access_timeline_to_str(
        self, start: int = 0, count: int = 0, access_by_line: int = 20,
        color: str = 'hls', output: str = 'term'
    ) -> str:
        legend = dict()
        legend_buff = []
        color_access_buff = [f'\n  {start:06}-']
        rgb_f_term = '\033[48;2;{};{};{}m {} \033[0m'
        rgb_f_html = ('<data style="background-color:rgb({}, {}, {}); '
                      'border-color: black; border-width: 1px; '
                      'border-style: solid;">{}</data>')
        rgb_f = rgb_f_term if output == 'term' else rgb_f_html
        end = None if count == 0 else start+count
        time_slice = self.access_timeline[start:end]

        if len(time_slice) == 0:
            return ''

        legend_keys = []
        for access_data in time_slice:
            if access_data.svd is not None:
                legend_keys.append(f'{access_data.svd.parent.name}'
                                   f':{access_data.svd.name}')
            else:
                legend_keys.append(f'0x{access_data.address:x}')

        colors = self._color_generator(self.access_count.periph_count(), color)

        r_id = 0
        for idx, periph_name in enumerate(self.access_count.get_all_peripherals()):
            for reg in self.access_count.get_all_registers():
                if isinstance(reg, SVDRegister) and reg.parent.name == periph_name:
                    r_id += 1
                    legend[f'{reg.parent.name}:{reg.name}'] = [colors[idx], r_id]

        for idx, access_data in enumerate(time_slice):
            if access_data.svd is not None:
                svd_key = f'{access_data.svd.parent.name}:{access_data.svd.name}'
                reg_id = f'{legend[svd_key][1]:03}'
                col = legend[svd_key][0]
            else:
                reg_id = f'{legend[access_data.address][1]:03}'
                col = legend[access_data.address][0]

            if isinstance(access_data, MmioReadRecord):
                access_str = 'r'
            elif (isinstance(access_data, MmioWriteRecord)
                    and access_data.state != access_data.new_state):
                access_str = 'c'
            else:
                access_str = 'w'

            color_access_buff.append(rgb_f.format(col[0], col[1], col[2],
                                                  f'{reg_id}-{access_str}'))

            if (idx+1) % (access_by_line*5) == 0:
                color_access_buff.append(f'\n  {start+idx+1:06}-')
            elif (idx+1) % access_by_line == 0:
                color_access_buff.append('\n         ')

        previous_color = None
        legend_item_by_line = 0
        for idx, reg_key in enumerate(legend):
            color_cur = legend[reg_key][0]

            if idx == 0:
               previous_color = color_cur

            if (isinstance(reg_key, str)
                    and (legend_item_by_line % 4 == 0
                         or color_cur != previous_color)):
                legend_item_by_line = 0
                endline = '\n\n' if color_cur != previous_color else '\n'
                legend_buff.append(endline)
            elif isinstance(reg_key, int) and legend_item_by_line % 4 == 0:
                legend_buff.append('\n')

            name = f'0x{reg_key:x}' if isinstance(reg_key, int) else reg_key

            if name not in legend_keys:
                continue

            color_code = rgb_f.format(
                *color_cur, f'{legend[reg_key][1]:03}')
            legend_buff.append(f'[{name} {color_code}]  ')

            previous_color = color_cur
            legend_item_by_line += 1

        out = (
            f'\n{len(self.access_timeline)} MMIO Access\n\n'
            f'{"".join(color_access_buff)}\n\n{"".join(legend_buff)}')

        if output == 'html':
            out = f'<pre>\n{out}\n</pre>'
            str_date = "{:%y-%m-%d-%H-%M-%S}".format(datetime.datetime.now())
            out_path = f'{tempfile.gettempdir()}{os.path.sep}{str_date}' \
                       f'-mmio_access_timeline_to_str.html'
            with open(out_path, 'w') as f:
                f.write(out)
            out = f'\n\nMMIO access timeline save to {out_path}.\n\n'

        return out

    def mmio_access_locations_data(self):
        locations = dict()

        for record in self.access_timeline:
            # This key is used to identify location access because different
            # MMIO register can be accessed from the same code address.
            key = f'{record.pc:#x}:{record.address:#x}'

            if key in locations:
                continue

            access_from = record.pc
            mmio_addr = record.address
            svd_name = (f'{record.svd.parent.name}:{record.svd.name}'
                        if record.svd is not None else None)
            access_type = 'w' if isinstance(record, MmioWriteRecord) else 'r'

            locations.update(
                {key: [access_from, mmio_addr, svd_name, access_type]})

        loc = list(locations.values())
        loc =  sorted(loc, key=lambda access_loc_info: access_loc_info[1])
        return loc

    def mmio_access_locations(self):
        return {record.pc for record in self.access_timeline}

    def mmio_access_registers(self):
        registers = {}
        for record in self.access_timeline:
            if record.address not in registers:
                svd_name = (f'{record.svd.parent.name}:{record.svd.name}'
                            if record.svd is not None else None)
                registers.update({record.address: (record.address, svd_name)})
        registers = list(registers.values())
        registers = sorted(registers, key=lambda r: r[0])
        return registers


class UnicornMmioTracer:
    LOGGER_NAME = 'fiit.unicorn_mmio_tracer'

    def __init__(
        self,
        uc: Uc,
        monitored_memory: Dict,
        mmio_filters: Dict = None,
        svd_resource: str = None,
        trace_data: bool = True,
        log: bool = False,
        log_show_field_states: bool = True
    ):
        ########################################################################
        # SVD Data
        ########################################################################
        svd_dev = SvdLoader().load(svd_resource) if svd_resource else None
        svd_index = SvdIndex(svd_dev) if svd_dev else None

        ########################################################################
        # Monitored Memory
        ########################################################################
        self.mem_bit_size = ArchUnicorn.get_mem_bit_size_by_uc(uc)
        self._monitored_memory = MonitoredMemory(
            self.mem_bit_size, **monitored_memory, svd_index=svd_index)

        ########################################################################
        # Logging
        ########################################################################
        mmio_logger = MmioLogger(
            self.mem_bit_size, self._monitored_memory, self.LOGGER_NAME,
            log_show_field_states)

        ########################################################################
        # Data Trace
        ########################################################################
        self.mmio_data_trace = MmioDataTrace()

        ########################################################################
        # Memory Access Callbacks
        ########################################################################
        self._read_callbacks = list()
        self._write_callbacks = list()
        self._svd_read_callbacks = list()
        self._svd_write_callbacks = list()
        self._log_callbacks = list()

        if trace_data:
            self._read_callbacks.append(self.mmio_data_trace.record_read_access)
            self._write_callbacks.append(self.mmio_data_trace.record_write_access)
            self._svd_read_callbacks.append(self.mmio_data_trace.record_svd_read_access)
            self._svd_write_callbacks.append(self.mmio_data_trace.record_svd_write_access)

        if log:
            self._read_callbacks.append(mmio_logger.log_read_access)
            self._write_callbacks.append(mmio_logger.log_write_access)
            self._svd_read_callbacks.append(mmio_logger.log_svd_read_access)
            self._svd_write_callbacks.append(mmio_logger.log_svd_write_access)

        ########################################################################
        # Memory Access Interceptor
        ########################################################################
        MmioInterceptor(
            uc,
            self._monitored_memory,
            self._read_callbacks,
            self._write_callbacks,
            self._svd_read_callbacks,
            self._svd_write_callbacks,
            mmio_filters=mmio_filters,
            svd_index=svd_index)


@IPython.core.magic.magics_class
class UnicornMmioTracerFrontend(IPython.core.magic.Magics):
    def __init__(self, mmio_tracer: UnicornMmioTracer, shell: Shell):
        self._mmio_mon = mmio_tracer
        super(UnicornMmioTracerFrontend, self).__init__(shell=shell.shell)
        self._shell = shell
        self._shell.register_magics(self)
        self._shell.register_aliases(self)

    @IPython.core.magic.line_magic
    def mmio_access_count(self, line: str):
        print(f'{self._mmio_mon.mmio_data_trace.mmio_access_count()}')

    @magic_arguments()
    @argument('--multi-bar', nargs='?', choices=['true', 'false'],
              const='true', default='false')
    @IPython.core.magic.line_magic
    def mmio_access_stats(self, line: str):
        """ Print MMIO access statistics as read, write, write with change"""
        kwargs = parse_argstring(self.mmio_access_stats, line)
        multi_bar = True if kwargs.multi_bar == 'true' else False
        print(self._mmio_mon.mmio_data_trace.mmio_access_stats_to_str(multi_bar))

    @magic_arguments()
    @argument('--start', nargs='?', type=int, const=0, default=0,
              help='Start the MMIO access timeline at specific offset.')
    @argument('--count', nargs='?', type=int, const=0, default=0,
              help='Number of access to include.')
    @argument('--access-by-line', nargs='?', type=int, const=20, default=20,
              help='Number of MMIO access by line.')
    @argument('--color', nargs='?', choices=['hls', 'husl', 'rand'],
              const='hls', default='hls', help='Cell colorization style.')
    @argument('--output', nargs='?', choices=['term', 'html'],
              const='term', default='term', help='Output type.')
    @IPython.core.magic.line_magic
    def mmio_access_timeline(self, line: str):
        """Print MMIO access timeline"""
        kwargs = vars(parse_argstring(self.mmio_access_timeline, line))
        print(self._mmio_mon.mmio_data_trace.mmio_access_timeline_to_str(**kwargs))

    @IPython.core.magic.line_magic
    def mmio_access_locations_info(self, line: str):
        """Display MMIO access location."""
        addr_f = ADDRESS_FORMAT[self._mmio_mon.mem_bit_size]
        table_cell = self._mmio_mon.mmio_data_trace.mmio_access_locations_data()
        table_cell = list(table_cell)
        for cell in table_cell:
            cell[0] = addr_f(cell[0])
            cell[1] = addr_f(cell[1])

        print(f'\n {len(self._mmio_mon.mmio_data_trace.mmio_access_registers())} '
              f'MMIO registers accessed from '
              f'{len(self._mmio_mon.mmio_data_trace.mmio_access_locations())} '
              f'code locations.\n')

        print(tabulate(
            table_cell, ['Access From', 'MMIO Address', 'Name', 'Access'],
            tablefmt='simple'))

    @IPython.core.magic.line_magic
    def mmio_access_locations_count(self, line: str):
        """Display MMIO access location number."""
        print(len(self._mmio_mon.mmio_data_trace.mmio_access_locations()))


class UnicornMmioDbg:
    LOGGER_NAME = 'fiit.unicorn_mmio_dbg'

    def __init__(
        self,
        dbg: UnicornDbg,
        monitored_memory: Dict,
        mmio_filters: Dict = None,
        svd_resource: str = None,
    ):
        self._dbg = dbg
        ########################################################################
        # SVD Data
        ########################################################################
        svd_dev = SvdLoader().load(svd_resource) if svd_resource else None
        svd_index = SvdIndex(svd_dev) if svd_dev else None

        ########################################################################
        # Monitored Memory
        ########################################################################
        self.mem_bit_size = ArchUnicorn.get_mem_bit_size_by_uc(self._dbg.uc)

        self._monitored_memory = MonitoredMemory(
            self.mem_bit_size, **monitored_memory, svd_index=svd_index)

        ########################################################################
        # Logging
        ########################################################################
        self.mmio_logger = MmioLogger(
            self.mem_bit_size, self._monitored_memory, self.LOGGER_NAME, True)

        ########################################################################
        # Memory Access Interceptor
        ########################################################################
        self.mmio_interceptor = MmioInterceptor(
            self._dbg.uc,
            self._monitored_memory,
            [self._read_callback],
            [self._write_callback],
            [self._svd_read_callback],
            [self._svd_write_callback],
            mmio_filters=mmio_filters,
            svd_index=svd_index)

    def _read_callback(self, address: int, pc: int, state: int):
        out = self.mmio_logger.format_read_access(address, pc, state)
        print(f'\n\nunicorn_mmio_dbg: {out}\n')
        self._dbg.debug_event_callback(
            DBG_EVENT_WATCHPOINT, {'address': pc, 'data': {'stdout': out}})

    def _write_callback(self, address: int, pc: int, state: int, new_state: int):
        out = self.mmio_logger.format_write_access(address, pc, state, new_state)
        print(f'\n\nunicorn_mmio_dbg: {out}\n')
        self._dbg.debug_event_callback(
            DBG_EVENT_WATCHPOINT, {'address': pc, 'data': {'stdout': out}})

    def _svd_read_callback(
        self, address: int, pc: int, state: int, reg: SVDRegister
    ):
        out = self.mmio_logger.format_svd_read_access(address, pc, state, reg)
        print(f'\n\nunicorn_mmio_dbg: {out}\n')
        self._dbg.debug_event_callback(
            DBG_EVENT_WATCHPOINT, {'address': pc, 'data': {'stdout': out}})

    def _svd_write_callback(
        self, address: int, pc: int, state: int, new_state: int, reg: SVDRegister
    ):
        out = self.mmio_logger.format_svd_write_access(address, pc, state,
                                                       new_state, reg)
        print(f'\n\nunicorn_mmio_dbg: {out}\n')
        self._dbg.debug_event_callback(
            DBG_EVENT_WATCHPOINT, {'address': pc, 'data': {'stdout': out}})


@IPython.core.magic.magics_class
class UnicornMmioDbgFrontend(IPython.core.magic.Magics):
    def __init__(self, mmio_dbg: UnicornMmioDbg, shell: Shell):
        self._mmio_dbg = mmio_dbg
        super(UnicornMmioDbgFrontend, self).__init__(shell=shell.shell)
        self._shell = shell
        self._shell.register_magics(self)
        self._shell.register_aliases(self)

    @magic_arguments()
    @argument('--exclude-from-address', nargs='*', default=[],
              help='Exclude MMIO access interception from this code location.')
    @IPython.core.magic.line_magic
    def mmio_dbg_filter(self, line: str):
        kwargs = parse_argstring(self.mmio_dbg_filter, line)
        self._mmio_dbg.mmio_interceptor.filter.exclude_from_address_add(
            [int(a, 16) for a in kwargs.exclude_from_address])
        self._mmio_dbg.mmio_interceptor.filter.build_filters()
