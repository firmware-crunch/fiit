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

from typing import TypedDict, Optional, Literal, List, Set, Callable
import dataclasses

from cmsis_svd.model import SVDRegister

from fiit.machine import DeviceCpu
from fiit.emunicorn import CpuUnicorn, unicorn_fix_issue_972

from .svd import SvdIndex
from .filter import MmioFilter


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


@dataclasses.dataclass
class WatchMemoryRange:
    begin: int
    end: int
    access: Literal['r', 'w', 'rw'] = 'rw'
    name: str = ''


@dataclasses.dataclass
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


class MmioInterceptor:
    def __init__(
        self,
        cpu: DeviceCpu,
        monitored_memory: MonitoredMemory,
        read_callbacks: List[Callable[[int, int, int], None]] = None,
        write_callbacks: List[Callable[[int, int, int, int], None]] = None,
        svd_read_callbacks: List[Callable[[int, int, int, SVDRegister], None]] = None,
        svd_write_callbacks: List[Callable[[int, int, int, int, SVDRegister], None]] = None,
        mmio_filters: dict = None,
        svd_index: SvdIndex = None
    ):
        self.cpu = cpu
        self.regs = cpu.regs
        self.mem = cpu.mem
        self.cpu_bytes = cpu.bits.value // 8

        self.monitored_memory = monitored_memory

        filter_conf = mmio_filters or {}
        self.filter = MmioFilter(**filter_conf, svd_index=svd_index)

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

        for mm_range in self.monitored_memory.ranges:
            self._install_hooks(mm_range.access, mm_range.begin, mm_range.end)

        for reg in self.monitored_memory.registers:
            self._install_hooks(reg.access, reg.address, reg.address)

        if isinstance(self.cpu, CpuUnicorn):
            # Dirty workaround to get correct PC value in memory access hook.
            # See design bug, not solved in unicorn 2:
            # - https://github.com/unicorn-engine/unicorn/pull/1257 :
            # Fix issue with some memory hooks and PC register
            # - https://github.com/unicorn-engine/unicorn/issues/972 :
            # ARM - Wrong PC in data hook
            unicorn_fix_issue_972(self.cpu.backend)

    def _install_hooks(
        self, access: Literal['r', 'w', 'rw'], begin: int, end: int
    ):
        for access_type in access:
            if access_type == 'r':
                self.cpu.hook_mem_read_range(
                    self._hook_read_wrapper, begin, end
                )

            elif access_type == 'w':
                self.cpu.hook_mem_write_range(
                    self._hook_write_wrapper, begin, end
                )

    def _hook_read_wrapper(
            self, _: DeviceCpu, address: int, size: int
    ) -> None:
        value = self.mem.read_int(address, size=self.cpu_bytes, signed=False)
        self._active_read_hook(address, self.regs.arch_pc, value)

    def _hook_write_wrapper(
        self, _: DeviceCpu, address: int, size: int, value: int
    ) -> None:
        previous = self.mem.read_int(address, size=self.cpu_bytes, signed=False)
        self._active_write_hook(address, self.regs.arch_pc, previous, value)

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

