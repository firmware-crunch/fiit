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

from typing import List, Any, Literal, Dict, Callable
from collections import OrderedDict
import logging
import dataclasses

from unicorn import Uc
from unicorn.unicorn_const import (
    UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_WRITE,
    UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_MEM_WRITE_UNMAPPED, UC_MEM_READ_UNMAPPED, UC_MEM_FETCH_UNMAPPED
)

from ..emu.arch_unicorn import ArchUnicorn
from ..emu.emu_types import ADDRESS_FORMAT

from .dis_capstone import DisassemblerCapstone, CAPSTONE_CONFIG


@dataclasses.dataclass
class Breakpoint:
    address: int
    count: int
    hit_count: int = 0


@dataclasses.dataclass
class Watchpoint:
    begin: int
    end: int
    access: str
    count: int = 0
    hit_count: int = 0


DBG_EVENT_SEGFAULT = 1
DBG_EVENT_BREAKPOINT = 2
DBG_EVENT_WATCHPOINT = 3
DBG_EVENT_STEP = 4



class Debugger:
    LOGGER_NAME = 'fiit.dbg'

    def __init__(self, uc: Uc, debug_event_callback: Callable = None):
        self._logger = logging.getLogger(self.LOGGER_NAME)

        ############################
        # Emulation settings
        ############################
        self.uc = uc
        self.arch = ArchUnicorn.get_arch_str_by_uc(self.uc)
        self.mem_bit_size = ArchUnicorn.get_mem_bit_size(self.arch)
        self.endiannes = ArchUnicorn.get_unicorn_endianness(self.uc._mode)
        self.cpu_reg = ArchUnicorn.get_unicorn_registers(self.arch)
        self.pc_code = ArchUnicorn.get_unicorn_pc_code(self.uc._arch)

        ############################
        # Debugger hook settings
        ############################
        self.uc.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED
            | UC_HOOK_MEM_WRITE_UNMAPPED
            | UC_HOOK_MEM_FETCH_UNMAPPED,
            self._hook_segfault)

        self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                         self._hook_watchpoint)

        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)

        ############################
        # Disassembler
        ############################
        cpu, size, endian, _ = self.arch.split(':')

        if self.arch in CAPSTONE_CONFIG:
            dis_arch_str = self.arch
        else:
            dis_arch_str = f'{cpu}:{size}:{endian}:default'

        self._disassembler = DisassemblerCapstone(dis_arch_str)

        ############################
        # Breakpoint
        ############################
        self._step_ins_flag = False
        self._breakpoints: OrderedDict[int, Breakpoint] = OrderedDict()

        ############################
        # Watchpoint
        ############################
        self._watchpoints: OrderedDict[str, Watchpoint] = OrderedDict()

        ############################
        # Debugger event callback
        ############################
        self.debug_event_callbacks: List[Callable] = []

        if debug_event_callback:
            self.debug_event_callbacks.append(debug_event_callback)

        ############################
        # Debugger frontend
        ############################
        self._addr_f = ADDRESS_FORMAT[self.mem_bit_size]

    def get_cpu_register(self, register: int) -> int:
        return self.uc.reg_read(register)

    def get_cpu_registers(self, registers: List[str] = None) -> Dict[str, int]:
        regs = registers if registers else self.cpu_reg
        return {r: self.get_cpu_register(self.cpu_reg[r]) for r in regs}

    def set_cpu_register(self, register: str, value: int) -> None:
        self.uc.reg_write(self.cpu_reg[register], value)

    def get_pc(self) -> int:
        return self.get_cpu_register(self.pc_code)

    def debug_event_callback(self, event_id: int, args: dict):
        for callback in self.debug_event_callbacks:
            callback(self, event_id, args)

    def _hook_segfault(self, uc: Uc, access: int, address: int, size: int,
                       value: int, user_data: Any):
        if access == UC_MEM_FETCH_UNMAPPED:
            self._logger.info(f'Invalid memory fetch to {self._addr_f(address)}')
        elif access in [UC_MEM_WRITE_UNMAPPED, UC_MEM_READ_UNMAPPED]:
            access_str = 'write' if access == UC_MEM_WRITE_UNMAPPED else 'read'
            self._logger.info(f'Invalid memory access {access_str} from '
                              f'{self._addr_f(self.get_pc())} to '
                              f'{self._addr_f(address)}')

        self.debug_event_callback(DBG_EVENT_SEGFAULT, {'address': address})

    def _hook_code(self, uc: Uc, address: int, size: int, user_data: Any):
        if address in self._breakpoints or self._step_ins_flag:
            if self._step_ins_flag:
                self._step_ins_flag = False
                event = DBG_EVENT_STEP
                self._logger.info(f'step instruction at {self._addr_f(address)}')

            if address in self._breakpoints:
                bp = self._breakpoints[address]
                bp.hit_count += 1
                event = DBG_EVENT_BREAKPOINT
                self._logger.info(f'Breakpoint at {self._addr_f(address)}, '
                                  f'hit {bp.hit_count}')

                if bp.count > 0 and bp.count == bp.hit_count:
                    self.breakpoint_del(address)

            self.debug_event_callback(event, {'address': address})

    def breakpoint_set(self, address: int, count=0):
        if address not in self._breakpoints:
            self._breakpoints.update({address: Breakpoint(address, count)})

    def breakpoint_del(self, address: int):
        self._breakpoints.pop(address)

    def breakpoint_del_by_index(self, idx: int):
        address = list(self._breakpoints.keys())[idx - 1]
        self.breakpoint_del(address)

    def set_step(self):
        self._step_ins_flag = True

    def _hook_watchpoint(
        self, uc: Uc, access: int, address: int, size: int, value: int,
        current_run: Any
    ):
        for area, wp in self._watchpoints.items():
            access_type = 'w' if access == UC_MEM_WRITE else 'r'
            if wp.begin >= address <= wp.end and access_type in wp.access:
                pc = self.get_pc()
                wp.hit_count += 1
                begin, end = area.split(':')
                access_str = 'write' if access == UC_MEM_WRITE else 'read'
                self._logger.info(
                    f'watchpoint at {self._addr_f(address)}, '
                    f'area [{self._addr_f(int(begin))}'
                    f'-{self._addr_f(int(end))}], '
                    f'hit {wp.hit_count}, '
                    f'access {access_str} from {self._addr_f(pc)}')
                meta = {'address': address, 'pc_address': pc,
                        'access': access_type, 'size': size}
                self.debug_event_callback(DBG_EVENT_WATCHPOINT, meta)

                if wp.count > 0 and wp.count == wp.hit_count:
                    self.watchpoint_del(area)

    def watchpoint_set(self, begin: int, end: int,
                       access: Literal['r', 'w', 'rw'], count=0):
        if end < begin:
            raise ValueError('Invalid Watch Memory area (begin < end).')

        if (area := f'{begin}:{end}') not in self._watchpoints:
            wp = Watchpoint(begin, end, access, count)
            self._watchpoints.update({area: wp})

    def watchpoint_del_by_index(self, idx: int):
        self.watchpoint_del(list(self._watchpoints.keys())[idx - 1])

    def watchpoint_del(self, area: str):
        self._watchpoints.pop(area)

    def disassemble(self, address: int, count: int) -> List[str]:
        mm = list(filter(
            lambda x: x[0] <= address < x[1], self.uc.mem_regions()))

        if len(mm) == 1:
            mm = mm[0]
            chunk_size = (mm[1]-mm[0]) - 1 - (address - mm[0])
            code = self.uc.mem_read(address, chunk_size)
            return self._disassembler.disassemble_mem_range(
                code, address, count)
        else:
            raise ValueError(f'Fail to disassemble at {address}, not mapped.')
