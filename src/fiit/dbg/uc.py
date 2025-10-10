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

__all__ = [
    'DebuggerUnicorn'
]

from collections import OrderedDict
from typing import List, Any, Literal, Optional

import unicorn
from unicorn.unicorn_const import (
    UC_HOOK_CODE,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_MEM_WRITE,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_MEM_WRITE_UNMAPPED,
    UC_MEM_READ_UNMAPPED,
    UC_MEM_FETCH_UNMAPPED
)

from ..machine import DeviceCpu
from ..emunicorn import CpuUnicorn

from .dbg import (
    Debugger,
    Breakpoint,
    Watchpoint,
    DBG_EVENT_SEGFAULT,
    DBG_EVENT_BREAKPOINT,
    DBG_EVENT_WATCHPOINT,
    DBG_EVENT_STEP,
    DebugEventCallback
)

# ==============================================================================-


class DebuggerUnicorn(Debugger):

    CPU_CLASS = CpuUnicorn

    def __init__(
        self,
        cpu: DeviceCpu,
        event_callback: Optional[DebugEventCallback] = None
    ):
        assert isinstance(cpu.cpu, CpuUnicorn)
        assert isinstance(cpu.backend, unicorn.Uc)
        Debugger.__init__(self, cpu, event_callback)

        uc = cpu.backend
        uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._hook_watchpoint)
        uc.hook_add(UC_HOOK_CODE, self._hook_code)
        uc.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED
            | UC_HOOK_MEM_WRITE_UNMAPPED
            | UC_HOOK_MEM_FETCH_UNMAPPED,
            self._hook_segfault
        )

        self._step_ins_flag: bool = False
        self._breakpoints: OrderedDict[int, Breakpoint] = OrderedDict()
        self._watchpoints: OrderedDict[str, Watchpoint] = OrderedDict()

    def _hook_segfault(
        self,
        _: unicorn.Uc,
        access: int,
        address: int,
        size: int,
        value: int,
        user_data: Any
    ) -> None:
        if access == UC_MEM_FETCH_UNMAPPED:
            self._logger.info(
                f'invalid memory fetch to '
                f'{self.mem.addr_to_str(address)}'
            )

        elif access in [UC_MEM_WRITE_UNMAPPED, UC_MEM_READ_UNMAPPED]:
            access_str = 'write' if access == UC_MEM_WRITE_UNMAPPED else 'read'
            self._logger.info(
                f'invalid memory access {access_str} from '
                f'{self.mem.addr_to_str(self.regs.arch_pc)} to '
                f'{self.mem.addr_to_str(address)}'
            )

        self.debug_event_callback(DBG_EVENT_SEGFAULT, {'address': address})

    def _hook_code(
        self, _: unicorn.Uc, address: int, size: int, user_data: Any
    ) -> None:
        if address in self._breakpoints or self._step_ins_flag:
            if self._step_ins_flag:
                self._step_ins_flag = False
                event = DBG_EVENT_STEP
                self._logger.info(
                    f'step instruction at '
                    f'{self.mem.addr_to_str(address)}'
                )

            if address in self._breakpoints:
                bp = self._breakpoints[address]
                bp.hit_count += 1
                event = DBG_EVENT_BREAKPOINT
                self._logger.info(
                    f'breakpoint at '
                    f'{self.mem.addr_to_str(address)}, hit {bp.hit_count}'
                )

                if bp.count > 0 and bp.count == bp.hit_count:
                    self.breakpoint_del(address)

            self.debug_event_callback(event, {'address': address})

    def breakpoint_set(self, address: int, count: int = 0) -> None:
        if address not in self._breakpoints:
            self._breakpoints.update({address: Breakpoint(address, count)})

    def breakpoint_del(self, address: int) -> None:
        self._breakpoints.pop(address)

    def breakpoint_del_by_index(self, idx: int) -> None:
        address = list(self._breakpoints.keys())[idx - 1]
        self.breakpoint_del(address)

    def breakpoint_get(self) -> List[Breakpoint]:
        return list(self._breakpoints.values())

    def set_step(self) -> None:
        self._step_ins_flag = True

    def _hook_watchpoint(
        self,
        _: unicorn.Uc,
        access: int,
        address: int,
        size: int,
        value: int,
        current_run: Any
    ) -> None:
        for area, wp in self._watchpoints.items():
            access_type = 'w' if access == UC_MEM_WRITE else 'r'

            if wp.begin >= address <= wp.end and access_type in wp.access:
                pc = self.regs.arch_pc
                wp.hit_count += 1
                begin, end = area.split(':')
                access_str = 'write' if access == UC_MEM_WRITE else 'read'
                self._logger.info(
                    f'watchpoint at {self.mem.addr_to_str(address)}, '
                    f'area [{self.mem.addr_to_str(int(begin))}'
                    f'-{self.mem.addr_to_str(int(end))}], '
                    f'hit {wp.hit_count}, '
                    f'access {access_str} from {self.mem.addr_to_str(pc)}'
                )
                meta = {
                    'address': address, 'pc_address': pc,
                    'access': access_type, 'size': size
                }
                self.debug_event_callback(DBG_EVENT_WATCHPOINT, meta)

                if wp.count > 0 and wp.count == wp.hit_count:
                    self.watchpoint_del(area)

    def watchpoint_set(
        self, begin: int, end: int, access: Literal['r', 'w', 'rw'],
        count: int = 0
    ) -> None:
        if end < begin:
            raise ValueError(f'invalid Watch Memory area (begin < end)')

        if (area := f'{begin}:{end}') not in self._watchpoints:
            wp = Watchpoint(begin, end, access, count)
            self._watchpoints.update({area: wp})

    def watchpoint_del_by_index(self, idx: int) -> None:
        self.watchpoint_del(list(self._watchpoints.keys())[idx - 1])

    def watchpoint_del(self, area: str) -> None:
        self._watchpoints.pop(area)

    def watchpoint_get(self) -> List[Watchpoint]:
        return list(self._watchpoints.values())
