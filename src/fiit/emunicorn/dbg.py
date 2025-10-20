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
from typing import Any, Optional, Union, Tuple, List, cast

import unicorn
from unicorn.unicorn_const import (
    UC_HOOK_CODE,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_MEM_READ,
    UC_MEM_WRITE_UNMAPPED,
    UC_MEM_READ_UNMAPPED,
    UC_MEM_FETCH_UNMAPPED
)

from fiit.machine import DeviceCpu
from fiit.emunicorn import CpuUnicorn

from fiit.dbg import (
    Debugger,
    Breakpoint,
    BreakpointType,
    BreakpointOOB,
    Watchpoint,
    WatchpointType,
    WatchpointAccess,
    DbgEventBase,
    DbgEventWatchpointAccess,
    DbgEventBreakpointCreated,
    DbgEventBreakpointDeleted,
    DbgEventContinue,
    DbgEventStartProgram,
    DbgEventStepInst,
    DbgEventBreakpoint,
    DbgEventWatchpoint,
    DbgEventMemFetchUnmapped,
    DbgEventMemReadUnmapped,
    DbgEventMemWriteUnmapped,
    BreakpointCondition,
    BreakpointHitCb,
    BreakpointInvalidateCb
)

# ==============================================================================


class DebuggerUnicorn(Debugger):

    CPU_CLASS = CpuUnicorn

    def __init__(self, cpu: DeviceCpu):
        assert isinstance(cpu.cpu, CpuUnicorn)
        assert isinstance(cpu.backend, unicorn.Uc)
        Debugger.__init__(self, cpu)

        uc = cpu.backend
        uc.hook_add(UC_HOOK_CODE, self._hook_breakpoint)
        uc.hook_add(
            UC_HOOK_MEM_READ
            | UC_HOOK_MEM_WRITE,
            self._hook_watchpoint
        )
        uc.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED
            | UC_HOOK_MEM_WRITE_UNMAPPED
            | UC_HOOK_MEM_FETCH_UNMAPPED,
            self._hook_unmapped_access
        )

        self._is_stop_event = False
        self._is_program_started = False
        self._is_step_ins = False

        self._breakpoints: OrderedDict[int, Breakpoint] = OrderedDict()
        self._watchpoints: OrderedDict[str, Watchpoint] = OrderedDict()

    # --------------------------------------------------------------------------
    # unicorn hooks

    def _hook_unmapped_access(
        self, uc: unicorn.Uc, access: int, address: int, size: int, value: int,
        user_data: Any
    ) -> None:
        from_address = self.cpu.regs.arch_pc
        event: Optional[DbgEventBase] = None

        if access == UC_MEM_FETCH_UNMAPPED:
            event = DbgEventMemFetchUnmapped(from_address)
        elif access == UC_MEM_WRITE_UNMAPPED:
            event = DbgEventMemWriteUnmapped(from_address, address)
        elif access == UC_MEM_READ_UNMAPPED:
            event = DbgEventMemReadUnmapped(from_address, address)
        else:
            raise ValueError('unmapped memory event')

        if event is not None:
            self.trigger_event(event)

        self.trigger_event(DbgEventContinue(address))

    def _hook_breakpoint(
        self, uc: unicorn.Uc, address: int, size: int, user_data: Any
    ) -> None:
        if not self._is_program_started:
            self._is_program_started = True
            self.trigger_event(DbgEventStartProgram(address))

        if address in self._breakpoints or self._is_step_ins:
            if self._is_step_ins:
                self._is_step_ins = False
                self._is_stop_event = True
                self.trigger_event(DbgEventStepInst(address))
                self.trigger_event(DbgEventContinue(address))

            if address in self._breakpoints:
                bp = self._breakpoints[address]

                if bp.is_valid and bp.enabled and bp.condition(self, bp):
                    bp.hit_count += 1
                    self._is_stop_event = True
                    self.trigger_event(DbgEventBreakpoint(bp))

                    if bp.hit_callback is not None:
                        bp.hit_callback(self, bp)

                    self.trigger_event(DbgEventContinue(address))

    def _hook_watchpoint(
        self, uc: unicorn.Uc, access: int, address: int, size: int, value: int,
        current_run: Any
    ) -> None:
        for area, bp in self._watchpoints.items():
            if access == UC_MEM_READ:
                event_access = DbgEventWatchpointAccess.READ
                access_filter = WatchpointAccess.READ
            else:
                event_access = DbgEventWatchpointAccess.WRITE
                access_filter = WatchpointAccess.WRITE

            if (bp.begin >= address <= bp.end
                    and (bp.access == access_filter
                         or bp.access == WatchpointAccess.READ_WRITE)):

                if bp.is_valid and bp.enabled and bp.condition(self, bp):
                    bp.hit_count += 1

                    event = DbgEventWatchpoint(
                        event_access, self.cpu.regs.arch_pc, address, size, bp
                    )

                    self.trigger_event(event)

                    if bp.hit_callback is not None:
                        bp.hit_callback(self, bp)

                    self.trigger_event(DbgEventContinue(address))

    def set_step_inst(self) -> None:
        self._is_step_ins = True

    # --------------------------------------------------------------------------
    # Breakpoint add/delete

    @property
    def breakpoints(self) -> List[Breakpoint]:
        return list(self._breakpoints.values())

    def breakpoint_add(
        self,
        address: int,
        breakpoint_type: BreakpointType = BreakpointType.OOB,
        condition: Optional[BreakpointCondition] = None,
        hit_callback: Optional[BreakpointHitCb] = None
    ) -> Breakpoint:
        if breakpoint_type != BreakpointType.OOB:
            raise RuntimeError(f'breakpoint not supported {breakpoint_type}')

        registered_bp = self._breakpoints.get(address, None)

        if registered_bp is not None:
            return registered_bp
        else:
            bp = BreakpointOOB(address, condition, hit_callback)
            bp.owner = self
            self._breakpoints[address] = bp
            self.trigger_event(DbgEventBreakpointCreated(bp))
            return bp

    def breakpoint_del(self, bp: Union[Breakpoint, int]) -> None:
        if isinstance(bp, int):
            bp_addr = bp
            bp_instance = self._breakpoints.get(bp_addr, None)

            if bp_instance is None:
                raise ValueError(f'breakpoint not found "{str(bp)}"')
            else:
                evinced_bp = self._breakpoints.pop(bp_addr)
                event = DbgEventBreakpointDeleted(evinced_bp)
                self.trigger_event(event)
                return

        elif isinstance(bp, Breakpoint):
            for stored_bp in self._breakpoints.values():
                if stored_bp == bp:
                    evinced_bp = self._breakpoints.pop(bp.address)
                    event = DbgEventBreakpointDeleted(evinced_bp)
                    self.trigger_event(event)
                    return

            raise ValueError(f'breakpoint not found "{str(bp)}"')

        else:
            raise ValueError(f'invalid breakpoint type "{str(bp)}"')

    def breakpoint_del_by_index(self, index: int) -> None:
        effective_index = index - 1
        bp_addresses = list(self._breakpoints.keys())

        if effective_index < len(bp_addresses):
            return self.breakpoint_del(bp_addresses[effective_index])

        raise ValueError(f'breakpoint index not found "{str(index)}"')

    # --------------------------------------------------------------------------
    # Watchpoint add/delete

    @property
    def watchpoints(self) -> List[Watchpoint]:
        return list(self._watchpoints.values())

    def watchpoint_add(
        self,
        begin: int,
        end: int,
        access: WatchpointAccess,
        watchpoint_type: WatchpointType = WatchpointType.OOB,
        condition: Optional[BreakpointCondition] = None,
        hit_callback: Optional[BreakpointHitCb] = None
    ) -> Watchpoint:
        if watchpoint_type != WatchpointType.OOB:
            raise RuntimeError(f'watchpoint not supported {watchpoint_type}')

        if end < begin:
            raise ValueError('invalid watchpoint memory area (begin < end)')

        area_key = f'{begin}:{end}'
        registered_wp = self._watchpoints.get(area_key)

        if registered_wp is not None:
            return registered_wp
        else:
            wp = Watchpoint(
                begin, end, access, watchpoint_type, condition, hit_callback
            )
            wp.owner = self
            self._watchpoints[area_key] = wp
            event = DbgEventBreakpointCreated(wp)
            self.trigger_event(event)
            return wp

    def watchpoint_del(
        self, watchpoint: Union[Watchpoint, Tuple[int, int]]
    ) -> None:
        is_area = (
            isinstance(watchpoint, tuple)
            and len(watchpoint) == 2
            and isinstance(watchpoint[0], int)
            and isinstance(watchpoint[1], int)
        )

        if is_area:
            begin, end = cast(Tuple[int, int], watchpoint)
            area_key = f'{begin}:{end}'
            wp_instance = self._watchpoints.get(area_key)

            if wp_instance is None:
                raise ValueError(f'watchpoint not found "{str(watchpoint)}"')
            else:
                evinced_wp = self._watchpoints.pop(area_key)
                event = DbgEventBreakpointDeleted(evinced_wp)
                self.trigger_event(event)
                return

        elif isinstance(watchpoint, Watchpoint):
            for stored_wp in self._watchpoints.values():
                if stored_wp == watchpoint:
                    area_key = f'{watchpoint.begin}:{watchpoint.end}'
                    evinced_wp = self._watchpoints.pop(area_key)
                    event = DbgEventBreakpointDeleted(evinced_wp)
                    self.trigger_event(event)
                    return

            raise ValueError(f'watchpoint not found "{str(watchpoint)}"')

        else:
            raise ValueError(f'invalid watchpoint type "{str(watchpoint)}"')

    def watchpoint_del_by_index(self, index: int) -> None:
        effective_index = index - 1

        wps = list(self._watchpoints.values())

        if effective_index < len(wps):
            return self.watchpoint_del(wps[effective_index])

        raise ValueError(f'watchpoint index not found "{str(index)}"')
