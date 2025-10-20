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
    'DebugEventCallback',
    'Debugger'
]

import abc
import logging
from typing import List, Callable, ClassVar, Type, Optional, Union, Tuple

from fiit.machine import Cpu, DeviceCpu

from .disasm import DisassemblerCapstone
from .defines import (
    BreakpointCondition,
    BreakpointHitCb,
    DbgEventBase,
    Breakpoint,
    BreakpointType,
    WatchpointAccess,
    WatchpointType,
    Watchpoint,
    DbgEventMemWrite,
    DbgEventRegisterWrite,
)

# ==============================================================================


DebugEventCallback = Callable[['Debugger', DbgEventBase], None]


class Debugger(abc.ABC):

    CPU_CLASS: ClassVar[Type[Cpu]]

    def __init__(self, cpu: DeviceCpu):
        self._logger_name = f'fiit.dbg@{cpu.dev_name}'
        self._logger = logging.getLogger(self._logger_name)

        self.cpu = cpu
        self.mem = self.cpu.mem
        self.regs = self.cpu.regs

        self._event_sequence_number = 0
        self.debug_event_callbacks: List[DebugEventCallback] = []

        dis_arch_str = (
            f'{self.cpu.ARCH_NAME}:{self.cpu.endian.label_hc_lc}'
            f':{self.cpu.bits.value}:default'
        )
        self._disassembler = DisassemblerCapstone(dis_arch_str)

    @property
    def dev_name(self) -> str:
        return f'dev@{self.cpu.dev_name}'

    @property
    def logger_name(self) -> str:
        return self._logger_name

    @property
    def log(self) -> logging.Logger:
        return self._logger

    def add_event_callback(self, event_callback: DebugEventCallback) -> None:
        self.debug_event_callbacks.append(event_callback)

    def trigger_event(self, event: DbgEventBase) -> None:
        self._event_sequence_number += 1
        event.seq = self._event_sequence_number
        event.dbg = self
        event.arch_bits = self.cpu.bits
        self._logger.info(str(event))

        for callback in self.debug_event_callbacks:
            callback(self, event)

    def mem_write(self, address: int, data: bytes) -> int:
        length = self.mem.write(address, data)
        event = DbgEventMemWrite(address, len(data))
        self.trigger_event(event)
        return length

    def reg_write(self, register: str, value: int) -> None:
        self.regs.write(register, value)
        event = DbgEventRegisterWrite(register, value)
        self.trigger_event(event)

    # --------------------------------------------------------------------------
    # breakpoint interface

    @abc.abstractmethod
    def set_step_inst(self) -> None:
        """ """

    @property
    @abc.abstractmethod
    def breakpoints(self) -> List[Breakpoint]:
        """ """

    @abc.abstractmethod
    def breakpoint_add(
        self,
        address: int,
        breakpoint_type: BreakpointType,
        condition: Optional[BreakpointCondition] = None,
        hit_callback: Optional[BreakpointHitCb] = None
    ) -> Breakpoint:
        """ """

    @abc.abstractmethod
    def breakpoint_del(self, bp: Union[Breakpoint, int]) -> None:
        """
        bp: A `Breakpoint` instance or the address of the breakpoint
        """

    @abc.abstractmethod
    def breakpoint_del_by_index(self, index: int) -> None:
        """ """

    # --------------------------------------------------------------------------
    # watchpoint interface

    @property
    @abc.abstractmethod
    def watchpoints(self) -> List[Watchpoint]:
        """ """

    @abc.abstractmethod
    def watchpoint_add(
        self,
        begin: int,
        end: int,
        access: WatchpointAccess,
        watchpoint_type: WatchpointType,
        condition: Optional[BreakpointCondition] = None,
        hit_callback: Optional[BreakpointHitCb] = None
    ) -> Watchpoint:
        """ """

    @abc.abstractmethod
    def watchpoint_del(
        self, watchpoint: Union[Watchpoint, Tuple[int, int]]
    ) -> None:
        """
        watchpoint: A `Watchpoint` instance or the (begin, end) address tuple of
                    the watchpoint
        """

    @abc.abstractmethod
    def watchpoint_del_by_index(self, index: int) -> None:
        """ """

    def disassemble(self, address: int, count: int) -> List[str]:
        search = list(filter(
            lambda r: r.base_address <= address < r.end_address,
            self.mem.regions))

        if len(search) == 1:
            region = search[0]
            chunk_size = (
                (region.end_address - region.base_address)
                - 1 - (address - region.base_address)
            )

            code = self.mem.read(address, chunk_size)

            listing = self._disassembler.disassemble_mem_range(
                bytearray(code), address, count
            )
            return listing

        raise ValueError(f'Fail to disassemble at {address}, not mapped')
