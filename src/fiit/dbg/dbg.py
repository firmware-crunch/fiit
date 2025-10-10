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
    'Breakpoint',
    'Watchpoint',

    'DBG_EVENT_SEGFAULT',
    'DBG_EVENT_BREAKPOINT',
    'DBG_EVENT_WATCHPOINT',
    'DBG_EVENT_STEP',

    'DebugEventCallback',
    'Debugger'
]

import abc
import logging
import dataclasses
from typing import Literal, List, Callable, ClassVar, Type, Dict, Any, Optional

from ..machine import Cpu, DeviceCpu

from .disasm import DisassemblerCapstone

# ==============================================================================


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


DebugEventCallback = Callable[['Debugger', int, Dict[Any, Any]], None]


class Debugger(abc.ABC):

    CPU_CLASS: ClassVar[Type[Cpu]]

    def __init__(
        self,
        cpu: DeviceCpu,
        event_callback: Optional[DebugEventCallback] = None
    ):
        self._logger_name = f'fiit.dbg@{cpu.dev_name}'
        self._logger = logging.getLogger(self._logger_name)
        self.dev_str = f'dev@{cpu.dev_name}'
        self.cpu = cpu
        self.mem = self.cpu.mem
        self.regs = self.cpu.regs

        self.debug_event_callbacks: List[DebugEventCallback] = []

        if event_callback is not None:
            self.add_event_callback(event_callback)

        dis_arch_str = (
            f'{self.cpu.ARCH_NAME}'
            f':{self.cpu.endian.label_hc_lc}'
            f':{self.cpu.bits.value}'
            f':default'
        )
        self._disassembler = DisassemblerCapstone(dis_arch_str)

    @property
    def logger_name(self) -> str:
        return self._logger_name

    @property
    def log(self) -> logging.Logger:
        return self._logger

    def add_event_callback(self, event_callback: DebugEventCallback) -> None:
        self.debug_event_callbacks.append(event_callback)

    def debug_event_callback(self, event_id: int, args: Dict[Any, Any]) -> None:
        for callback in self.debug_event_callbacks:
            callback(self, event_id, args)

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

            return self._disassembler.disassemble_mem_range(
                bytearray(code), address, count)
        else:
            raise ValueError(f'Fail to disassemble at {address}, not mapped')

    @abc.abstractmethod
    def breakpoint_set(self, address: int, count: int = 0) -> None:
        """ """

    @abc.abstractmethod
    def breakpoint_del(self, address: int) -> None:
        """ """

    @abc.abstractmethod
    def breakpoint_del_by_index(self, idx: int) -> None:
        """ """

    @abc.abstractmethod
    def breakpoint_get(self) -> List[Breakpoint]:
        """ """

    @abc.abstractmethod
    def set_step(self) -> None:
        """ """

    @abc.abstractmethod
    def watchpoint_set(
        self, begin: int, end: int, access: Literal['r', 'w', 'rw'],
        count: int = 0
    ) -> None:
        """ """

    @abc.abstractmethod
    def watchpoint_del_by_index(self, idx: int) -> None:
        """ """

    @abc.abstractmethod
    def watchpoint_del(self, area: str) -> None:
        """ """

    @abc.abstractmethod
    def watchpoint_get(self) -> List[Watchpoint]:
        """ """
