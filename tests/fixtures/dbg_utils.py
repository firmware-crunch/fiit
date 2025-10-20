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
    'DbgEventCollectEntry',
    'DbgCallbackHarness'
]

from typing import List, Callable, Generator, Optional, Dict, Any, Union, Tuple

from fiit.emunicorn import CpuUnicorn, DebuggerUnicorn
from fiit.dbg import DbgEventBase, Debugger
from fiit import FiitDbgFactory

from .blobs.meta_bin_blob import MetaBinBlob
from .cpu_utils import Blob2Cpu

# ==============================================================================


class Blob2Dbg(Blob2Cpu):
    def __init__(self, bin_blob: MetaBinBlob, debug_event_callback=None):
        Blob2Cpu.__init__(self, bin_blob, 'unicorn', 'cpu0')
        self.dbg = FiitDbgFactory.get(self.cpu)

        if debug_event_callback is not None:
            self.dbg.add_event_callback(debug_event_callback)

        assert isinstance(self.cpu.cpu, CpuUnicorn)
        assert isinstance(self.dbg, DebuggerUnicorn)


class DbgEventCollectEntry:
    def __init__(
        self, event: DbgEventBase, registers: Optional[Dict] = None
    ):
        self._event: DbgEventBase = event
        self._registers: Dict[str, int] = registers
        self._data = {}

    @property
    def event(self) -> DbgEventBase:
        return self._event

    def get_register(self, register: str) -> int:
        if self._registers is not None:
            return self._registers[register]

    def add_data(self, data_entry: Union[int, str], value: Any):
        self._data[data_entry] = value

    def get_data(self, data_entry) -> Union[Any, None]:
        return self._data.get(data_entry, None)


class DbgCallbackHarness:
    def __init__(
        self, callback: Callable = None, register_collect: List[str] = None
    ) -> None:
        self._event_collect: List[DbgEventCollectEntry] = []
        self._callback = callback
        self._register_collect = register_collect

    def _event_callback(
        self, dbg: Debugger, event: DbgEventBase
    ) -> None:
        registers = {}

        if self._register_collect is not None:
            for register in self._register_collect:
                registers[register] = dbg.regs.read(register)

        entry = DbgEventCollectEntry(event, registers)
        self._event_collect.append(entry)

        if self._callback is not None:
            self._callback(dbg, entry)

    @property
    def event_callback(self) -> Callable[[Debugger, DbgEventBase], None]:
        return self._event_callback

    def clear_collect(self) -> None:
        self._event_collect.clear()

    def count_events(self, event_filter: Tuple = None) -> int:
        if event_filter is None:
            return len(self._event_collect)
        else:
            count = 0
            for collect in self._event_collect:
                if isinstance(collect.event, event_filter):
                    count += 1
            return count

    def get_event(self, index: int) -> DbgEventBase:
        return self._event_collect[index].event

    def iter_event(self) -> Generator[DbgEventBase, None, None]:
        for e in self._event_collect:
            yield e.event

    def get_event_collect_entry(self, index: int) -> DbgEventCollectEntry:
        return self._event_collect[index]

    def iter_collect(self) -> Generator[DbgEventCollectEntry, None, None]:
        for e in self._event_collect:
            yield e
