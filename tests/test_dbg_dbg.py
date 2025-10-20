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

import logging
from typing import Optional, Union, Tuple, List

from fiit.dbg import (
    Debugger,
    DebugEventCallback,
    Watchpoint,
    WatchpointAccess,
    WatchpointType,
    BreakpointCondition,
    BreakpointHitCb,
    Breakpoint,
    BreakpointType,
    DbgEventBase,
    DbgEventContinue,
    DbgEventMemWrite,
    DbgEventRegisterWrite
)

import pytest

from .fixtures.blobs import BlobArmEl32IncLoop
from .fixtures import Blob2Cpu, DbgCallbackHarness

# ==============================================================================

# ------------------------------------------------------------------------------
# fixtures


class MythicDebugger(Debugger):
    def __init__(self, event_callback: Optional[DebugEventCallback] = None):
        b2c = Blob2Cpu(BlobArmEl32IncLoop, 'unicorn', 'cpu0')
        Debugger.__init__(self, b2c.cpu)

    @property
    def breakpoints(self) -> List[Breakpoint]:
        return []

    @property
    def watchpoints(self) -> List[Watchpoint]:
        return []

    def breakpoint_add(
        self,
        address: int,
        breakpoint_type: BreakpointType,
        condition: Optional[BreakpointCondition] = None,
        hit_callback: Optional[BreakpointHitCb] = None
    ) -> Breakpoint:
        pass

    def breakpoint_del(self, bp: Union[Breakpoint, int]) -> None:
        pass

    def breakpoint_del_by_index(self, index: int) -> None:
        pass

    def set_step_inst(self) -> None:
        pass

    def watchpoint_add(
        self,
        begin: int,
        end: int,
        access: WatchpointAccess,
        watchpoint_type: WatchpointType,
        condition: Optional[BreakpointCondition] = None,
        hit_callback: Optional[BreakpointHitCb] = None
    ) -> Watchpoint:
        pass

    def watchpoint_del(
        self, watchpoint: Union[Watchpoint, Tuple[int, int]]
    ) -> None:
        pass

    def watchpoint_del_by_index(self, index: int) -> None:
        pass


# ------------------------------------------------------------------------------
# tests

def test_disassemble():
    expected_disasm = (
        '0x00000000:\t0000a0e3            \tmov\tr0, #0\n'
        '0x00000004:\tffffffea            \tb\t#8\n'
        '0x00000008:\t010080e2            \tadd\tr0, r0, #1\n'
        '0x0000000c:\t0a0050e3            \tcmp\tr0, #0xa\n'
        '0x00000010:\tfcffff1a            \tbne\t#8\n'
        '0x00000014:\t0110a0e3            \tmov\tr1, #1'
    )
    listing = '\n'.join(MythicDebugger().disassemble(0x0, 6))
    assert listing == expected_disasm


def test_disassemble_unmapped_address():
    with pytest.raises(ValueError):
        MythicDebugger().disassemble(0xff409000, 6)


def test_logger_name():
    assert MythicDebugger().logger_name == 'fiit.dbg@cpu0'


def test_dev_name():
    assert MythicDebugger().dev_name == 'dev@cpu0'


def test_log():
    assert isinstance(MythicDebugger().log, logging.Logger)


def test_trigger_event():
    collect = []

    def event_callback(dbg: Debugger, event: DbgEventBase) -> None:
        collect.append((dbg, event))

    md = MythicDebugger()
    md.add_event_callback(event_callback)
    event = DbgEventContinue(0xc0dec0fee)
    md.trigger_event(event)

    assert len(collect) == 1
    assert collect[0][1] == event


def test_mem_write():
    harness = DbgCallbackHarness()
    md = MythicDebugger()
    md.add_event_callback(harness.event_callback)
    md.mem_write(0xff, b'\xC0\xDE\xC0\xFE')
    assert harness.count_events() == 1
    assert DbgEventMemWrite
    iter_event = harness.iter_event()
    assert isinstance(next(iter_event), DbgEventMemWrite)


def test_register_write():
    harness = DbgCallbackHarness()
    md = MythicDebugger()
    md.add_event_callback(harness.event_callback)
    md.reg_write('r5', 0xC0DEF00D)
    assert harness.count_events() == 1
    assert DbgEventMemWrite
    iter_event = harness.iter_event()
    assert isinstance(next(iter_event), DbgEventRegisterWrite)
