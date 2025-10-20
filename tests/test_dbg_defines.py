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

import datetime

import pytest
from unittest.mock import Mock, patch

from fiit.machine import CpuBits
from fiit.dbg.defines import (
    BreakpointBase,

    BreakpointType,
    Breakpoint,
    BreakpointOOB,

    WatchpointAccess,
    WatchpointType,
    Watchpoint,
    WatchpointReadOOB,
    WatchpointWriteOOB,
    WatchpointRwOOB,

    DbgEventBase,
    DbgEventStartProgram,
    DbgEventContinue,
    DbgEventStopType,
    DbgEventStop,
    DbgEventBreakpoint,
    DbgEventBreakpointChanged,
    DbgEventWatchpointAccess,
    DbgEventWatchpoint,
    DbgEventStepInst,
    DbgEventMemFetchUnmapped,
    DbgEventMemAccessUnmapped,
    DbgEventMemWriteUnmapped,
    DbgEventMemReadUnmapped,
    DbgEventBreakpointCreated,
    DbgEventBreakpointDeleted,
    DbgEventRegisterWrite,
    DbgEventMemWrite
)

# ==============================================================================


# ------------------------------------------------------------------------------
# fixture

class MythicDebugger:
    def __init__(self):
        self.dev_name = 'cpu0'
        self._event_callbacks = []

    def watchpoint_del(self, *args, **kwargs) -> None:
        pass

    def breakpoint_del(self, *args, **kwargs) -> None:
        pass

    def add_event_callback(self, callback):
        self._event_callbacks.append(callback)

    def trigger_event(self, event: DbgEventBase) -> None:
        for cb in self._event_callbacks:
            cb(self, event)



# ------------------------------------------------------------------------------
# tests breakpoint interface


# --------------
# BreakpointBase

class BreakpointBaseImpl(BreakpointBase):
    pass


def test_breakpoint_base_type_():
    bp = BreakpointBaseImpl(BreakpointType.OOB)
    assert bp.break_type == BreakpointType.OOB
    assert isinstance(bp.break_type, BreakpointType)


def test_breakpoint_base_is_breakpoint():
    bp = BreakpointBaseImpl(BreakpointType.OOB)
    assert bp.is_breakpoint
    assert not bp.is_watchpoint


def test_breakpoint_base_is_watchpoint():
    wp = Watchpoint(
        0x0, 0xfff, WatchpointAccess.READ, WatchpointType.OOB
    )
    assert not wp.is_breakpoint
    assert wp.is_watchpoint


def test_breakpoint_base_set_owner():
    md = MythicDebugger()
    bp = BreakpointBaseImpl(BreakpointType.OOB)
    assert not bp.is_valid
    bp.owner = md
    assert bp.is_valid
    assert bp.owner == md


def test_breakpoint_base_set_owner_error():
    md = MythicDebugger()
    bp = BreakpointBaseImpl(BreakpointType.OOB)
    assert not bp.is_valid
    bp.owner = md
    assert bp.is_valid
    assert bp.owner == md

    with pytest.raises(RuntimeError):
        bp.owner = md


def test_breakpoint_base_enable():
    collect = []

    def event_callback(dbg: MythicDebugger, event: DbgEventBase):
        collect.append(event)

    md = MythicDebugger()
    md.add_event_callback(event_callback)
    bp = BreakpointBaseImpl(BreakpointType.OOB)
    bp.owner = md
    assert bp.enabled
    bp.enabled = False
    assert not bp.enabled
    assert len(collect) == 1
    assert isinstance(collect[0], DbgEventBreakpointChanged)


def test_breakpoint_base_hit_callback():
    bp = BreakpointBaseImpl(BreakpointType.OOB)
    custom_hitter = (lambda b: None)
    assert bp.hit_callback is None
    bp.hit_callback = custom_hitter
    assert bp.hit_callback == custom_hitter


def test_breakpoint_base_default_condition():
    md = MythicDebugger()
    bp = BreakpointBaseImpl(BreakpointType.OOB)
    assert bp.condition(md, bp)


# ----------
# Breakpoint

def test_breakpoint():
    bp = Breakpoint(0xdeadc0de, BreakpointType.OOB)
    assert bp.address == 0xdeadc0de


def test_breakpoint_oob():
    bp = BreakpointOOB(0xdeadc0de)
    assert bp.address == 0xdeadc0de


def test_breakpoint_invalidate():
    meth_path = f'{__name__}.MythicDebugger.breakpoint_del'
    with patch(meth_path, side_effect=Mock()) as m_fun:
        md = MythicDebugger()
        bp = BreakpointOOB(0xdeadc0de)
        assert not bp.is_valid
        bp.owner = md
        assert bp.is_valid
        assert bp.owner == md
        bp.invalidate()
        m_fun.assert_called_once()


# ----------
# Watchpoint

def test_watchpoint_access():
    assert WatchpointAccess.from_str('r') == WatchpointAccess.READ
    assert WatchpointAccess.from_str('r-') == WatchpointAccess.READ
    assert WatchpointAccess.from_str('read') == WatchpointAccess.READ
    assert WatchpointAccess.READ.label == 'r'
    assert WatchpointAccess.READ.label_unix == 'r-'
    assert WatchpointAccess.READ.label_full == 'read'
    assert WatchpointAccess.from_str('w') == WatchpointAccess.WRITE
    assert WatchpointAccess.from_str('-w') == WatchpointAccess.WRITE
    assert WatchpointAccess.from_str('write') == WatchpointAccess.WRITE
    assert WatchpointAccess.WRITE.label == 'w'
    assert WatchpointAccess.WRITE.label_unix == '-w'
    assert WatchpointAccess.WRITE.label_full == 'write'

    with pytest.raises(ValueError):
        WatchpointAccess.from_str('boom')


def test_watchpoint():
    wp = Watchpoint(
        0x0, 0xfff, WatchpointAccess.READ, WatchpointType.OOB
    )
    assert wp.access == WatchpointAccess.READ
    assert wp.break_type == WatchpointType.OOB
    assert wp.begin == 0x0
    assert wp.end == 0xfff


def test_watchpoint_read_oob():
    wp = WatchpointReadOOB(0x0, 0xfff)
    assert wp.access == WatchpointAccess.READ
    assert wp.break_type == WatchpointType.OOB
    assert wp.begin == 0x0
    assert wp.end == 0xfff


def test_watchpoint_write_oob():
    wp = WatchpointWriteOOB(0x0, 0xfff)
    assert wp.access == WatchpointAccess.WRITE
    assert wp.break_type == WatchpointType.OOB
    assert wp.begin == 0x0
    assert wp.end == 0xfff


def test_watchpoint_read_write_oob():
    wp = WatchpointRwOOB(0x0, 0xfff)
    assert wp.access == WatchpointAccess.READ_WRITE
    assert wp.break_type == WatchpointType.OOB
    assert wp.begin == 0x0
    assert wp.end == 0xfff


def test_watchpoint_invalidate():
    meth_path = f'{__name__}.MythicDebugger.watchpoint_del'
    with patch(meth_path, side_effect=Mock()) as m_fun:
        md = MythicDebugger()
        wp = WatchpointRwOOB(0x0, 0xfff)
        assert not wp.is_valid
        wp.owner = md
        assert wp.is_valid
        assert wp.owner == md
        wp.invalidate()
        m_fun.assert_called_once()


# ------------------------------------------------------------------------------
# tests event interface


# EventBase

def test_dbg_event_base_frozen_dbg_ref():
    md = MythicDebugger()
    event = DbgEventBase()
    event.dbg = md
    assert event.dbg == md

    with pytest.raises(RuntimeError):
        event.dbg = None


def test_dbg_event_timestamp():
    event = DbgEventBase()
    assert isinstance(event.timestamp, datetime.datetime)


def test_dbg_event_dev_name():
    md = MythicDebugger()
    event = DbgEventBase()
    event.dbg = md
    assert event.dev_name == 'cpu0'


def test_dbg_event_base_arch_bits():
    event = DbgEventBase()
    assert event.arch_bits is None


def test_dbg_event_base_arch_bits_none():
    event = DbgEventBase()
    assert event.arch_bits is None


def test_dbg_event_base_arch_bits_set():
    event = DbgEventBase()
    event.arch_bits = 32
    assert event.arch_bits == CpuBits.BITS_32


def test_dbg_event_base_set_seq_frozen():
    event = DbgEventBase()
    event.seq = 99
    assert event.seq == 99

    with pytest.raises(RuntimeError):
        event.seq = 110


def test_dbg_event_base_set_seq_zero_error():
    event = DbgEventBase()
    with pytest.raises(ValueError):
        event.seq = 0


# Events

def test_dbg_event_start_program():
    event = DbgEventStartProgram(0x20000)
    assert event.address == 0x20000
    assert str(event) == 'start program at 0x20000'


def test_dbg_event_continue():
    event = DbgEventContinue(0x30000)
    assert event.address == 0x30000
    assert str(event) == 'continue from 0x30000'


def test_dbg_event_stop():
    event = DbgEventStop(DbgEventStopType.BREAKPOINT)
    assert event.reason == DbgEventStopType.BREAKPOINT
    assert str(event) == 'stop program, reason "1"'


def test_dbg_event_breakpoint():
    bp = BreakpointOOB(0x20000)
    event = DbgEventBreakpoint(bp)
    assert event.reason == DbgEventStopType.BREAKPOINT
    assert event.address == 0x20000
    assert str(event) == 'breakpoint hit at 0x20000, hit 0'


def test_dbg_event_watchpoint():
    wp = Watchpoint(
        0x100000, 0x1fffff, WatchpointAccess.READ, WatchpointType.OOB,
    )

    wp.hit_count += 1

    event = DbgEventWatchpoint(
        DbgEventWatchpointAccess.READ, 0x20000, 0x100000, 4, wp
    )

    assert event.watchpoint == wp
    assert event.from_address == 0x20000
    assert event.to_address == 0x100000
    assert event.access == DbgEventWatchpointAccess.READ
    assert event.size == 4
    assert event.hit_count == 1
    assert str(event) == (
        'watchpoint hit, r- access from 0x20000 to 0x100000-0x1fffff, hit 1'
    )


def test_dbg_event_step_inst():
    event = DbgEventStepInst(0x20000)
    assert event.address == 0x20000
    assert str(event) == 'step instruction at 0x20000'


def test_dbg_event_mem_fetch_unmapped():
    event = DbgEventMemFetchUnmapped(0xdeadc0de)
    assert event.address == 0xdeadc0de
    assert str(event) == 'fetch unmapped memory 0xdeadc0de'


def test_dbg_event_mem_access_unmapped():
    event = DbgEventMemAccessUnmapped(
        DbgEventStopType.MEM_READ_UNMAPPED, 0x20000, 0x30000
    )
    assert event.from_address == 0x20000
    assert event.to_address == 0x30000
    assert str(event) == 'mem read unmapped from 0x20000 to 0x30000'


def test_dbg_event_mem_write_unmapped():
    event = DbgEventMemWriteUnmapped(0x20000, 0x30000)
    assert event.from_address == 0x20000
    assert event.to_address == 0x30000
    assert str(event) == 'mem write unmapped from 0x20000 to 0x30000'


def test_dbg_event_mem_read_unmapped():
    event = DbgEventMemReadUnmapped(0x20000, 0x30000)
    assert event.from_address == 0x20000
    assert event.to_address == 0x30000
    assert str(event) == 'mem read unmapped from 0x20000 to 0x30000'


def test_dbg_event_breakpoint_created():
    bp = Breakpoint(0x10000, BreakpointType.OOB)
    event = DbgEventBreakpointCreated(bp)
    assert event.breakpoint == bp
    assert str(event) == 'breakpoint created at 0x10000'


def test_dbg_event_mem_write():
    event = DbgEventMemWrite(0xfff, 256)
    assert event.address == 0xfff
    assert event.length == 256


def test_dbg_event_watchpoint_created():
    wp = Watchpoint(
        0x100000, 0x1fffff, WatchpointAccess.READ, WatchpointType.OOB
    )
    event = DbgEventBreakpointCreated(wp)
    assert event.breakpoint == wp
    assert str(event) == (
        'watchpoint created with access r- on memory range 0x100000-0x1fffff'
    )


def test_dbg_event_breakpoint_deleted():
    bp = Breakpoint(0x10000, BreakpointType.OOB)
    event = DbgEventBreakpointDeleted(bp)
    assert event.breakpoint == bp
    assert str(event) == 'breakpoint deleted at 0x10000'


def test_dbg_event_watchpoint_deleted():
    wp = Watchpoint(
        0x100000, 0x1fffff, WatchpointAccess.READ, WatchpointType.OOB
    )
    event = DbgEventBreakpointDeleted(wp)
    assert event.breakpoint == wp
    assert str(event) == (
        'watchpoint deleted with access r- on memory range 0x100000-0x1fffff'
    )


def test_dbg_event_breakpoint_changed():
    bp = Breakpoint(0x10000, BreakpointType.OOB)
    event = DbgEventBreakpointChanged(bp)
    assert event.breakpoint == bp
    assert str(event) == 'breakpoint changed at 0x10000'


def test_dbg_event_watchpoint_changed():
    wp = Watchpoint(
        0x100000, 0x1fffff, WatchpointAccess.READ, WatchpointType.OOB
    )
    event = DbgEventBreakpointChanged(wp)
    assert event.breakpoint == wp
    assert str(event) == (
        'watchpoint changed with access r- on memory range 0x100000-0x1fffff'
    )


def test_dbg_event_register_write():
    event = DbgEventRegisterWrite('rip', 0xc0dec0fe)
    assert event.value == 0xc0dec0fe
    assert event.register == 'rip'
