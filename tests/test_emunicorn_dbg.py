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

from typing import List

import pytest

import unicorn
from unicorn.unicorn_const import UC_ERR_FETCH_UNMAPPED

from .fixtures.blobs import (
    BlobArmEl32MemFetchUnmapped,
    BlobArmEl32MemReadUnmapped,
    BlobArmEl32MemWriteUnmapped,
    BlobArmEl32IncLoop,
    BlobArmEl32ReadWriteLoop,
    BlobArmEl32MultiBlock
)

from fiit.dbg import (
    Debugger,
    Breakpoint,
    BreakpointType,
    Watchpoint,
    WatchpointType,
    WatchpointAccess,
    DbgEventBreakpoint,
    DbgEventWatchpoint,
    DbgEventWatchpointAccess,
    DbgEventStepInst,
    DbgEventMemFetchUnmapped,
    DbgEventMemWriteUnmapped,
    DbgEventMemReadUnmapped,
    DbgEventStartProgram,
    DbgEventBreakpointCreated,
    DbgEventBreakpointDeleted,
    DbgEventContinue
)

from .fixtures import DbgCallbackHarness, DbgEventCollectEntry, Blob2Dbg

# ==============================================================================


def test_mem_fetch_unmapped():
    # unicorn specific
    harness = DbgCallbackHarness()

    with pytest.raises(unicorn.unicorn.UcError) as exc_info:
        Blob2Dbg(BlobArmEl32MemFetchUnmapped, harness.event_callback).start()

    assert harness.count_events() == 3
    iter_event = harness.iter_event()
    assert isinstance(next(iter_event), DbgEventStartProgram)
    assert isinstance(next(iter_event), DbgEventMemFetchUnmapped)
    assert isinstance(next(iter_event), DbgEventContinue)
    assert exc_info.value.errno == UC_ERR_FETCH_UNMAPPED


def test_mem_read_unmapped():
    # unicorn specific
    harness = DbgCallbackHarness()

    with pytest.raises(unicorn.unicorn.UcError):
        Blob2Dbg(BlobArmEl32MemReadUnmapped, harness.event_callback).start()

    assert harness.count_events() == 3
    iter_event = harness.iter_event()
    assert isinstance(next(iter_event), DbgEventStartProgram)
    assert isinstance(next(iter_event), DbgEventMemReadUnmapped)
    assert isinstance(next(iter_event), DbgEventContinue)


def test_mem_write_unmapped():
    # unicorn specific
    harness = DbgCallbackHarness()

    with pytest.raises(unicorn.unicorn.UcError):
        Blob2Dbg(BlobArmEl32MemWriteUnmapped, harness.event_callback).start()

    assert harness.count_events() == 3
    iter_event = harness.iter_event()
    assert isinstance(next(iter_event), DbgEventStartProgram)
    assert isinstance(next(iter_event), DbgEventMemWriteUnmapped)
    assert isinstance(next(iter_event), DbgEventContinue)


def test_mem_event_unmapped_invalid():
    # unicorn specific
    # Trigger a case which potentially can't be triggered in real world
    dbg = Blob2Dbg(BlobArmEl32MemReadUnmapped).dbg
    with pytest.raises(ValueError):
        dbg._hook_unmapped_access(None, None, None, None, None, None)


def test_breakpoint_add_with_condition():
    harness = DbgCallbackHarness(register_collect=['r0'])
    b2d = Blob2Dbg(BlobArmEl32IncLoop, harness.event_callback)
    b2d.dbg.breakpoint_add(16, condition=lambda d, b: b.hit_count < 2)
    b2d.start()

    assert harness.count_events() == 6
    iter_collect = harness.iter_collect()
    assert isinstance(next(iter_collect).event, DbgEventBreakpointCreated)
    assert isinstance(next(iter_collect).event, DbgEventStartProgram)
    collect = next(iter_collect)
    event = collect.event
    assert isinstance(event, DbgEventBreakpoint)
    assert event.address == 16
    assert collect.get_register('r0') == 1
    assert isinstance(next(iter_collect).event, DbgEventContinue)
    collect = next(iter_collect)
    event = collect.event
    assert isinstance(event, DbgEventBreakpoint)
    assert event.address == 16
    assert collect.get_register('r0') == 2
    assert isinstance(next(iter_collect).event, DbgEventContinue)


def test_breakpoint_add_with_callback():
    callback_called = []

    def break_callback(_: Debugger, __: Breakpoint) -> None:
        callback_called.append(True)

    harness = DbgCallbackHarness()
    b2d = Blob2Dbg(BlobArmEl32IncLoop, harness.event_callback)
    bp = b2d.dbg.breakpoint_add(
        16, condition=lambda d, b: b.hit_count < 1, hit_callback=break_callback
    )
    b2d.start()
    assert bp.hit_callback == break_callback
    assert len(callback_called) == 1


def test_breakpoint_add_invalid_type():
    b2d = Blob2Dbg(BlobArmEl32IncLoop)

    with pytest.raises(RuntimeError):
        b2d.dbg.breakpoint_add(4, None)


def test_breakpoint_add_already_exist():
    b2d = Blob2Dbg(BlobArmEl32IncLoop)
    bp = b2d.dbg.breakpoint_add(4)
    assert bp == b2d.dbg.breakpoint_add(4)


def test_breakpoint_del_by_instance():
    b2d = Blob2Dbg(BlobArmEl32IncLoop)
    bp = b2d.dbg.breakpoint_add(16)
    assert len(b2d.dbg.breakpoints) == 1
    assert b2d.dbg.breakpoints[0] == bp
    b2d.dbg.breakpoint_del(bp)
    assert len(b2d.dbg.breakpoints) == 0


def test_breakpoint_del_by_index():
    b2d = Blob2Dbg(BlobArmEl32IncLoop)
    bp = b2d.dbg.breakpoint_add(16)
    assert len(b2d.dbg.breakpoints) == 1
    assert b2d.dbg.breakpoints[0] == bp
    b2d.dbg.breakpoint_del_by_index(1)
    assert len(b2d.dbg.breakpoints) == 0


def test_breakpoint_del_by_instance_not_found():
    bp = Breakpoint(0xC0DEF00D, BreakpointType.OOB)
    b2d = Blob2Dbg(BlobArmEl32IncLoop)

    with pytest.raises(ValueError):
        b2d.dbg.breakpoint_del(bp)


def test_breakpoint_del_invalid_type():
    b2d = Blob2Dbg(BlobArmEl32IncLoop)

    with pytest.raises(ValueError):
        b2d.dbg.breakpoint_del(None)


def test_breakpoint_del_by_address_not_found():
    b2d = Blob2Dbg(BlobArmEl32IncLoop)

    with pytest.raises(ValueError):
        b2d.dbg.breakpoint_del(0xC0DEF00D)


def test_breakpoint_del_by_index_invalid():
    b2d = Blob2Dbg(BlobArmEl32IncLoop)

    with pytest.raises(ValueError):
        b2d.dbg.breakpoint_del_by_index(10)


def test_breakpoint_del_by_index_in_hook():
    def callback(dbg: Debugger, entry: DbgEventCollectEntry):
        if isinstance(entry.event, DbgEventBreakpoint) and entry.event.seq == 3:
            dbg.breakpoint_del_by_index(1)

    harness = DbgCallbackHarness(callback, register_collect=['r0'])
    b2d = Blob2Dbg(BlobArmEl32IncLoop, harness.event_callback)
    b2d.dbg.breakpoint_add(16)
    b2d.start()

    assert harness.count_events() == 5
    iter_collect = harness.iter_collect()
    assert isinstance(next(iter_collect).event, DbgEventBreakpointCreated)
    assert isinstance(next(iter_collect).event, DbgEventStartProgram)
    collect = next(iter_collect)
    event = collect.event
    assert isinstance(event, DbgEventBreakpoint)
    assert event.address == 16
    assert collect.get_register('r0') == 1
    assert isinstance(next(iter_collect).event, DbgEventBreakpointDeleted)
    assert isinstance(next(iter_collect).event, DbgEventContinue)


class TestWatchpointAddWithCondition:
    @staticmethod
    def callback(dbg: Debugger, collect: DbgEventCollectEntry):
        event = collect.event
        if isinstance(event, DbgEventWatchpoint):
            mem_chunk = dbg.mem.read(event.to_address, event.size)
            collect.add_data(event.to_address, mem_chunk)

    def _run_test(
        self,
        access: WatchpointAccess,
        expected_access: List[DbgEventWatchpointAccess]
    ):
        hit = len(expected_access)

        harness = DbgCallbackHarness(self.callback)
        b2d = Blob2Dbg(BlobArmEl32ReadWriteLoop, harness.event_callback)
        b2d.dbg.watchpoint_add(
            32, 36, access, condition=(lambda d, b: b.hit_count < hit)
        )
        b2d.start()

        assert harness.count_events() == hit * 2 + 2
        iter_collect = harness.iter_collect()
        assert isinstance(next(iter_collect).event, DbgEventBreakpointCreated)
        assert isinstance(next(iter_collect).event, DbgEventStartProgram)

        for idx, collect in enumerate(iter_collect):
            if idx % 2:
                assert isinstance(collect.event, DbgEventContinue)
            else:
                event = collect.event
                assert isinstance(event, DbgEventWatchpoint)

                if event.access == DbgEventWatchpointAccess.READ:
                    assert event.from_address == 8
                elif event.access == DbgEventWatchpointAccess.WRITE:
                    assert event.from_address == 12
                else:
                    raise ValueError('invalid watchpoint event type')

                assert event.access == expected_access[idx//2]
                assert collect.get_data(event.to_address) == b'\x00\x00\xa0\xe1'

    def test_access_read(self):
        exp = [DbgEventWatchpointAccess.READ, DbgEventWatchpointAccess.READ]
        self._run_test(WatchpointAccess.READ, exp)

    def test_access_write(self):
        exp = [DbgEventWatchpointAccess.WRITE, DbgEventWatchpointAccess.WRITE]
        self._run_test(WatchpointAccess.WRITE, exp)

    def test_access_read_write(self):
        exp = [DbgEventWatchpointAccess.READ, DbgEventWatchpointAccess.WRITE,
               DbgEventWatchpointAccess.READ, DbgEventWatchpointAccess.WRITE]
        self._run_test(WatchpointAccess.READ_WRITE, exp)


def test_watchpoint_add_error_end_inferior_to_begin():
    b2d = Blob2Dbg(BlobArmEl32ReadWriteLoop)
    with pytest.raises(ValueError):
        b2d.dbg.watchpoint_add(36, 32, WatchpointAccess.READ)


def test_watchpoint_add_invalid_type():
    b2d = Blob2Dbg(BlobArmEl32ReadWriteLoop)
    with pytest.raises(RuntimeError):
        b2d.dbg.watchpoint_add(32, 36, WatchpointAccess.READ, None)


def test_watchpoint_add_already_exist():
    b2d = Blob2Dbg(BlobArmEl32ReadWriteLoop)
    wp = b2d.dbg.watchpoint_add(32, 36, WatchpointAccess.READ)
    assert len(b2d.dbg.watchpoints) == 1
    wp2 = b2d.dbg.watchpoint_add(32, 36, WatchpointAccess.READ)
    assert len(b2d.dbg.watchpoints) == 1
    assert wp == wp2


def test_watchpoint_add_with_callback():
    callback_called = []

    def watch_callback(_: Debugger, __: Breakpoint) -> None:
        callback_called.append(True)

    b2d = Blob2Dbg(BlobArmEl32ReadWriteLoop)
    wp = b2d.dbg.watchpoint_add(
        32, 36, WatchpointAccess.READ, hit_callback=watch_callback
    )
    b2d.start()

    assert wp.hit_callback == watch_callback
    assert len(callback_called) == 10


def test_watchpoint_del_by_index():
    b2d = Blob2Dbg(BlobArmEl32ReadWriteLoop)
    b2d.dbg.watchpoint_add(32, 36, WatchpointAccess.READ)
    assert len(b2d.dbg.watchpoints) == 1
    b2d.dbg.watchpoint_del_by_index(1)
    assert len(b2d.dbg.watchpoints) == 0


def test_watchpoint_del_by_index_not_found():
    b2d = Blob2Dbg(BlobArmEl32ReadWriteLoop)
    b2d.dbg.watchpoint_add(32, 36, WatchpointAccess.READ)
    assert len(b2d.dbg.watchpoints) == 1

    with pytest.raises(ValueError):
        b2d.dbg.watchpoint_del_by_index(10)


def test_watchpoint_del_by_instance():
    b2d = Blob2Dbg(BlobArmEl32ReadWriteLoop)
    wp = b2d.dbg.watchpoint_add(32, 36, WatchpointAccess.READ)
    assert len(b2d.dbg.watchpoints) == 1
    b2d.dbg.watchpoint_del(wp)
    assert len(b2d.dbg.watchpoints) == 0


def test_watchpoint_del_by_instance_not_found():
    b2d = Blob2Dbg(BlobArmEl32ReadWriteLoop)
    wp = Watchpoint(82, 86, WatchpointAccess.WRITE, WatchpointType.OOB)
    b2d.dbg.watchpoint_add(32, 36, WatchpointAccess.READ)
    assert len(b2d.dbg.watchpoints) == 1

    with pytest.raises(ValueError):
        b2d.dbg.watchpoint_del(wp)


def test_watchpoint_del_invalid_type():
    b2d = Blob2Dbg(BlobArmEl32ReadWriteLoop)
    with pytest.raises(ValueError):
        b2d.dbg.watchpoint_del(None)


def test_watchpoint_del_by_area():
    b2d = Blob2Dbg(BlobArmEl32ReadWriteLoop)
    b2d.dbg.watchpoint_add(32, 36, WatchpointAccess.READ)
    assert len(b2d.dbg.watchpoints) == 1
    b2d.dbg.watchpoint_del((32, 36))
    assert len(b2d.dbg.watchpoints) == 0


def test_watchpoint_del_by_area_not_found():
    b2d = Blob2Dbg(BlobArmEl32ReadWriteLoop)
    b2d.dbg.watchpoint_add(32, 36, WatchpointAccess.READ)
    assert len(b2d.dbg.watchpoints) == 1

    with pytest.raises(ValueError):
        b2d.dbg.watchpoint_del((132, 136))


def test_watchpoint_del_by_index_in_hook():
    def callback(dbg: Debugger, collect: DbgEventCollectEntry):
        if isinstance(collect.event, DbgEventWatchpoint):
            dbg.watchpoint_del_by_index(1)

    harness = DbgCallbackHarness(callback)
    b2d = Blob2Dbg(BlobArmEl32ReadWriteLoop, harness.event_callback)
    b2d.dbg.watchpoint_add(32, 36, WatchpointAccess.READ)
    b2d.start()

    assert harness.count_events() == 5
    iter_event = harness.iter_event()
    assert isinstance(next(iter_event), DbgEventBreakpointCreated)
    assert isinstance(next(iter_event), DbgEventStartProgram)
    event = next(iter_event)
    assert isinstance(event, DbgEventWatchpoint)
    assert event.access == DbgEventWatchpointAccess.READ
    assert event.from_address == 8
    assert isinstance(next(iter_event), DbgEventBreakpointDeleted)
    assert isinstance(next(iter_event), DbgEventContinue)


def test_set_step_from_breakpoint():
    def callback(dbg: Debugger, collect: DbgEventCollectEntry):
        if (isinstance(collect.event, DbgEventBreakpoint)
                and collect.event.seq == 3):
            dbg.set_step_inst()
        elif (isinstance(collect.event, DbgEventStepInst)
              and collect.event.seq == 5):
            dbg.set_step_inst()

    harness = DbgCallbackHarness(callback)
    b2d = Blob2Dbg(BlobArmEl32MultiBlock, harness.event_callback)
    b2d.dbg.breakpoint_add(16, condition=lambda _, bp: bp.hit_count < 2)
    b2d.start()

    assert harness.count_events() == 8
    iter_event = harness.iter_event()
    assert isinstance(next(iter_event), DbgEventBreakpointCreated)
    assert isinstance(next(iter_event), DbgEventStartProgram)
    event = next(iter_event)
    assert isinstance(event, DbgEventBreakpoint)
    assert event.address == 16
    assert isinstance(next(iter_event), DbgEventContinue)
    event = next(iter_event)
    assert isinstance(event, DbgEventStepInst)
    assert event.address == 20
    assert isinstance(next(iter_event), DbgEventContinue)
    event = next(iter_event)
    assert isinstance(event, DbgEventStepInst)
    assert event.address == 24
    assert isinstance(next(iter_event), DbgEventContinue)


def test_step_inst_from_watchpoint():
    def callback(dbg: Debugger, collect: DbgEventCollectEntry):
        if (isinstance(collect.event, DbgEventWatchpoint)
                and collect.event.seq == 3):
            dbg.set_step_inst()
        elif (isinstance(collect.event, DbgEventStepInst)
              and collect.event.seq == 5):
            dbg.set_step_inst()

    harness = DbgCallbackHarness(callback)
    b2d = Blob2Dbg(BlobArmEl32ReadWriteLoop, harness.event_callback)
    b2d.dbg.watchpoint_add(32, 36, WatchpointAccess.WRITE,
                           condition=lambda _, bp: bp.hit_count < 1)
    b2d.start()

    assert harness.count_events() == 8
    iter_event = harness.iter_event()
    assert isinstance(next(iter_event), DbgEventBreakpointCreated)
    assert isinstance(next(iter_event), DbgEventStartProgram)
    event = next(iter_event)
    assert isinstance(event, DbgEventWatchpoint)
    assert event.from_address == 12
    assert isinstance(next(iter_event), DbgEventContinue)
    event = next(iter_event)
    assert isinstance(event, DbgEventStepInst)
    assert event.address == 16
    assert isinstance(next(iter_event), DbgEventContinue)
    event = next(iter_event)
    assert isinstance(event, DbgEventStepInst)
    assert event.address == 20
    assert isinstance(next(iter_event), DbgEventContinue)


def test_complete_run():
    expected_dump_complete = {
        'r0': 5, 'r1': 5, 'r2': 0, 'r3': 0, 'r4': 0, 'r5': 0, 'r6': 0,
        'r7': 0, 'r8': 0, 'r9': 0, 'r10': 0, 'r11': 0, 'r12': 0, 'sp': 0,
        'lr': 0, 'pc': 80, 'cpsr': 1610613203
    }
    b2d = Blob2Dbg(BlobArmEl32MultiBlock)
    b2d.start()
    reg_filter = [
        'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10',
        'r11', 'r12', 'sp', 'lr', 'pc', 'cpsr'
    ]
    assert expected_dump_complete == b2d.dbg.regs.save(reg_filter)
