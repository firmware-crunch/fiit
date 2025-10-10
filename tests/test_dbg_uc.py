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

from typing import List, Literal, Callable

import pytest

import unicorn
from unicorn.unicorn_const import (
    UC_ERR_FETCH_UNMAPPED, UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_UNMAPPED
)

from .fixtures import MetaBinBlob, Blob2Cpu
from .fixtures.blobs import (
    BlobArmEl32MemFetchUnmapped,
    BlobArmEl32MemReadUnmapped,
    BlobArmEl32MemWriteUnmapped,
    BlobArmEl32IncLoop,
    BlobArmEl32ReadWriteLoop,
    BlobArmEl32MultiBlock
)

from fiit.emunicorn import CpuUnicorn
from fiit.dbg import (
    DebuggerUnicorn, DebuggerFactory,
    DBG_EVENT_BREAKPOINT,
    DBG_EVENT_STEP,
    DBG_EVENT_WATCHPOINT,
    DBG_EVENT_SEGFAULT
)

# ==============================================================================


class Blob2Dbg(Blob2Cpu):
    def __init__(self, bin_blob: MetaBinBlob, **kwargs):
        Blob2Cpu.__init__(self, bin_blob, 'unicorn')
        self.dbg = DebuggerFactory.get(self.cpu, **kwargs)
        assert isinstance(self.cpu.cpu, CpuUnicorn)
        assert isinstance(self.dbg, DebuggerUnicorn)


class CallbackHarness:
    def __init__(self, callback: Callable):
        self.count = 0
        self.callback = callback

    def callback_wrapper(self, *args, **kwargs):
        self.count += 1
        self.callback(*args, **kwargs)


def test_segfault_fetch():
    def debug_callback(dbg: DebuggerUnicorn, event_id: int, args: dict):
        assert event_id == DBG_EVENT_SEGFAULT
        assert args['address'] == 0xffff0000

    harness = CallbackHarness(debug_callback)

    with pytest.raises(unicorn.unicorn.UcError) as exc_info:
        Blob2Dbg(BlobArmEl32MemFetchUnmapped,
                 event_callback=harness.callback_wrapper).start()

    assert exc_info.value.errno == UC_ERR_FETCH_UNMAPPED
    assert harness.count == 1


def test_segfault_read():
    def debug_callback(dbg: DebuggerUnicorn, event_id: int, args: dict):
        assert event_id == DBG_EVENT_SEGFAULT
        assert args['address'] == 0xffffff00

    harness = CallbackHarness(debug_callback)

    with pytest.raises(unicorn.unicorn.UcError) as exc_info:
        Blob2Dbg(BlobArmEl32MemReadUnmapped,
                 event_callback=harness.callback_wrapper).start()

    assert exc_info.value.errno == UC_ERR_READ_UNMAPPED
    assert harness.count == 1


def test_segfault_write():
    def debug_callback(dbg: DebuggerUnicorn, event_id: int, args: dict):
        assert event_id == DBG_EVENT_SEGFAULT
        assert args['address'] == 0xffffff00

    harness = CallbackHarness(debug_callback)

    with pytest.raises(unicorn.unicorn.UcError) as exc_info:
        Blob2Dbg(BlobArmEl32MemWriteUnmapped,
                 event_callback=harness.callback_wrapper).start()

    assert exc_info.value.errno == UC_ERR_WRITE_UNMAPPED
    assert harness.count == 1


class TestBreakpoint:
    def bp_callback(self, dbg: DebuggerUnicorn, event_id: int, args: dict):
        assert event_id == DBG_EVENT_BREAKPOINT
        assert dbg.regs.arch_pc == 16
        assert dbg.regs.arch_pc == args['address']
        assert dbg.regs.r0 == self.expected_r0[self.bp_count]
        self.bp_count += 1
        assert self.bp_count < 3

    def test(self):
        self.bp_count = 0
        self.expected_r0 = [1, 2]

        emu_dbg = Blob2Dbg(BlobArmEl32IncLoop,
                           event_callback=self.bp_callback)
        dbg = emu_dbg.dbg
        dbg.breakpoint_set(16, 2)
        self.bp_count = 0
        emu_dbg.start()
        assert self.bp_count == 2


class TestDeleteBreakpoint:
    def bp_callback(self, dbg: DebuggerUnicorn, event_id: int, args: dict):
        assert event_id == DBG_EVENT_BREAKPOINT
        assert dbg.regs.arch_pc == 16
        assert dbg.regs.arch_pc == args['address']
        assert dbg.regs.r0 == self.expected_r0[self.bp_count]
        dbg.breakpoint_del_by_index(1)
        self.bp_count += 1
        assert self.bp_count == 1

    def test(self):
        self.expected_r0 = [1, 2]
        emu_dbg = Blob2Dbg(BlobArmEl32IncLoop,
                           event_callback=self.bp_callback)
        dbg = emu_dbg.dbg
        dbg.breakpoint_set(16, 4)
        self.bp_count = 0
        emu_dbg.start()
        assert self.bp_count == 1


class TestReadWatchpoint:
    def callback(self, dbg: DebuggerUnicorn, event_id: int, args: dict):
        assert event_id == DBG_EVENT_WATCHPOINT
        assert args['access'] == self.expected_access[self.count]
        self.count += 1

        if args['access'] == 'r':
            assert args['pc_address'] == 8
        if args['access'] == 'w':
            assert args['pc_address'] == 12

        assert dbg.mem.read(args['address'], args['size']) \
               == b'\x00\x00\xa0\xe1'

    def _run_test(self, access: Literal['r', 'w', 'rw'], hit: int,
                  expected_access: List[str]):
        emu_dbg = Blob2Dbg(BlobArmEl32ReadWriteLoop,
                           event_callback=self.callback)
        dbg = emu_dbg.dbg
        dbg.watchpoint_set(32, 36, access, hit)
        self.expected_access = expected_access
        self.count = 0
        emu_dbg.start()
        assert self.count == hit

    def test_read_watchpoint(self):
        self._run_test('r', 2, ['r', 'r'])

    def test_write_watchpoint(self):
        self._run_test('w', 2, ['w', 'w'])

    def test_read_write_watchpoint(self):
        self._run_test('rw', 4, ['r', 'w', 'r', 'w'])


def test_invalid_watchpoint():
    emu_dbg = Blob2Dbg(BlobArmEl32ReadWriteLoop)
    with pytest.raises(ValueError):
        emu_dbg.dbg.watchpoint_set(36, 32, 'r', 5)


class TestDeleteWatchpoint:
    def callback(self, dbg: DebuggerUnicorn, event_id: int, args: dict):
        assert event_id == DBG_EVENT_WATCHPOINT
        assert args['access'] == 'r'
        assert args['pc_address'] == 8
        self.count += 1
        dbg.watchpoint_del_by_index(1)

    def test(self):
        emu_dbg = Blob2Dbg(BlobArmEl32ReadWriteLoop,
                           event_callback=self.callback)
        emu_dbg.dbg.watchpoint_set(32, 36, 'r')
        self.count = 0
        emu_dbg.start()
        assert self.count == 1


class TestSetStepFromBp:
    def bp_callback(self, dbg: DebuggerUnicorn, event_id: int, args: dict):
        self.bp_count += 1
        assert self.bp_count < 4

        if self.bp_count == 1:
            assert event_id == DBG_EVENT_BREAKPOINT
            assert args['address'] == 16
            dbg.set_step()
        elif self.bp_count == 2:
            assert event_id == DBG_EVENT_STEP
            assert args['address'] == 20
            dbg.set_step()
        elif self.bp_count == 3:
            assert event_id == DBG_EVENT_STEP
            assert args['address'] == 24

    def test(self):
        emu_dbg = Blob2Dbg(BlobArmEl32MultiBlock,
                           event_callback=self.bp_callback)
        dbg = emu_dbg.dbg
        dbg.breakpoint_set(16, 1)
        self.bp_count = 0
        emu_dbg.start()
        assert self.bp_count == 3


class TestSetFromWatchpoint:
    def callback(self, dbg: DebuggerUnicorn, event_id: int, args: dict):
        self.count += 1

        if self.count == 1:
            assert event_id == DBG_EVENT_WATCHPOINT
            self.count_watch += 1
            assert args['pc_address'] == 12
            dbg.set_step()
        if self.count == 3:
            assert event_id == DBG_EVENT_WATCHPOINT
            self.count_watch += 1
            assert args['pc_address'] == 12
            dbg.set_step()
        elif self.count == 2:
            assert event_id == DBG_EVENT_STEP
            self.count_step += 1
            assert args['address'] == 16
        elif self.count == 4:
            assert event_id == DBG_EVENT_STEP
            self.count_step += 1
            assert args['address'] == 16

    def test(self):
        emu_dbg = Blob2Dbg(BlobArmEl32ReadWriteLoop,
                           event_callback=self.callback)
        emu_dbg.dbg.watchpoint_set(32, 36, 'w', 2)
        self.count = 0
        self.count_watch = 0
        self.count_step = 0
        emu_dbg.start()
        assert self.count == 4
        assert self.count_watch == 2
        assert self.count_step == 2


def test_disassemble():
    expected_dis = (
        '0x00000000:\t0000a0e3            \tmov\tr0, #0\n'
        '0x00000004:\tffffffea            \tb\t#8\n'
        '0x00000008:\t010080e2            \tadd\tr0, r0, #1\n'
        '0x0000000c:\t0a0050e3            \tcmp\tr0, #0xa\n'
        '0x00000010:\tfcffff1a            \tbne\t#8\n'
        '0x00000014:\t0110a0e3            \tmov\tr1, #1')
    assert ('\n'.join(Blob2Dbg(BlobArmEl32IncLoop).dbg.disassemble(0x0, 6))
            == expected_dis)


def test_disassemble_unmapped_address():
    with pytest.raises(ValueError):
        Blob2Dbg(BlobArmEl32IncLoop).dbg.disassemble(0xff409000, 6)
