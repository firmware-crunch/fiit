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

from typing import List, Literal
import logging
import itertools
import contextlib

import pytest
from unittest.mock import patch

from .fixtures.blobs import (
    BlobArmEl32IncLoop,
    BlobArmEl32ReadWriteLoop,
    BlobArmEl32MultiBlock
)

from fiit.shell import Shell
from fiit.shell.front import DbgFrontend
from fiit.dbg import Debugger
from fiit.dbg import (
    DbgEventBreakpoint,
    DbgEventWatchpoint,
    DbgEventWatchpointAccess,
    DbgEventStepInst,
    DbgEventStartProgram,
    DbgEventBreakpointCreated,
    DbgEventBreakpointDeleted,
    DbgEventContinue
)

from .fixtures import DbgCallbackHarness, DbgEventCollectEntry, Blob2Dbg

# ==============================================================================


@pytest.fixture(autouse=True)
def clear_log():
    """
    Remove handlers from all loggers
    copied from https://github.com/neutrons/SNAPRed/pull/34/files
    """
    import logging

    loggers = (
        [logging.getLogger()] + list(logging.Logger.manager.loggerDict.values())
    )
    for logger in loggers:
        handlers = getattr(logger, "handlers", [])
        for handler in handlers:
            logger.removeHandler(handler)


def test_disassemble(capsys):
    out = \
        '0x00000000:\t0000a0e3            \tmov\tr0, #0\n' \
        '0x00000004:\tffffffea            \tb\t#8\n' \
        '0x00000008:\t010080e2            \tadd\tr0, r0, #1\n' \
        '0x0000000c:\t0a0050e3            \tcmp\tr0, #0xa\n' \
        '0x00000010:\tfcffff1a            \tbne\t#8\n' \
        '0x00000014:\t0110a0e3            \tmov\tr1, #1'
    front = DbgFrontend([Blob2Dbg(BlobArmEl32IncLoop).dbg], Shell())
    front.disassemble('0x0 6')
    assert capsys.readouterr().out == out


def test_mem_read(capsys):
    out = \
        '00000000  00 00 a0 e3 ff ff ff ea  01 00 80 e2 0a 00 50 e3 |..............P.|\n' \
        '00000010  fc ff ff 1a 01 10 a0 e3  00 00 a0 e1 00 00 00 00 |................|\n' \
        '00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|\n' \
        '00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|\n' \
        '00000040  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|\n' \
        '00000050  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|\n' \
        '00000060  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|\n' \
        '00000070  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|\n' \
        '00000080  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|\n' \
        '00000090  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|\n' \
        '000000a0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|\n' \
        '000000b0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|\n' \
        '000000c0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|\n' \
        '000000d0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|\n' \
        '000000e0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|\n' \
        '000000f0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|'
    front = DbgFrontend([Blob2Dbg(BlobArmEl32IncLoop).dbg], Shell())
    front.mem_read('0x0 256')
    assert capsys.readouterr().out == out


def test_mem_write_word():
    front = DbgFrontend([Blob2Dbg(BlobArmEl32IncLoop).dbg], Shell())
    front.mem_write('0x50 word 0xdeadbeef')
    assert front.dbg.cpu.mem.read(0x50, 4) == b'\xef\xbe\xad\xde'


def test_mem_write_cstring():
    cstring = 'patched_boot_line("/dev/mp0")'
    front = DbgFrontend([Blob2Dbg(BlobArmEl32IncLoop).dbg], Shell())
    front.mem_write(f'0x50 cstring {cstring}')
    assert front.dbg.cpu.mem.read(0x50, len(cstring)).decode() == cstring


def test_register_set():
    expected_value = 0xffeebbcc
    front = DbgFrontend([Blob2Dbg(BlobArmEl32MultiBlock).dbg], Shell())
    front.register_set(f'r2 {expected_value:#x}')
    assert front.dbg.cpu.regs.r2 == expected_value


def test_register_get(capsys):
    out = 'r0    0x00000005   r1    0x00000005   r2    0x00000000   \n' \
          'pc    0x00000050   cpsr  0x600001d3   '
    wrap = Blob2Dbg(BlobArmEl32MultiBlock)
    front = DbgFrontend([wrap.dbg], Shell())
    wrap.start()
    front.register_get('r0 r1 r2 pc cpsr')
    assert capsys.readouterr().out == out


@pytest.mark.usefixtures('clear_log')
def test_break_add(caplog):
    harness = DbgCallbackHarness()
    caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
    b2d = Blob2Dbg(BlobArmEl32IncLoop, harness.event_callback)
    front = DbgFrontend([b2d.dbg], Shell())
    front.break_add('0x10')

    with patch('fiit.plugins.shell.Shell.wait_for_prompt_suspend'):
        b2d.start()

    assert harness.count_events() == 22
    iter_event = harness.iter_event()
    assert isinstance(next(iter_event), DbgEventBreakpointCreated)
    assert isinstance(next(iter_event), DbgEventStartProgram)

    for idx, event in enumerate(iter_event):  # loop because x10
        if idx % 2 == 0:
            assert isinstance(event, DbgEventBreakpoint)
        else:
            assert isinstance(event, DbgEventContinue)

    assert len(caplog.record_tuples) > 0

    for mod, level, _ in caplog.record_tuples:  # loop because x10
        assert mod == 'dbg@cpu0'
        assert level == logging.INFO

    iter_log = iter(caplog.record_tuples)
    assert next(iter_log)[2] == 'breakpoint created at 0x00000010'
    assert next(iter_log)[2] == 'start program at 0x00000000'

    for i, l in enumerate(iter_log):  # loop because x10
        if i % 2 == 0:
            assert l[2] == f'breakpoint hit at 0x00000010, hit {i//2+1}'
        else:
            assert l[2] == 'continue from 0x00000010'


class TestBreakDel:
    def callback(self, _, collect: DbgEventCollectEntry):
        event = collect.event
        if isinstance(event, DbgEventBreakpoint) and event.seq == 5:
            self.front.break_del('1')

    @pytest.mark.usefixtures('clear_log')
    def test(self, caplog):
        harness = DbgCallbackHarness(self.callback)
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        b2d = Blob2Dbg(BlobArmEl32IncLoop, harness.event_callback)
        self.front = DbgFrontend([b2d.dbg], Shell())
        self.front.break_add('0x10')

        with patch('fiit.plugins.shell.Shell.wait_for_prompt_suspend'):
            b2d.start()

        assert harness.count_events() == 7
        iter_event = harness.iter_event()
        assert isinstance(next(iter_event), DbgEventBreakpointCreated)
        assert isinstance(next(iter_event), DbgEventStartProgram)
        assert isinstance(next(iter_event), DbgEventBreakpoint)
        assert isinstance(next(iter_event), DbgEventContinue)
        assert isinstance(next(iter_event), DbgEventBreakpoint)
        assert isinstance(next(iter_event), DbgEventBreakpointDeleted)
        assert isinstance(next(iter_event), DbgEventContinue)

        for mod, level, _ in caplog.record_tuples:
            assert (mod, level) == ('dbg@cpu0', logging.INFO)

        logs = [
            'breakpoint created at 0x00000010',
            'start program at 0x00000000',
            'breakpoint hit at 0x00000010, hit 1',
            'continue from 0x00000010',
            'breakpoint hit at 0x00000010, hit 2',
            'breakpoint deleted at 0x00000010',
            'continue from 0x00000010',
        ]
        assert logs == [log_rec[2] for log_rec in caplog.record_tuples]


def test_break_print(capsys):
    out = (
        '  index  address       hit\n'
        '-------  ----------  -----\n'
        '      1  0x00000010      0\n')
    front = DbgFrontend([Blob2Dbg(BlobArmEl32IncLoop).dbg], Shell())
    front.break_add('0x10 4')
    front.break_print('')
    assert capsys.readouterr().out == out


class TestWatch:
    def callback(self, dbg: Debugger, collect: DbgEventCollectEntry):
        event = collect.event
        if isinstance(event, DbgEventWatchpoint):
            chunk = dbg.mem.read(event.to_address, event.size)
            collect.add_data(event.to_address, chunk)
            if event.seq - self.prev_event_nb == self.hit * 2 - 1:
                dbg.watchpoint_del_by_index(1)

    @contextlib.contextmanager
    def _bootstrap_test(self, hit: int, expected_access: List[int]):
        harness = DbgCallbackHarness(self.callback)
        b2d = Blob2Dbg(BlobArmEl32ReadWriteLoop, harness.event_callback)
        front = DbgFrontend([b2d.dbg], Shell())

        yield front

        self.hit = hit
        self.prev_event_nb = 2  # start program + set breakpoint
        hit_and_cont = hit*2

        with patch("fiit.plugins.shell.Shell.wait_for_prompt_suspend"):
            b2d.start()

        assert harness.count_events() == hit_and_cont + 3
        iter_collect = harness.iter_collect()
        assert isinstance(next(iter_collect).event, DbgEventBreakpointCreated)
        assert isinstance(next(iter_collect).event, DbgEventStartProgram)

        for idx, collect in enumerate(itertools.islice(iter_collect, hit_and_cont - 1)):
            if idx % 2 == 0:
                event = collect.event
                assert isinstance(event, DbgEventWatchpoint)
                assert collect.get_data(event.to_address) == b'\x00\x00\xa0\xe1'
                assert event.access == expected_access[idx//2]
                if event.access == DbgEventWatchpointAccess.READ:
                    assert event.from_address == 8
                elif event.access == DbgEventWatchpointAccess.WRITE:
                    assert event.from_address == 12
            else:
                assert isinstance(collect.event, DbgEventContinue)

        assert isinstance(next(iter_collect).event, DbgEventBreakpointDeleted)
        assert isinstance(next(iter_collect).event, DbgEventContinue)

    def _test_area(
        self, access: Literal['r', 'w', 'rw'], hit: int,
        expected_access: List[int]
    ) -> None:
        with self._bootstrap_test(hit, expected_access) as front:
            front.watch_area(f'{access} 0x20 0x24')

    def _test_var(
        self, access: Literal['r', 'w', 'rw'], hit: int,
        expected_access: List[int]
    ) -> None:
        with self._bootstrap_test(hit, expected_access) as front:
            front.watch_var(f'{access} 0x20')

    @staticmethod
    def _check_log(
         records, mod: str, level: int, expected_logs: List[str]
    ) -> None:
        assert len(records) == len(expected_logs)

        for r_mod, r_level, _ in records:
            assert (mod, level) == (r_mod, r_level)

        assert expected_logs == [log_rec[2] for log_rec in records]

    @pytest.mark.usefixtures('clear_log')
    def test_watch_mem_area_read(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        self._test_area('r', 2, [DbgEventWatchpointAccess.READ,
                                 DbgEventWatchpointAccess.READ])
        logs = [
            'watchpoint created with access r- on memory range 0x00000020-0x00000024',
            'start program at 0x00000000',
            'watchpoint hit, r- access from 0x00000008 to 0x00000020-0x00000024, hit 1',
            'continue from 0x00000020',
            'watchpoint hit, r- access from 0x00000008 to 0x00000020-0x00000024, hit 2',
            'watchpoint deleted with access r- on memory range 0x00000020-0x00000024',
            'continue from 0x00000020'
        ]
        self._check_log(caplog.record_tuples, 'dbg@cpu0', logging.INFO, logs)

    @pytest.mark.usefixtures('clear_log')
    def test_watch_mem_area_write(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        self._test_area('w', 2, [DbgEventWatchpointAccess.WRITE,
                                 DbgEventWatchpointAccess.WRITE])
        logs = [
            'watchpoint created with access -w on memory range 0x00000020-0x00000024',
            'start program at 0x00000000',
            'watchpoint hit, -w access from 0x0000000c to 0x00000020-0x00000024, hit 1',
            'continue from 0x00000020',
            'watchpoint hit, -w access from 0x0000000c to 0x00000020-0x00000024, hit 2',
            'watchpoint deleted with access -w on memory range 0x00000020-0x00000024',
            'continue from 0x00000020',
        ]
        self._check_log(caplog.record_tuples, 'dbg@cpu0', logging.INFO, logs)

    @pytest.mark.usefixtures('clear_log')
    def test_watch_mem_area_read_write(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        self._test_area('rw', 4, [DbgEventWatchpointAccess.READ,
                                  DbgEventWatchpointAccess.WRITE,
                                  DbgEventWatchpointAccess.READ,
                                  DbgEventWatchpointAccess.WRITE])
        logs = [
            'watchpoint created with access rw on memory range 0x00000020-0x00000024',
            'start program at 0x00000000',
            'watchpoint hit, r- access from 0x00000008 to 0x00000020-0x00000024, hit 1',
            'continue from 0x00000020',
            'watchpoint hit, -w access from 0x0000000c to 0x00000020-0x00000024, hit 2',
            'continue from 0x00000020',
            'watchpoint hit, r- access from 0x00000008 to 0x00000020-0x00000024, hit 3',
            'continue from 0x00000020',
            'watchpoint hit, -w access from 0x0000000c to 0x00000020-0x00000024, hit 4',
            'watchpoint deleted with access rw on memory range 0x00000020-0x00000024',
            'continue from 0x00000020',
        ]
        self._check_log(caplog.record_tuples, 'dbg@cpu0', logging.INFO, logs)

    @pytest.mark.usefixtures('clear_log')
    def test_watch_var_read(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        self._test_var('r', 2, [DbgEventWatchpointAccess.READ,
                                DbgEventWatchpointAccess.READ])
        logs = [
            'watchpoint created with access r- on memory range 0x00000020-0x00000020',
            'start program at 0x00000000',
            'watchpoint hit, r- access from 0x00000008 to 0x00000020-0x00000020, hit 1',
            'continue from 0x00000020',
            'watchpoint hit, r- access from 0x00000008 to 0x00000020-0x00000020, hit 2',
            'watchpoint deleted with access r- on memory range 0x00000020-0x00000020',
            'continue from 0x00000020',
        ]
        self._check_log(caplog.record_tuples, 'dbg@cpu0', logging.INFO, logs)

    @pytest.mark.usefixtures('clear_log')
    def test_watch_var_write(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        self._test_var('w', 2, [DbgEventWatchpointAccess.WRITE,
                                DbgEventWatchpointAccess.WRITE])
        logs = [
            'watchpoint created with access -w on memory range 0x00000020-0x00000020',
            'start program at 0x00000000',
            'watchpoint hit, -w access from 0x0000000c to 0x00000020-0x00000020, hit 1',
            'continue from 0x00000020',
            'watchpoint hit, -w access from 0x0000000c to 0x00000020-0x00000020, hit 2',
            'watchpoint deleted with access -w on memory range 0x00000020-0x00000020',
            'continue from 0x00000020',
        ]
        self._check_log(caplog.record_tuples, 'dbg@cpu0', logging.INFO, logs)

    @pytest.mark.usefixtures('clear_log')
    def test_watch_var_read_write(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        self._test_var('rw', 4, [DbgEventWatchpointAccess.READ,
                                 DbgEventWatchpointAccess.WRITE,
                                 DbgEventWatchpointAccess.READ,
                                 DbgEventWatchpointAccess.WRITE])
        logs = [
            'watchpoint created with access rw on memory range 0x00000020-0x00000020',
            'start program at 0x00000000',
            'watchpoint hit, r- access from 0x00000008 to 0x00000020-0x00000020, hit 1',
            'continue from 0x00000020',
            'watchpoint hit, -w access from 0x0000000c to 0x00000020-0x00000020, hit 2',
            'continue from 0x00000020',
            'watchpoint hit, r- access from 0x00000008 to 0x00000020-0x00000020, hit 3',
            'continue from 0x00000020',
            'watchpoint hit, -w access from 0x0000000c to 0x00000020-0x00000020, hit 4',
            'watchpoint deleted with access rw on memory range 0x00000020-0x00000020',
            'continue from 0x00000020',
        ]
        self._check_log(caplog.record_tuples, 'dbg@cpu0', logging.INFO, logs)


class TestWatchDel:
    def callback(self, _, collect: DbgEventCollectEntry):
        event = collect.event
        if isinstance(event, DbgEventWatchpoint) and event.seq == 3:
            self.front.watch_del('1')

    @pytest.mark.usefixtures('clear_log')
    def test(self, caplog):
        harness = DbgCallbackHarness(self.callback)
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        b2d = Blob2Dbg(BlobArmEl32ReadWriteLoop, harness.event_callback)
        self.front = DbgFrontend([b2d.dbg], Shell())
        self.front.watch_area('r 0x20 0x24')

        with patch("fiit.plugins.shell.Shell.wait_for_prompt_suspend"):
            b2d.start()

        assert harness.count_events() == 5
        iter_event = harness.iter_event()
        assert isinstance(next(iter_event), DbgEventBreakpointCreated)
        assert isinstance(next(iter_event), DbgEventStartProgram)
        assert isinstance(next(iter_event), DbgEventWatchpoint)
        assert isinstance(next(iter_event), DbgEventBreakpointDeleted)
        assert isinstance(next(iter_event), DbgEventContinue)

        logs = [
            'watchpoint created with access r- on memory range 0x00000020-0x00000024',
            'start program at 0x00000000',
            'watchpoint hit, r- access from 0x00000008 to 0x00000020-0x00000024, hit 1',
            'watchpoint deleted with access r- on memory range 0x00000020-0x00000024',
            'continue from 0x00000020'
        ]
        assert logs == [log_rec[2] for log_rec in caplog.record_tuples]
        for mod, level, _ in caplog.record_tuples:
            assert (mod, level) == ('dbg@cpu0', logging.INFO)


def test_watch_print(capsys):
    out = (
        '  index  begin       end         access      hit\n'
        '-------  ----------  ----------  --------  -----\n'
        '      1  0x00000020  0x00000024  r-            0\n'
    )
    front = DbgFrontend([Blob2Dbg(BlobArmEl32ReadWriteLoop).dbg],
                        Shell())
    front.watch_area('r 0x20 0x24')
    front.watch_print('')
    assert capsys.readouterr().out == out


class TestSetStepInstFromBp:
    def callback(self, _, collect: DbgEventCollectEntry):
        event = collect.event
        if isinstance(event, DbgEventBreakpoint) and event.seq == 3:
            self.front._current_event = event  # dirty patch to unlock step
            self.front.step('')
        elif isinstance(event, DbgEventStepInst) and event.seq == 5:
            self.front._current_event = event  # dirty patch to unlock step
            self.front.step('')

    @pytest.mark.usefixtures('clear_log')
    def test(self, caplog):
        harness = DbgCallbackHarness(self.callback)
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        b2d = Blob2Dbg(BlobArmEl32MultiBlock, harness.event_callback)
        self.front = DbgFrontend([b2d.dbg], Shell())
        self.front.break_add('0x10')

        with patch("fiit.plugins.shell.Shell.wait_for_prompt_suspend"):
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

        logs = [
            'breakpoint created at 0x00000010',
            'start program at 0x00000000',
            'breakpoint hit at 0x00000010, hit 1',
            'continue from 0x00000010',
            'step instruction at 0x00000014',
            'continue from 0x00000014',
            'step instruction at 0x00000018',
            'continue from 0x00000018',
        ]
        assert logs == [log_rec[2] for log_rec in caplog.record_tuples]
        for mod, level, _ in caplog.record_tuples:
            assert (mod, level) == ('dbg@cpu0', logging.INFO)


class TestContinueFromBp:
    def callback(self, _, collect: DbgEventCollectEntry):
        event = collect.event
        if isinstance(event, DbgEventBreakpoint) and event.seq == 3:
            self.front._current_event = event  # dirty patch to unlock step
            self.front.cont('')

    @pytest.mark.usefixtures('clear_log')
    def test(self, caplog):
        harness = DbgCallbackHarness(self.callback)
        b2d = Blob2Dbg(BlobArmEl32MultiBlock, harness.event_callback)
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        self.front = DbgFrontend([b2d.dbg], Shell())
        self.front.break_add('0x10')

        with patch("fiit.plugins.shell.Shell.wait_for_prompt_suspend"):
            b2d.start()

        assert harness.count_events() == 4
        iter_event = harness.iter_event()
        assert isinstance(next(iter_event), DbgEventBreakpointCreated)
        assert isinstance(next(iter_event), DbgEventStartProgram)
        event = next(iter_event)
        assert isinstance(event, DbgEventBreakpoint)
        assert isinstance(next(iter_event), DbgEventContinue)
        assert b2d.dbg.regs.arch_pc == 0x50

        logs = [
            'breakpoint created at 0x00000010',
            'start program at 0x00000000',
            'breakpoint hit at 0x00000010, hit 1',
            'continue from 0x00000010',
        ]
        assert logs == [log_rec[2] for log_rec in caplog.record_tuples]
        for mod, level, _ in caplog.record_tuples:
            assert (mod, level) == ('dbg@cpu0', logging.INFO)
