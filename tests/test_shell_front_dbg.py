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

import pytest
from unittest.mock import patch

from .fixtures import Blob2Cpu, MetaBinBlob
from .fixtures.blobs import (
    BlobArmEl32IncLoop,
    BlobArmEl32ReadWriteLoop,
    BlobArmEl32MultiBlock
)

from fiit.shell import Shell
from fiit.shell.front_dbg import DbgFrontend
from fiit.dbg import (
    DebuggerFactory,
    Debugger,
    DBG_EVENT_BREAKPOINT,
    DBG_EVENT_STEP,
    DBG_EVENT_WATCHPOINT
)

# ==============================================================================


@pytest.fixture(autouse=True)
def clear_log():
    """
    Remove handlers from all loggers
    copied from https://github.com/neutrons/SNAPRed/pull/34/files
    """
    import logging

    loggers = [logging.getLogger()] + list(logging.Logger.manager.loggerDict.values())
    for logger in loggers:
        handlers = getattr(logger, "handlers", [])
        for handler in handlers:
            logger.removeHandler(handler)


class BinBlob2Dbg(Blob2Cpu):
    def __init__(self, bin_blob: MetaBinBlob, **kwargs):
        Blob2Cpu.__init__(self, bin_blob, cpu_name='cpu0')
        self.dbg = DebuggerFactory.get(self.cpu, **kwargs)


def test_disassemble(capsys):
    out = \
        '0x00000000:\t0000a0e3            \tmov\tr0, #0\n' \
        '0x00000004:\tffffffea            \tb\t#8\n' \
        '0x00000008:\t010080e2            \tadd\tr0, r0, #1\n' \
        '0x0000000c:\t0a0050e3            \tcmp\tr0, #0xa\n' \
        '0x00000010:\tfcffff1a            \tbne\t#8\n' \
        '0x00000014:\t0110a0e3            \tmov\tr1, #1'
    front = DbgFrontend([BinBlob2Dbg(BlobArmEl32IncLoop).dbg], Shell())
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
    front = DbgFrontend([BinBlob2Dbg(BlobArmEl32IncLoop).dbg], Shell())
    front.mem_read('0x0 256')
    assert capsys.readouterr().out == out


def test_write_word():
    front = DbgFrontend([BinBlob2Dbg(BlobArmEl32IncLoop).dbg], Shell())
    front.mem_write('0x50 word 0xdeadbeef')
    assert front.dbg.cpu.mem.read(0x50, 4) == b'\xef\xbe\xad\xde'


def test_write_cstring():
    cstring = 'patched_boot_line("/dev/mp0")'
    front = DbgFrontend([BinBlob2Dbg(BlobArmEl32IncLoop).dbg], Shell())
    front.mem_write(f'0x50 cstring {cstring}')
    assert front.dbg.cpu.mem.read(0x50, len(cstring)).decode() == cstring


def test_register_set():
    expected_value = 0xffeebbcc
    front = DbgFrontend([BinBlob2Dbg(BlobArmEl32MultiBlock).dbg], Shell())
    front.register_set(f'r2 {expected_value:#x}')
    assert front.dbg.cpu.regs.r2 == expected_value


def test_register_get(capsys):
    out = 'r0    0x00000005   r1    0x00000005   r2    0x00000000   \n' \
          'pc    0x00000050   cpsr  0x600001d3   '
    wrap = BinBlob2Dbg(BlobArmEl32MultiBlock)
    front = DbgFrontend([wrap.dbg], Shell())
    wrap.start()
    front.register_get('r0 r1 r2 pc cpsr')
    assert capsys.readouterr().out == out


class TestFrontendBreakpointSet:
    def callback(self, _: Debugger, event_id: int, __: dict):
        assert event_id == DBG_EVENT_BREAKPOINT
        self.count += 1

    @pytest.mark.usefixtures('clear_log')
    def test(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        self.count = 0
        wrap = BinBlob2Dbg(BlobArmEl32IncLoop, event_callback=self.callback)
        front = DbgFrontend([wrap.dbg], Shell())

        # This function is tested
        front.breakpoint_set("0x10 4")

        with patch("fiit.shell.Shell.wait_for_prompt_suspend"):
            wrap.start()

        assert self.count == 4
        assert caplog.record_tuples == [
            ('dbg@cpu0', logging.INFO, 'breakpoint at 0x00000010, hit 1'),
            ('dbg@cpu0', logging.INFO, 'breakpoint at 0x00000010, hit 2'),
            ('dbg@cpu0', logging.INFO, 'breakpoint at 0x00000010, hit 3'),
            ('dbg@cpu0', logging.INFO, 'breakpoint at 0x00000010, hit 4')]


class TestFrontendBreakpointDel:
    def callback(self, _: Debugger, event_id: int, __: dict):
        assert event_id == DBG_EVENT_BREAKPOINT
        self.count += 1
        if self.count == 3:
            self.front.breakpoint_del('1')

    @pytest.mark.usefixtures('clear_log')
    def test(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        self.count = 0
        wrap = BinBlob2Dbg(BlobArmEl32IncLoop, event_callback=self.callback)
        self.front = DbgFrontend([wrap.dbg], Shell())

        # This function is tested
        self.front.breakpoint_set("0x10 4")

        with patch("fiit.shell.Shell.wait_for_prompt_suspend"):
            wrap.start()

        assert self.count == 3
        assert caplog.record_tuples == [
            ('dbg@cpu0', logging.INFO, 'breakpoint at 0x00000010, hit 1'),
            ('dbg@cpu0', logging.INFO, 'breakpoint at 0x00000010, hit 2'),
            ('dbg@cpu0', logging.INFO, 'breakpoint at 0x00000010, hit 3')]


def test_breakpoint_print(capsys):
    out = (
        '  index  address       hit\n'
        '-------  ----------  -----\n'
        '      1  0x00000010      0\n')
    front = DbgFrontend([BinBlob2Dbg(BlobArmEl32IncLoop).dbg], Shell())
    front.breakpoint_set('0x10 4')
    front.breakpoint_print('')
    assert capsys.readouterr().out == out


class TestWatchpoint:
    def callback(self, dbg: Debugger, event_id: int, args: dict):
        assert event_id == DBG_EVENT_WATCHPOINT
        assert args['access'] == self.expected_access[self.count]
        self.count += 1

        if args['access'] == 'r':
            assert args['pc_address'] == 8
        if args['access'] == 'w':
            assert args['pc_address'] == 12

        assert dbg.cpu.mem.read(args['address'], args['size']) \
               == b'\x00\x00\xa0\xe1'

    def _test_area(self, access: Literal['r', 'w', 'rw'], hit: int,
                   expected_access: List[str]):
        wrap = BinBlob2Dbg(BlobArmEl32ReadWriteLoop,
                           event_callback=self.callback)
        front = DbgFrontend([wrap.dbg], Shell())

        # This function is tested
        front.watchpoint_area(f'{access} 0x20 0x24 {int(hit)}')

        self.expected_access = expected_access
        self.count = 0
        with patch("fiit.shell.Shell.wait_for_prompt_suspend"):
            wrap.start()

        assert self.count == hit

    def _test_var(self, access: Literal['r', 'w', 'rw'], hit: int,
                  expected_access: List[str]):
        wrap = BinBlob2Dbg(BlobArmEl32ReadWriteLoop,
                           event_callback=self.callback)
        front = DbgFrontend([wrap.dbg], Shell())

        # This function is tested
        front.watchpoint_var(f'{access} 0x20 {int(hit)}')

        self.expected_access = expected_access
        self.count = 0
        with patch("fiit.shell.Shell.wait_for_prompt_suspend"):
            wrap.start()

        assert self.count == hit

    @pytest.mark.usefixtures('clear_log')
    def test_read_watchpoint_area(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        exp = [
            ('dbg@cpu0', logging.INFO,
             'watchpoint at 0x00000020, area [0x00000020-0x00000024], hit 1, access read from 0x00000008'),
            ('dbg@cpu0', logging.INFO,
             'watchpoint at 0x00000020, area [0x00000020-0x00000024], hit 2, access read from 0x00000008')]
        self._test_area('r', 2, ['r', 'r'])
        assert exp == caplog.record_tuples

    @pytest.mark.usefixtures('clear_log')
    def test_write_watchpoint_area(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        exp = [
            ('dbg@cpu0', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000024], hit 1, access write from 0x0000000c'),
            ('dbg@cpu0', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000024], hit 2, access write from 0x0000000c')]
        self._test_area('w', 2, ['w', 'w'])
        assert exp == caplog.record_tuples

    @pytest.mark.usefixtures('clear_log')
    def test_read_write_watchpoint_area(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        exp = [
            ('dbg@cpu0', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000024], hit 1, access read from 0x00000008'),
            ('dbg@cpu0', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000024], hit 2, access write from 0x0000000c'),
            ('dbg@cpu0', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000024], hit 3, access read from 0x00000008'),
            ('dbg@cpu0', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000024], hit 4, access write from 0x0000000c')]
        self._test_area('rw', 4, ['r', 'w', 'r', 'w'])
        assert exp == caplog.record_tuples

    @pytest.mark.usefixtures('clear_log')
    def test_read_watchpoint_var(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        exp = [
            ('dbg@cpu0', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000020], hit 1, access read from 0x00000008'),
            ('dbg@cpu0', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000020], hit 2, access read from 0x00000008')]
        self._test_var('r', 2, ['r', 'r'])
        assert exp == caplog.record_tuples

    @pytest.mark.usefixtures('clear_log')
    def test_write_watchpoint_var(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        exp = [
            ('dbg@cpu0', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000020], hit 1, access write from 0x0000000c'),
            ('dbg@cpu0', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000020], hit 2, access write from 0x0000000c')]
        self._test_var('w', 2, ['w', 'w'])
        assert exp == caplog.record_tuples

    @pytest.mark.usefixtures('clear_log')
    def test_read_write_watchpoint_var(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        exp = [
            ('dbg@cpu0', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000020], hit 1, access read from 0x00000008'),
            ('dbg@cpu0', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000020], hit 2, access write from 0x0000000c'),
            ('dbg@cpu0', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000020], hit 3, access read from 0x00000008'),
            ('dbg@cpu0', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000020], hit 4, access write from 0x0000000c')]
        self._test_var('rw', 4, ['r', 'w', 'r', 'w'])
        assert exp == caplog.record_tuples


class TestDeleteWatchpoint:
    def callback(self, _: Debugger, event_id: int, args: dict):
        assert event_id == DBG_EVENT_WATCHPOINT
        assert args['access'] == 'r'
        assert args['pc_address'] == 8
        self.count += 1

        # This function is tested
        self.front.watchpoint_del('1')

    @pytest.mark.usefixtures('clear_log')
    def test(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        wrap = BinBlob2Dbg(BlobArmEl32ReadWriteLoop,
                           event_callback=self.callback)
        self.front = DbgFrontend([wrap.dbg], Shell())
        self.front.watchpoint_area('r 0x20 0x24')
        self.count = 0

        with patch("fiit.shell.Shell.wait_for_prompt_suspend"):
            wrap.start()

        assert self.count == 1
        assert caplog.record_tuples == [
            ('dbg@cpu0',
             logging.INFO,
             'watchpoint at 0x00000020, area [0x00000020-0x00000024], '
             'hit 1, access read from 0x00000008')
        ]


def test_watchpoint_print(capsys):
    out = (
        '  index  begin       end         access      hit\n'
        '-------  ----------  ----------  --------  -----\n'
        '      1  0x00000020  0x00000024  r             0\n'
    )
    front = DbgFrontend([BinBlob2Dbg(BlobArmEl32ReadWriteLoop).dbg],
                        Shell())
    front.watchpoint_area('r 0x20 0x24 5')
    front.watchpoint_print('')
    assert capsys.readouterr().out == out


class TestSetStepFromBp:
    def bp_callback(self, _: Debugger, event_id: int, args: dict):
        self.front._current_event = (event_id, args)
        self.bp_count += 1
        assert self.bp_count < 4

        if self.bp_count == 1:
            assert event_id == DBG_EVENT_BREAKPOINT
            assert args['address'] == 16
            self.front.step('')
        elif self.bp_count == 2:
            assert event_id == DBG_EVENT_STEP
            assert args['address'] == 20
            self.front.step('')
        elif self.bp_count == 3:
            assert event_id == DBG_EVENT_STEP
            assert args['address'] == 24

    @pytest.mark.usefixtures('clear_log')
    def test(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        wrap = BinBlob2Dbg(
            BlobArmEl32MultiBlock, event_callback=self.bp_callback
        )
        self.front = DbgFrontend([wrap.dbg], Shell())
        self.front.breakpoint_set('0x10 1')
        self.bp_count = 0

        with patch("fiit.shell.Shell.wait_for_prompt_suspend"):
            wrap.start()

        assert self.bp_count == 3

        assert caplog.record_tuples == [
            ('dbg@cpu0', logging.INFO, 'breakpoint at 0x00000010, hit 1'),
            ('dbg@cpu0', logging.INFO, 'step instruction at 0x00000014'),
            ('dbg@cpu0', logging.INFO, 'step instruction at 0x00000018')]


class TestContinueFromBp:
    def bp_callback(self, _: Debugger, event_id: int, __: dict):
        self.bp_count += 1
        assert event_id == DBG_EVENT_BREAKPOINT
        self.front.cont('')

    @pytest.mark.usefixtures('clear_log')
    def test(self, caplog):
        wrap = BinBlob2Dbg(BlobArmEl32MultiBlock,
                           event_callback=self.bp_callback)
        caplog.set_level(logging.INFO, 'fiit.dbg@cpu0')
        self.front = DbgFrontend([wrap.dbg], Shell())
        self.front.breakpoint_set('0x10 1')
        self.bp_count = 0

        with patch("fiit.shell.Shell.wait_for_prompt_suspend"):
            wrap.start()

        assert self.bp_count == 1
        assert wrap.dbg.cpu.regs.arch_pc == 0x50
        assert caplog.record_tuples == [
            ('dbg@cpu0', logging.INFO, 'breakpoint at 0x00000010, hit 1')]
