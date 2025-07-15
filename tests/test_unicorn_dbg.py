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

from typing import List, Literal, Type, Callable
import logging

import pytest
from unittest.mock import patch

import unicorn
from unicorn.arm_const import UC_ARM_REG_R2
from unicorn.unicorn_const import (
    UC_ERR_FETCH_UNMAPPED, UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_UNMAPPED)

from .fixtures.unicorn_utils import BinBlob2Emulator
from .fixtures.blobs.meta_bin_blob import MetaBinBlob
from .fixtures.blobs import (
    BlobArmEl32MemFetchUnmapped, BlobArmEl32MemReadUnmapped,
    BlobArmEl32MemWriteUnmapped, BlobArmEl32IncLoop, BlobArmEl32ReadWriteLoop,
    BlobArmEl32MultiBlock, BlobArmEl64Demo)

from fiit.plugins.shell import Shell
from fiit.unicorn.dbg import (
    UnicornDbg, UnicornDbgFrontend,
    DBG_EVENT_BREAKPOINT, DBG_EVENT_STEP, DBG_EVENT_WATCHPOINT,
    DBG_EVENT_SEGFAULT)


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


class BinBlob2Dbg:
    def __init__(self, bin_blob: Type[MetaBinBlob], **kargs):
        self.emu = BinBlob2Emulator(bin_blob)
        self.dbg = UnicornDbg(self.emu.uc, **kargs)


################################################################################
# EmulatorDbgUnicorn
################################################################################

class CallbackHarness:
    def __init__(self, callback: Callable):
        self.count = 0
        self.callback = callback

    def callback_wrapper(self, *args, **kwargs):
        self.count += 1
        self.callback(*args, **kwargs)


def test_dbg_segfault_fetch():
    def debug_callback(dbg: UnicornDbg, event_id: int, args: dict):
        assert event_id == DBG_EVENT_SEGFAULT
        assert args['address'] == 0xffff0000

    harness = CallbackHarness(debug_callback)

    with pytest.raises(unicorn.unicorn.UcError) as exc_info:
        BinBlob2Dbg(BlobArmEl32MemFetchUnmapped,
                    debug_event_callback=harness.callback_wrapper).emu.start()

    assert exc_info.value.errno == UC_ERR_FETCH_UNMAPPED
    assert harness.count == 1


def test_dbg_segfault_read():
    def debug_callback(dbg: UnicornDbg, event_id: int, args: dict):
        assert event_id == DBG_EVENT_SEGFAULT
        assert args['address'] == 0xffffff00

    harness = CallbackHarness(debug_callback)

    with pytest.raises(unicorn.unicorn.UcError) as exc_info:
        BinBlob2Dbg(BlobArmEl32MemReadUnmapped,
                    debug_event_callback=harness.callback_wrapper).emu.start()

    assert exc_info.value.errno == UC_ERR_READ_UNMAPPED
    assert harness.count == 1


def test_dbg_segfault_write():
    def debug_callback(dbg: UnicornDbg, event_id: int, args: dict):
        assert event_id == DBG_EVENT_SEGFAULT
        assert args['address'] == 0xffffff00

    harness = CallbackHarness(debug_callback)

    with pytest.raises(unicorn.unicorn.UcError) as exc_info:
        BinBlob2Dbg(BlobArmEl32MemWriteUnmapped,
                    debug_event_callback=harness.callback_wrapper).emu.start()

    assert exc_info.value.errno == UC_ERR_WRITE_UNMAPPED
    assert harness.count == 1


class TestDbgBreakpoint:
    def bp_callback(self, dbg: UnicornDbg, event_id: int, args: dict):
        assert event_id == DBG_EVENT_BREAKPOINT
        assert dbg.uc.reg_read(dbg.cpu_reg['pc']) == 16
        assert dbg.uc.reg_read(dbg.cpu_reg['pc']) == args['address']
        assert dbg.uc.reg_read(dbg.cpu_reg['r0']) \
               == self.expected_r0[self.bp_count]
        self.bp_count += 1
        assert self.bp_count < 3

    def test(self):
        self.bp_count = 0
        self.expected_r0 = [1, 2]

        emu_dbg = BinBlob2Dbg(BlobArmEl32IncLoop,
                              debug_event_callback=self.bp_callback)
        dbg = emu_dbg.dbg
        dbg.breakpoint_set(16, 2)
        self.bp_count = 0
        emu_dbg.emu.start()
        assert self.bp_count == 2


class TestDbgDeleteBreakpoint:
    def bp_callback(self, dbg: UnicornDbg, event_id: int, args: dict):
        assert event_id == DBG_EVENT_BREAKPOINT
        assert dbg.uc.reg_read(dbg.cpu_reg['pc']) == 16
        assert dbg.uc.reg_read(dbg.cpu_reg['pc']) == args['address']
        assert dbg.uc.reg_read(dbg.cpu_reg['r0']) \
               == self.expected_r0[self.bp_count]
        dbg.breakpoint_del_by_index(1)
        self.bp_count += 1
        assert self.bp_count == 1

    def test(self):
        self.expected_r0 = [1, 2]
        emu_dbg = BinBlob2Dbg(BlobArmEl32IncLoop,
                              debug_event_callback=self.bp_callback)
        dbg = emu_dbg.dbg
        dbg.breakpoint_set(16, 4)
        self.bp_count = 0
        emu_dbg.emu.start()
        assert self.bp_count == 1


class TestDbgTReadWatchpoint:
    def callback(self, dbg: UnicornDbg, event_id: int, args: dict):
        assert event_id == DBG_EVENT_WATCHPOINT
        assert args['access'] == self.expected_access[self.count]
        self.count += 1

        if args['access'] == 'r':
            assert args['pc_address'] == 8
        if args['access'] == 'w':
            assert args['pc_address'] == 12

        assert dbg.uc.mem_read(args['address'], args['size']) \
               == b'\x00\x00\xa0\xe1'

    def _run_test(self, access: Literal['r', 'w', 'rw'], hit: int,
                  expected_access: List[str]):
        emu_dbg = BinBlob2Dbg(BlobArmEl32ReadWriteLoop,
                              debug_event_callback=self.callback)
        dbg = emu_dbg.dbg
        dbg.watchpoint_set(32, 36, access, hit)
        self.expected_access = expected_access
        self.count = 0
        emu_dbg.emu.start()
        assert self.count == hit

    def test_dbg_read_watchpoint(self):
        self._run_test('r', 2, ['r', 'r'])

    def test_dbg_write_watchpoint(self):
        self._run_test('w', 2, ['w', 'w'])

    def test_dbg_read_write_watchpoint(self):
        self._run_test('rw', 4, ['r', 'w', 'r', 'w'])


def test_dbg_invalid_watchpoint():
    emu_dbg = BinBlob2Dbg(BlobArmEl32ReadWriteLoop)
    with pytest.raises(ValueError):
        emu_dbg.dbg.watchpoint_set(36, 32, 'r', 5)


class TestDbgDeleteWatchpoint:
    def callback(self, dbg: UnicornDbg, event_id: int, args: dict):
        assert event_id == DBG_EVENT_WATCHPOINT
        assert args['access'] == 'r'
        assert args['pc_address'] == 8
        self.count += 1
        dbg.watchpoint_del_by_index(1)

    def test(self):
        emu_dbg = BinBlob2Dbg(BlobArmEl32ReadWriteLoop,
                              debug_event_callback=self.callback)
        emu_dbg.dbg.watchpoint_set(32, 36, 'r')
        self.count = 0
        emu_dbg.emu.start()
        assert self.count == 1


class TestDbgSetStepFromBp:
    def bp_callback(self, dbg: UnicornDbg, event_id: int, args: dict):
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
        emu_dbg = BinBlob2Dbg(BlobArmEl32MultiBlock,
                              debug_event_callback=self.bp_callback)
        dbg = emu_dbg.dbg
        dbg.breakpoint_set(16, 1)
        self.bp_count = 0
        emu_dbg.emu.start()
        assert self.bp_count == 3


class TestDbgSetFromWatchpoint:
    def callback(self, dbg: UnicornDbg, event_id: int, args: dict):
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
        emu_dbg = BinBlob2Dbg(BlobArmEl32ReadWriteLoop,
                              debug_event_callback=self.callback)
        emu_dbg.dbg.watchpoint_set(32, 36, 'w', 2)
        self.count = 0
        self.count_watch = 0
        self.count_step = 0
        emu_dbg.emu.start()
        assert self.count == 4
        assert self.count_watch == 2
        assert self.count_step == 2


def test_dbg_disassemble():
    expected_dis = (
        '0x00000000:\t0000a0e3            \tmov\tr0, #0\n'
        '0x00000004:\tffffffea            \tb\t#8\n'
        '0x00000008:\t010080e2            \tadd\tr0, r0, #1\n'
        '0x0000000c:\t0a0050e3            \tcmp\tr0, #0xa\n'
        '0x00000010:\tfcffff1a            \tbne\t#8\n'
        '0x00000014:\t0110a0e3            \tmov\tr1, #1')
    assert ('\n'.join(BinBlob2Dbg(BlobArmEl32IncLoop).dbg.disassemble(0x0, 6))
            == expected_dis)


def test_dbg_disassemble_unmapped_address():
    with pytest.raises(ValueError):
        BinBlob2Dbg(BlobArmEl32IncLoop).dbg.disassemble(0xff409000, 6)


def test_dbg_complete_dump_register():
    expected_dump_complete = {
        'r0': 5, 'r1': 5, 'r2': 0, 'r3': 0, 'r4': 0, 'r5': 0, 'r6': 0,
        'r7': 0, 'r8': 0, 'r9': 0, 'r10': 0, 'r11': 0, 'r12': 0, 'sp': 0,
        'lr': 0, 'pc': 80, 'cpsr': 1610613203}
    emu_dbg = BinBlob2Dbg(BlobArmEl32MultiBlock)
    emu_dbg.emu.start()
    assert expected_dump_complete == emu_dbg.dbg.get_cpu_registers()


def test_dbg_partial_dump_register():
    expected_dump_partial = {
        'r0': 5, 'r1': 5, 'r2': 0, 'pc': 80, 'cpsr': 1610613203}
    emu_dbg = BinBlob2Dbg(BlobArmEl32MultiBlock)
    emu_dbg.emu.start()
    assert expected_dump_partial \
           == emu_dbg.dbg.get_cpu_registers(['r0', 'r1', 'r2', 'pc', 'cpsr'])


def test_dbg_set_register():
    expected_value = 0xffeebbcc
    emu_dbg = BinBlob2Dbg(BlobArmEl32MultiBlock)
    emu_dbg.dbg.set_cpu_register('r2', expected_value)
    assert emu_dbg.dbg.uc.reg_read(UC_ARM_REG_R2) == expected_value


################################################################################
# DebuggerFrontend
################################################################################

def test_frontend_dbg_disassemble(capsys):
    out = \
        '0x00000000:\t0000a0e3            \tmov\tr0, #0\n' \
        '0x00000004:\tffffffea            \tb\t#8\n' \
        '0x00000008:\t010080e2            \tadd\tr0, r0, #1\n' \
        '0x0000000c:\t0a0050e3            \tcmp\tr0, #0xa\n' \
        '0x00000010:\tfcffff1a            \tbne\t#8\n' \
        '0x00000014:\t0110a0e3            \tmov\tr1, #1'
    front = UnicornDbgFrontend(BinBlob2Dbg(BlobArmEl32IncLoop).dbg, Shell())
    front.disassemble('0x0 6')
    assert capsys.readouterr().out == out


def test_frontend_dbg_mem_read(capsys):
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
    front = UnicornDbgFrontend(BinBlob2Dbg(BlobArmEl32IncLoop).dbg, Shell())
    front.mem_read('0x0 256')
    assert capsys.readouterr().out == out


def test_frontend_dbg_mem_read_64(capsys):
    out = '0000000000000000  e0 03 01 aa 20 f8 40 d3  e0 03 00 aa 00 00 00 00 |.... .@.........|\n' \
          '0000000000000010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|\n' \
          '0000000000000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|\n' \
          '0000000000000030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|'
    front = UnicornDbgFrontend(BinBlob2Dbg(BlobArmEl64Demo).dbg, Shell())
    front.mem_read('0x0 64')
    assert capsys.readouterr().out == out


def test_frontend_dbg_write_word():
    front = UnicornDbgFrontend(BinBlob2Dbg(BlobArmEl32IncLoop).dbg, Shell())
    front.mem_write('0x50 word 0xdeadbeef')
    assert front.dbg.uc.mem_read(0x50, 4) == b'\xef\xbe\xad\xde'


def test_frontend_dbg_write_cstring():
    cstring = 'patched_boot_line("/dev/mp0")'
    front = UnicornDbgFrontend(BinBlob2Dbg(BlobArmEl32IncLoop).dbg, Shell())
    front.mem_write(f'0x50 cstring {cstring}')
    assert front.dbg.uc.mem_read(0x50, len(cstring)).decode() == cstring


def test_register_set():
    expected_value = 0xffeebbcc
    front = UnicornDbgFrontend(BinBlob2Dbg(BlobArmEl32MultiBlock).dbg, Shell())
    front.register_set(f'r2 {expected_value:#x}')
    assert front.dbg.uc.reg_read(UC_ARM_REG_R2) == expected_value


def test_frontend_dbg_complete_register_get(capsys):
    out = 'r0   0x00000005   r1   0x00000005   r2   0x00000000   \n' \
          'r3   0x00000000   r4   0x00000000   r5   0x00000000   \n' \
          'r6   0x00000000   r7   0x00000000   r8   0x00000000   \n' \
          'r9   0x00000000   r10  0x00000000   r11  0x00000000   \n' \
          'r12  0x00000000   sp   0x00000000   lr   0x00000000   \n' \
          'pc   0x00000050   cpsr 0x600001d3   '

    emu_dbg = BinBlob2Dbg(BlobArmEl32MultiBlock)
    front = UnicornDbgFrontend(emu_dbg.dbg, Shell())
    emu_dbg.emu.start()
    front.register_get('')
    assert capsys.readouterr().out == out


def test_frontend_dbg_complete_register_get_64(capsys):
    out = 'x0   0x0000000000000000   x1   0x0000000000000000   x2   0x0000000000000000   \n' \
          'x3   0x0000000000000000   x4   0x0000000000000000   x5   0x0000000000000000   \n' \
          'x6   0x0000000000000000   x7   0x0000000000000000   x8   0x0000000000000000   \n' \
          'x9   0x0000000000000000   x10  0x0000000000000000   x11  0x0000000000000000   \n' \
          'x12  0x0000000000000000   x13  0x0000000000000000   x14  0x0000000000000000   \n' \
          'x15  0x0000000000000000   x16  0x0000000000000000   x17  0x0000000000000000   \n' \
          'x18  0x0000000000000000   x19  0x0000000000000000   x20  0x0000000000000000   \n' \
          'x21  0x0000000000000000   x22  0x0000000000000000   x23  0x0000000000000000   \n' \
          'x24  0x0000000000000000   x25  0x0000000000000000   x26  0x0000000000000000   \n' \
          'x27  0x0000000000000000   x28  0x0000000000000000   pc   0x0000000000000008   \n' \
          'sp   0x0000000000000000   fp   0x0000000000000000   lr   0x0000000000000000   \n' \
          'cpsr 0x0000000040000000   '
    emu_dbg = BinBlob2Dbg(BlobArmEl64Demo)
    front = UnicornDbgFrontend(emu_dbg.dbg, Shell())
    emu_dbg.emu.start()
    front.register_get('')
    assert capsys.readouterr().out == out


def test_frontend_dbg_partial_register_get(capsys):
    out = 'r0   0x00000005   r1   0x00000005   r2   0x00000000   \n' \
          'pc   0x00000050   cpsr 0x600001d3   '
    emu_dbg = BinBlob2Dbg(BlobArmEl32MultiBlock)
    front = UnicornDbgFrontend(emu_dbg.dbg, Shell())
    emu_dbg.emu.start()
    front.register_get('r0 r1 r2 pc cpsr')
    assert capsys.readouterr().out == out


class TestFrontendBreakpointSet:
    def callback(self, dbg: UnicornDbg, event_id: int, args: dict):
        assert event_id == DBG_EVENT_BREAKPOINT
        self.count += 1

    @pytest.mark.usefixtures('clear_log')
    def test(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.unicorn_dbg')
        self.count = 0
        emu_dbg = BinBlob2Dbg(BlobArmEl32IncLoop,
                              debug_event_callback=self.callback)
        front = UnicornDbgFrontend(emu_dbg.dbg, Shell())

        # This function is tested
        front.breakpoint_set("0x10 4")

        with patch("fiit.plugins.shell.Shell.wait_for_prompt_suspend"):
            emu_dbg.emu.start()

        assert self.count == 4
        assert caplog.record_tuples == [
            ('unicorn_dbg', logging.INFO, 'Breakpoint at 0x00000010, hit 1'),
            ('unicorn_dbg', logging.INFO, 'Breakpoint at 0x00000010, hit 2'),
            ('unicorn_dbg', logging.INFO, 'Breakpoint at 0x00000010, hit 3'),
            ('unicorn_dbg', logging.INFO, 'Breakpoint at 0x00000010, hit 4')]


class TestFrontendBreakpointDel:
    def callback(self, dbg: UnicornDbg, event_id: int, args: dict):
        assert event_id == DBG_EVENT_BREAKPOINT
        self.count += 1
        if self.count == 3:
            self.front.breakpoint_del('1')

    @pytest.mark.usefixtures('clear_log')
    def test(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.unicorn_dbg')
        self.count = 0
        emu_dbg = BinBlob2Dbg(BlobArmEl32IncLoop,
                              debug_event_callback=self.callback)
        self.front = UnicornDbgFrontend(emu_dbg.dbg, Shell())

        # This function is tested
        self.front.breakpoint_set("0x10 4")

        with patch("fiit.plugins.shell.Shell.wait_for_prompt_suspend"):
            emu_dbg.emu.start()

        assert self.count == 3
        assert caplog.record_tuples == [
            ('unicorn_dbg', logging.INFO, 'Breakpoint at 0x00000010, hit 1'),
            ('unicorn_dbg', logging.INFO, 'Breakpoint at 0x00000010, hit 2'),
            ('unicorn_dbg', logging.INFO, 'Breakpoint at 0x00000010, hit 3')]


def test_frontend_dbg_breakpoint_print(capsys):
    out = (
        '  index  address       hit\n'
        '-------  ----------  -----\n'
        '      1  0x00000010      0\n')
    front = UnicornDbgFrontend(BinBlob2Dbg(BlobArmEl32IncLoop).dbg, Shell())
    front.breakpoint_set('0x10 4')
    front.breakpoint_print('')
    assert capsys.readouterr().out == out


def test_frontend_dbg_breakpoint_print_64(capsys):
    out = (
        '  index  address               hit\n'
        '-------  ------------------  -----\n'
        '      1  0x0000000000000004      0\n')
    front = UnicornDbgFrontend(BinBlob2Dbg(BlobArmEl64Demo).dbg, Shell())
    front.breakpoint_set('0x4 4')
    front.breakpoint_print('')
    assert capsys.readouterr().out == out


class TestFrontendDbgWatchpoint:
    def callback(self, dbg: UnicornDbg, event_id: int, args: dict):
        assert event_id == DBG_EVENT_WATCHPOINT
        assert args['access'] == self.expected_access[self.count]
        self.count += 1

        if args['access'] == 'r':
            assert args['pc_address'] == 8
        if args['access'] == 'w':
            assert args['pc_address'] == 12

        assert dbg.uc.mem_read(args['address'], args['size']) \
               == b'\x00\x00\xa0\xe1'

    def _test_area(self, access: Literal['r', 'w', 'rw'], hit: int,
                   expected_access: List[str]):
        emu_dbg = BinBlob2Dbg(BlobArmEl32ReadWriteLoop,
                              debug_event_callback=self.callback)
        front = UnicornDbgFrontend(emu_dbg.dbg, Shell())

        # This function is tested
        front.watchpoint_area(f'{access} 0x20 0x24 {int(hit)}')

        self.expected_access = expected_access
        self.count = 0
        with patch("fiit.plugins.shell.Shell.wait_for_prompt_suspend"):
            emu_dbg.emu.start()

        assert self.count == hit

    def _test_var(self, access: Literal['r', 'w', 'rw'], hit: int,
                  expected_access: List[str]):
        emu_dbg = BinBlob2Dbg(BlobArmEl32ReadWriteLoop,
                              debug_event_callback=self.callback)
        front = UnicornDbgFrontend(emu_dbg.dbg, Shell())

        # This function is tested
        front.watchpoint_var(f'{access} 0x20 {int(hit)}')

        self.expected_access = expected_access
        self.count = 0
        with patch("fiit.plugins.shell.Shell.wait_for_prompt_suspend"):
            emu_dbg.emu.start()

        assert self.count == hit

    @pytest.mark.usefixtures('clear_log')
    def test_frontend_dbg_read_watchpoint_area(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.unicorn_dbg')
        exp = [
            ('unicorn_dbg', logging.INFO,
             'watchpoint at 0x00000020, area [0x00000020-0x00000024], hit 1, access read from 0x00000008'),
            ('unicorn_dbg', logging.INFO,
             'watchpoint at 0x00000020, area [0x00000020-0x00000024], hit 2, access read from 0x00000008')]
        self._test_area('r', 2, ['r', 'r'])
        assert exp == caplog.record_tuples

    @pytest.mark.usefixtures('clear_log')
    def test_frontend_dbg_write_watchpoint_area(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.unicorn_dbg')
        exp = [
            ('unicorn_dbg', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000024], hit 1, access write from 0x0000000c'),
            ('unicorn_dbg', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000024], hit 2, access write from 0x0000000c')]
        self._test_area('w', 2, ['w', 'w'])
        assert exp == caplog.record_tuples

    @pytest.mark.usefixtures('clear_log')
    def test_frontend_dbg_read_write_watchpoint_area(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.unicorn_dbg')
        exp = [
            ('unicorn_dbg', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000024], hit 1, access read from 0x00000008'),
            ('unicorn_dbg', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000024], hit 2, access write from 0x0000000c'),
            ('unicorn_dbg', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000024], hit 3, access read from 0x00000008'),
            ('unicorn_dbg', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000024], hit 4, access write from 0x0000000c')]
        self._test_area('rw', 4, ['r', 'w', 'r', 'w'])
        assert exp == caplog.record_tuples

    @pytest.mark.usefixtures('clear_log')
    def test_frontend_dbg_read_watchpoint_var(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.unicorn_dbg')
        exp = [
            ('unicorn_dbg', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000020], hit 1, access read from 0x00000008'),
            ('unicorn_dbg', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000020], hit 2, access read from 0x00000008')]
        self._test_var('r', 2, ['r', 'r'])
        assert exp == caplog.record_tuples

    @pytest.mark.usefixtures('clear_log')
    def test_frontend_dbg_write_watchpoint_var(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.unicorn_dbg')
        exp = [
            ('unicorn_dbg', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000020], hit 1, access write from 0x0000000c'),
            ('unicorn_dbg', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000020], hit 2, access write from 0x0000000c')]
        self._test_var('w', 2, ['w', 'w'])
        assert exp == caplog.record_tuples

    @pytest.mark.usefixtures('clear_log')
    def test_frontend_dbg_read_write_watchpoint_var(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.unicorn_dbg')
        exp = [
            ('unicorn_dbg', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000020], hit 1, access read from 0x00000008'),
            ('unicorn_dbg', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000020], hit 2, access write from 0x0000000c'),
            ('unicorn_dbg', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000020], hit 3, access read from 0x00000008'),
            ('unicorn_dbg', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000020], hit 4, access write from 0x0000000c')]
        self._test_var('rw', 4, ['r', 'w', 'r', 'w'])
        assert exp == caplog.record_tuples


class TestFrontendDbgDeleteWatchpoint:
    def callback(self, dbg: UnicornDbg, event_id: int, args: dict):
        assert event_id == DBG_EVENT_WATCHPOINT
        assert args['access'] == 'r'
        assert args['pc_address'] == 8
        self.count += 1

        # This function is tested
        self.front.watchpoint_del('1')

    @pytest.mark.usefixtures('clear_log')
    def test(self, caplog):
        caplog.set_level(logging.INFO, 'fiit.unicorn_dbg')
        emu_dbg = BinBlob2Dbg(BlobArmEl32ReadWriteLoop,
                              debug_event_callback=self.callback)
        self.front = UnicornDbgFrontend(emu_dbg.dbg, Shell())
        self.front.watchpoint_area('r 0x20 0x24')
        self.count = 0

        with patch("fiit.plugins.shell.Shell.wait_for_prompt_suspend"):
            emu_dbg.emu.start()

        assert self.count == 1
        assert caplog.record_tuples == [('unicorn_dbg', logging.INFO, 'watchpoint at 0x00000020, area [0x00000020-0x00000024], hit 1, access read from 0x00000008')]


def test_frontend_dbg_watchpoint_print(capsys):
    out = (
        '  index  begin       end         access      hit\n'
        '-------  ----------  ----------  --------  -----\n'
        '      1  0x00000020  0x00000024  r             0\n'
    )
    front = UnicornDbgFrontend(BinBlob2Dbg(BlobArmEl32ReadWriteLoop).dbg,
                               Shell())
    front.watchpoint_area('r 0x20 0x24 5')
    front.watchpoint_print('')
    assert capsys.readouterr().out == out


def test_frontend_dbg_watchpoint_print_64(capsys):
    out = (
        '  index  begin               end                 access      hit\n'
        '-------  ------------------  ------------------  --------  -----\n'
        '      1  0x0000000000000004  0x0000000000000008  r             0\n'
    )
    front = UnicornDbgFrontend(BinBlob2Dbg(BlobArmEl64Demo).dbg, Shell())
    front.watchpoint_area('r 0x4 0x8 5')
    front.watchpoint_print('')
    assert capsys.readouterr().out == out


class TestFrontendDbgSetStepFromBp:
    def bp_callback(self, dbg: UnicornDbg, event_id: int, args: dict):
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
        caplog.set_level(logging.INFO, 'fiit.unicorn_dbg')
        emu_dbg = BinBlob2Dbg(BlobArmEl32MultiBlock,
                              debug_event_callback=self.bp_callback)
        self.front = UnicornDbgFrontend(emu_dbg.dbg, Shell())
        self.front.breakpoint_set('0x10 1')
        self.bp_count = 0
        with patch("fiit.plugins.shell.Shell.wait_for_prompt_suspend"):
            emu_dbg.emu.start()

        assert self.bp_count == 3

        assert caplog.record_tuples == [
            ('unicorn_dbg', logging.INFO, 'Breakpoint at 0x00000010, hit 1'),
            ('unicorn_dbg', logging.INFO, 'step instruction at 0x00000014'),
            ('unicorn_dbg', logging.INFO, 'step instruction at 0x00000018')]


class TestFrontendDbgContinueFromBp:
    def bp_callback(self, dbg: UnicornDbg, event_id: int, args: dict):
        self.bp_count += 1
        assert event_id == DBG_EVENT_BREAKPOINT
        self.front.cont('')

    @pytest.mark.usefixtures('clear_log')
    def test(self, caplog):
        emu_dbg = BinBlob2Dbg(BlobArmEl32MultiBlock,
                              debug_event_callback=self.bp_callback)
        caplog.set_level(logging.INFO, 'fiit.unicorn_dbg')
        self.front = UnicornDbgFrontend(emu_dbg.dbg, Shell())
        self.front.breakpoint_set('0x10 1')
        self.bp_count = 0
        with patch("fiit.plugins.shell.Shell.wait_for_prompt_suspend"):
            emu_dbg.emu.start()

        assert self.bp_count == 1
        assert emu_dbg.emu.uc.reg_read(emu_dbg.dbg.cpu_reg['pc']) == 0x50
        assert caplog.record_tuples == [
            ('unicorn_dbg', logging.INFO, 'Breakpoint at 0x00000010, hit 1')]
