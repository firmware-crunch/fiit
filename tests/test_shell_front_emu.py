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

from io import StringIO

from unittest.mock import patch

import unicorn

from fiit.emu.emulator import Emulator, EXEC_QUANTUM_UNIT_INSN
from fiit.plugins.shell import Shell
from fiit.shell.front_emu import EmulatorFrontend

from .fixtures.blobs import BlobArmEl32MultiBlock, BlobArmEl64Demo



def test_memory_mapping(capsys):
    out = (
        'start       end         size        name\n'
        '----------  ----------  ----------  ------\n'
        '0x00000000  0x00000fff  0x00001000  rom\n'
    )
    shell = Shell()
    emu = Emulator(
        BlobArmEl32MultiBlock.arch_unicorn,
        BlobArmEl32MultiBlock.mem_map,
        memory_mapped_blobs=BlobArmEl32MultiBlock.mapped_blobs)
    front = EmulatorFrontend(emu, shell)
    front.memory_mapping('')
    assert capsys.readouterr().out == out


def test_memory_mapping_64bit(capsys):
    out = (
        'start               end                 size                name\n'
        '------------------  ------------------  ------------------  ------\n'
        '0x0000000000000000  0x0000000000000fff  0x0000000000001000  rom\n'
    )
    shell = Shell()
    emu = Emulator(
        BlobArmEl64Demo.arch_unicorn,
        BlobArmEl64Demo.mem_map,
        memory_mapped_blobs=BlobArmEl64Demo.mapped_blobs)
    front = EmulatorFrontend(emu, shell)
    front.memory_mapping('')
    assert capsys.readouterr().out == out


class TestEmuStart:
    def int_tester_callback(
        self, _: unicorn.Uc, __: int, ___: int
    ):
        if self.count == 0:
            self.front.emu_start('')
        self.count += 1

    def test(self, capsys):
        self.count = 0
        self.capsys = capsys
        self.emu = Emulator(
            BlobArmEl32MultiBlock.arch_unicorn,
            BlobArmEl32MultiBlock.mem_map,
            memory_mapped_blobs=BlobArmEl32MultiBlock.mapped_blobs,
            interrupt_callback=self.int_tester_callback,
            interrupt_type=EXEC_QUANTUM_UNIT_INSN,
            interrupt_tick_count=1,
            entry_point=BlobArmEl32MultiBlock.emu_start,
            end_address=BlobArmEl32MultiBlock.emu_end)

        self.shell = Shell()
        self.front = EmulatorFrontend(self.emu, self.shell)

        with patch('sys.stdin', StringIO('emu_start\nquit\n')):
            self.shell.start_shell()

        assert (capsys.readouterr().out
                == '\nfiit >>> \n'
                   'Emulator is already running.\n'
                   '\nfiit >>> ')

        assert self.emu.uc.reg_read(self.emu.cpu_reg['pc']) == 0x50
        assert self.emu.uc.reg_read(self.emu.cpu_reg['r0']) == 0x5
        assert self.emu.uc.reg_read(self.emu.cpu_reg['r1']) == 0x5
