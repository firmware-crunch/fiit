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

from fiit.shell import Shell
from fiit.shell.front_machine import MachineFrontend
from fiit.machine import TickUnit, DeviceCpu, Machine

from .fixtures import Blob2Cpu
from .fixtures.blobs import BlobArmEl32MultiBlock

# ==============================================================================


def test_cpu_mem_map(capsys):
    out = (
        '\ndevice: cpu0\n\n'
        'start       end         size        name\n'
        '----------  ----------  ----------  ---------\n'
        '0x00000000  0x00000fff  0x00001000  <unknown>\n\n'
    )
    shell = Shell()
    cpu = Blob2Cpu(BlobArmEl32MultiBlock, 'unicorn', 'cpu0').cpu
    machine = Machine()
    machine.add_device(cpu)
    front = MachineFrontend(machine, shell)
    front.cpu_mem_map('')
    assert capsys.readouterr().out == out


class TestCpuExec:
    def int_tester_callback(self, _: DeviceCpu):
        if self.count == 0:
            self.front.cpu_exec('cpu0')
        self.count += 1

    def test(self, capsys):
        self.count = 0
        self.capsys = capsys

        cpu = Blob2Cpu(BlobArmEl32MultiBlock, 'unicorn', cpu_name='cpu0').cpu
        cpu.program_entry_point = BlobArmEl32MultiBlock.emu_start
        cpu.program_exit_point = BlobArmEl32MultiBlock.emu_end
        cpu.set_contention(TickUnit.INST, 1)
        cpu.add_contention_callback(self.int_tester_callback)
        machine = Machine()
        machine.add_device(cpu)

        self.shell = Shell()
        self.front = MachineFrontend(machine, self.shell)

        with patch('sys.stdin', StringIO('cpu_exec\nquit\n')):
            self.shell.start_shell()

        assert (capsys.readouterr().out
                == '\nfiit >>> \n'
                   'error: cpu is already running\n'
                   '\nfiit >>> ')

        assert cpu.regs.pc == 0x50
        assert cpu.regs.r0 == 0x5
        assert cpu.regs.r1 == 0x5
