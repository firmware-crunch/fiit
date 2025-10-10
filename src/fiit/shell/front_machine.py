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
    'MachineFrontend'
]

import threading
from typing import Union, Optional

import tabulate

import IPython
from IPython.core import magic

from fiit.machine import Machine, DeviceCpu

from .shell import register_alias, Shell

# ==============================================================================


@IPython.core.magic.magics_class
class MachineFrontend(IPython.core.magic.Magics):
    def __init__(self, machine: Machine, shell: Shell) -> None:
        self.machine = machine
        self._shell = shell
        self._shell_monitor_tread: Union[threading.Thread, None] = None
        self._cpu_focus: Optional[DeviceCpu] = None

        super(MachineFrontend, self).__init__(shell=shell.shell)
        shell.register_magics(self)
        shell.register_aliases(self)

    @register_alias('cmm')
    @IPython.core.magic.line_magic
    def cpu_mem_map(self, _: str) -> None:
        """Print machine memory region"""
        headers = ['start', 'end', 'size', 'name']
        output = ''

        for dev in self.machine.cpu_devices:
            table = [
                [
                    dev.mem.addr_to_str(mm.base_address),
                    dev.mem.addr_to_str((mm.base_address + mm.size) - 1),
                    dev.mem.addr_to_str(mm.size),
                    mm.name if mm.name is not None else '<unknown>'
                ]
                for mm in dev.mem.regions
            ]

            out_tab = tabulate.tabulate(table, headers, tablefmt="simple")
            output += f'\ndevice: {dev.dev_name}\n\n{out_tab}\n'

        print(output)

    def _join_exec_thread(self, cpu_thread: threading.Thread) -> None:
        cpu_thread.join()
        self._cpu_focus = None
        self._shell.resume()

    @register_alias('ce')
    @IPython.core.magic.line_magic
    def cpu_exec(self, cpu_name: str) -> None:
        """run cpu execution"""
        target_cpu: Optional[DeviceCpu] = None

        if cpu_name is None or cpu_name == '':
            cpu_devices = self.machine.cpu_devices
            cpu_devices_len = len(cpu_devices)

            if cpu_devices_len == 1:
                target_cpu = cpu_devices[0]
            if cpu_devices_len > 1:
                print('error: no cpu name provided')
                return
            if cpu_devices_len == 0:
                print('error: no device cpu')
                return

        for cpu in self.machine.cpu_devices:
            if cpu.dev_name == cpu_name:
                target_cpu = cpu

        if target_cpu is None:
            print(f'error: cpu name not found for "{cpu_name}"')
            return

        if target_cpu.is_running:
            print('error: cpu is already running')
        elif target_cpu.program_entry_point is None:
            print('error: cpu program entry not configured')
        else:
            self._cpu_focus = target_cpu
            print('')
            self._shell.suspend()
            cpu_thread = self._cpu_focus.start_in_thread(
                self._cpu_focus.program_entry_point,
                self._cpu_focus.program_exit_point
            )
            self._shell_monitor_tread = threading.Thread(
                target=self._join_exec_thread, daemon=True, args=(cpu_thread,)
            )
            self._shell_monitor_tread.start()
