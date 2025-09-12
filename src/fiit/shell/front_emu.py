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

import threading
from typing import Union

import tabulate

import IPython
from IPython.core import magic

from ..emu import Emulator, AddressSpace, ADDRESS_FORMAT
from ..shell import register_alias, Shell


@IPython.core.magic.magics_class
class EmulatorFrontend(IPython.core.magic.Magics):
    # FIXME: monitor unicorn issue statu before implement emu_stop command
    # Uc.emu_stop() doesn't work in a hook if PC is updated
    # https://github.com/unicorn-engine/unicorn/issues/1579

    def __init__(self, emu: Emulator, shell: Shell):
        self.emu = emu
        self._shell = shell
        self.emu_tread: Union[threading.Thread, None] = None
        self._addr_f = ADDRESS_FORMAT[self.emu.arch.mem_bit_size]

        super(EmulatorFrontend, self).__init__(shell=shell.shell)
        shell.register_magics(self)
        shell.register_aliases(self)

    def _mem_map_format(self, memory_mapping: AddressSpace) -> str:
        headers = ['start', 'end', 'size', 'name']
        table = [[self._addr_f(mm.base_address),
                  self._addr_f((mm.base_address + mm.size) - 1),
                  self._addr_f(mm.size),
                  mm.name]
                 for mm in memory_mapping]
        return tabulate.tabulate(table, headers, tablefmt="simple")

    @register_alias('mm')
    @IPython.core.magic.line_magic
    def memory_mapping(self, line: str):
        """Print memory mapping."""
        print(self._mem_map_format(self.emu.address_space))

    def _emu_end(self):
        self.emu.emu_tread.join()
        self._shell.resume()

    @register_alias('es')
    @IPython.core.magic.line_magic
    def emu_start(self, line: str):
        """Start emulation."""
        if not self.emu.is_running:
            print('')
            self._shell.suspend()
            self.emu.start_in_thread()
            threading.Thread(target=self._emu_end).start()
        else:
            print('Emulator is already running.')
