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
    'MmioDbgFrontend'
]

from typing import List, Union

import IPython
from IPython.core import magic
from IPython.core.magic_arguments import (
    argument, magic_arguments, parse_argstring
)

from fiit.mmio_trace import MmioDbg
from ..shell import Shell

# ==============================================================================


@IPython.core.magic.magics_class
class MmioDbgFrontend(IPython.core.magic.Magics):
    def __init__(self, mmio_dbg_list: List[MmioDbg], shell: Shell):
        self._mmio_dbg_list = mmio_dbg_list
        super(MmioDbgFrontend, self).__init__(shell=shell.shell)
        self._shell = shell
        self._shell.register_magics(self)
        self._shell.register_aliases(self)

    def _get_mmio_dbg(self, cpu_name: str) -> Union[MmioDbg, None]:
        for mmio_dbg in self._mmio_dbg_list:
            if mmio_dbg._dbg.cpu.name == cpu_name:
                return mmio_dbg

    @magic_arguments()
    @argument('cpu_name', type=str, help='')
    @argument('--exclude-from-address', nargs='*', default=[],
              help='Exclude MMIO access interception from this code location.')
    @IPython.core.magic.line_magic
    def mmio_dbg_filter(self, line: str):
        kwargs = parse_argstring(self.mmio_dbg_filter, line)
        mmio_dbg = self._get_mmio_dbg(kwargs.dev_name)

        if mmio_dbg is None:
            print(f'mmio debugger not found for CPU device "{kwargs.dev_name}"')
        else:
            exclude = [int(a, 16) for a in kwargs.exclude_from_address]
            mmio_dbg.mmio_interceptor.filter.exclude_from_address_add(exclude)
            mmio_dbg.mmio_interceptor.filter.build_filters()
