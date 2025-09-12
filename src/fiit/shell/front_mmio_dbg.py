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

import IPython
from IPython.core import magic
from IPython.core.magic_arguments import (
    argument, magic_arguments, parse_argstring
)

from ..shell import Shell
from ..mmio_trace import MmioDbg



@IPython.core.magic.magics_class
class MmioDbgFrontend(IPython.core.magic.Magics):
    def __init__(self, mmio_dbg: MmioDbg, shell: Shell):
        self._mmio_dbg = mmio_dbg
        super(MmioDbgFrontend, self).__init__(shell=shell.shell)
        self._shell = shell
        self._shell.register_magics(self)
        self._shell.register_aliases(self)

    @magic_arguments()
    @argument('--exclude-from-address', nargs='*', default=[],
              help='Exclude MMIO access interception from this code location.')
    @IPython.core.magic.line_magic
    def mmio_dbg_filter(self, line: str):
        kwargs = parse_argstring(self.mmio_dbg_filter, line)
        self._mmio_dbg.mmio_interceptor.filter.exclude_from_address_add(
            [int(a, 16) for a in kwargs.exclude_from_address])
        self._mmio_dbg.mmio_interceptor.filter.build_filters()
