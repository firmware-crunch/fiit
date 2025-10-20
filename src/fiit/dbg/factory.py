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
from typing import List, Type

from fiit.emunicorn import DebuggerUnicorn
from fiit.dbg import Debugger
from fiit.machine import DeviceCpu

# ==============================================================================


class FiitDbgFactory:

    _DEBUGGERS: List[Type[Debugger]] = [
        DebuggerUnicorn  # Add debugger backend here ...
    ]

    @classmethod
    def get(cls, cpu: DeviceCpu) -> Debugger:
        if not isinstance(cpu, DeviceCpu):
            raise ValueError(f'cpu not supported "{cpu}"')

        for backend_class in cls._DEBUGGERS:
            if isinstance(cpu.cpu, backend_class.CPU_CLASS):
                return backend_class(cpu)

        raise ValueError(f'debugger backend not found for cpu "{cpu}"')
