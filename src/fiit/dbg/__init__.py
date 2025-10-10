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
    'Breakpoint',
    'Watchpoint',
    'DBG_EVENT_SEGFAULT',
    'DBG_EVENT_BREAKPOINT',
    'DBG_EVENT_WATCHPOINT',
    'DBG_EVENT_STEP',
    'DebugEventCallback',
    'Debugger',
    'DebuggerUnicorn',
    'DebuggerFactory'
]

from typing import (
    Optional,
    List,
    Type
)

from ..machine import DeviceCpu

from .dbg import (
    Breakpoint,
    Watchpoint,
    DBG_EVENT_SEGFAULT,
    DBG_EVENT_BREAKPOINT,
    DBG_EVENT_WATCHPOINT,
    DBG_EVENT_STEP,
    DebugEventCallback,
    Debugger
)

from .uc import DebuggerUnicorn

# ==============================================================================


class DebuggerFactory:

    _DEBUGGERS: List[Type[Debugger]] = [
        DebuggerUnicorn  # Add debugger backend here ...
    ]

    @classmethod
    def get(
        cls, cpu: DeviceCpu, event_callback: Optional[DebugEventCallback] = None
    ) -> Debugger:
        for backend_class in cls._DEBUGGERS:
            if isinstance(cpu.cpu, backend_class.CPU_CLASS):
                return backend_class(cpu, event_callback)

        raise ValueError(f'Debugger backend not found for cpu "{cpu}"')
