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
    'DebugEventCallback',
    'Debugger',
    'BreakpointBase',

    'BreakpointType',
    'Breakpoint',
    'BreakpointOOB',

    'WatchpointAccess',
    'Watchpoint',
    'WatchpointType',
    'WatchpointReadOOB',
    'WatchpointWriteOOB',
    'WatchpointRwOOB',

    'DbgEventBase',
    'DbgEventStartProgram',
    'DbgEventContinue',
    'DbgEventStopType',
    'DbgEventStop',
    'DbgEventBreakpoint',
    'DbgEventWatchpointAccess',
    'DbgEventWatchpoint',
    'DbgEventStepInst',
    'DbgEventMemFetchUnmapped',
    'DbgEventMemAccessUnmapped',
    'DbgEventMemWriteUnmapped',
    'DbgEventMemWrite',
    'DbgEventMemReadUnmapped',
    'DbgEventBreakpointCreated',
    'DbgEventBreakpointDeleted',
    'DbgEventBreakpointChanged',
    'DbgEventRegisterWrite',

    'BreakpointCondition',
    'BreakpointHitCb',
    'BreakpointInvalidateCb'
]

from .dbg import DebugEventCallback, Debugger
from .defines import (
    BreakpointBase,

    BreakpointType,
    Breakpoint,
    BreakpointOOB,

    WatchpointAccess,
    WatchpointType,
    Watchpoint,
    WatchpointReadOOB,
    WatchpointWriteOOB,
    WatchpointRwOOB,

    DbgEventBase,
    DbgEventStartProgram,
    DbgEventContinue,
    DbgEventStopType,
    DbgEventStop,
    DbgEventBreakpoint,
    DbgEventWatchpointAccess,
    DbgEventWatchpoint,
    DbgEventStepInst,
    DbgEventMemFetchUnmapped,
    DbgEventMemAccessUnmapped,
    DbgEventMemWriteUnmapped,
    DbgEventMemWrite,
    DbgEventMemReadUnmapped,
    DbgEventBreakpointCreated,
    DbgEventBreakpointDeleted,
    DbgEventBreakpointChanged,
    DbgEventRegisterWrite,

    BreakpointCondition,
    BreakpointHitCb,
    BreakpointInvalidateCb
)
