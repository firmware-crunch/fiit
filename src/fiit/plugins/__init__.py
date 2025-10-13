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
    'CTX_MACHINE',
    'CTX_REQ_MACHINE',
    'CTX_DBG',
    'CTX_REQ_DBG',
    'CTX_CDATA_MMAP',
    'CTX_REQ_CDATA_MMAP',
    'CTX_MMIO_TRACER',
    'CTX_REQ_MMIO_TRACER',
    'CTX_MMIO_DBG',
    'CTX_REQ_MMIO_DBG',
    'CTX_SHELL',
    'CTX_REQ_SHELL',
    'CTX_HOOKING',
    'CTX_REQ_HOOKING',
    'CTX_FTRACER',
    'CTX_REQ_FTRACER'
]

from typing import List

from fiit.shell import Shell
from fiit.plugin import ContextObject
from fiit.machine import Machine
from fiit.dbg import Debugger
from fiit.arch_ctypes import CDataMemMapper
from fiit.hooking.engine import HookingEngine
from fiit.ftrace.ftrace import Ftrace
from fiit.iotrace import MmioTracer, MmioDbg

# ==============================================================================


CTX_MACHINE = ContextObject('machine', Machine)
CTX_REQ_MACHINE = CTX_MACHINE.as_require()

CTX_DBG = ContextObject('dbg', List[Debugger])
CTX_REQ_DBG = CTX_DBG.as_require()

CTX_CDATA_MMAP = ContextObject('cdata_mmap', List[CDataMemMapper])
CTX_REQ_CDATA_MMAP = CTX_CDATA_MMAP.as_require()

CTX_MMIO_TRACER = ContextObject('mmio_tracer', List[MmioTracer])
CTX_REQ_MMIO_TRACER = CTX_MMIO_TRACER.as_require()

CTX_MMIO_DBG = ContextObject('mmio_dbg', List[MmioDbg])
CTX_REQ_MMIO_DBG = CTX_MMIO_DBG.as_require()

CTX_HOOKING = ContextObject('hooking', List[HookingEngine])
CTX_REQ_HOOKING = CTX_HOOKING.as_require()

CTX_FTRACER = ContextObject('ftracer', List[Ftrace])
CTX_REQ_FTRACER = CTX_FTRACER.as_require()

CTX_SHELL = ContextObject('shell', Shell)
CTX_REQ_SHELL = CTX_SHELL.as_require()
