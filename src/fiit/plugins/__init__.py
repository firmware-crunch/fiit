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

import unicorn

from fiit.plugin import ContextObject
from fiit.shell import Shell
from fiit.emu.emu_types import AddressSpace, Architecture
from fiit.arch_ctypes import CDataMemMapper

from fiit.emu.emulator import Emulator
from fiit.dbg.debugger import Debugger
from fiit.mmio_trace import MmioTrace, MmioDbg
from fiit.emu.arch_arm.arm import ArchArm
from fiit.emu.hw.pl190 import ArmPl190
from fiit.emu.hw.pl190_int_gen import Pl190IntGenerator
from fiit.hooking_engine.engine import HookingEngine
from fiit.ftrace.ftrace import Ftrace



CTX_UNICORN_UC = ContextObject('unicorn_uc', unicorn.Uc)
CTX_SHELL = ContextObject('shell', Shell)
CTX_EMULATOR_ADDRESS_SPACE = ContextObject('emulator_address_space', AddressSpace)
CTX_EMULATOR_ARCH = ContextObject('emulator_arch', Architecture)
CTX_CDATA_MEMORY_MAPPER = ContextObject('cdata_memory_mapper', CDataMemMapper)
CTX_EMULATOR = ContextObject('emulator', Emulator)
CTX_DBG = ContextObject('debugger', Debugger)
CTX_MMIO_TRACER = ContextObject('mmio_tracer', MmioTrace)
CTX_MMIO_DBG = ContextObject('mmio_dbg', MmioDbg)
CTX_ARCH_ARM = ContextObject('arch_arm', ArchArm)
CTX_ARM_PL190 = ContextObject('arm_pl190', ArmPl190)
CTX_PL190_INT_GENERATOR = ContextObject('pl190_int_generator', Pl190IntGenerator)
CTX_HOOKING_ENGINE = ContextObject('hooking_engine', HookingEngine)
CTX_FTRACE = ContextObject('ftrace', Ftrace)
