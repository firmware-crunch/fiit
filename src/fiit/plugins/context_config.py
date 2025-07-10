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

from fiit.core.plugin import ContextObject
from fiit.core.shell import Shell
from fiit.core.emulator_types import AddressSpace
from fiit.core.emulator_types import Architecture
from fiit.core.ctypes import CDataMemMapper

from fiit.unicorn.emulator import UnicornEmulator
from fiit.unicorn.dbg import UnicornDbg
from fiit.unicorn.mmio_tracer import UnicornMmioTracer, UnicornMmioDbg
from fiit.unicorn.arm.arm_generic_core import UnicornArmGenericCore
from fiit.unicorn.arm.pl190 import UnicornArmPl190
from fiit.unicorn.arm.pl190_round_robin_int_gen import UnicornPl190RoundRobinIntGenerator
from fiit.unicorn.function_hooking_engine import UnicornFunctionHookingEngine
from fiit.unicorn.function_tracer import UnicornFunctionTracer


UNICORN_UC = ContextObject('unicorn_uc', unicorn.Uc)

SHELL = ContextObject('shell', Shell)
EMULATOR_ADDRESS_SPACE = ContextObject('emulator_address_space', AddressSpace)
EMULATOR_ARCH = ContextObject('emulator_arch', Architecture)
CDATA_MEMORY_MAPPER = ContextObject('cdata_memory_mapper', CDataMemMapper)

UNICORN_EMULATOR = ContextObject('unicorn_emulator', UnicornEmulator)
UNICORN_DBG = ContextObject('unicorn_dbg', UnicornDbg)
UNICORN_MMIO_TRACER = ContextObject('unicorn_mmio_tracer', UnicornMmioTracer)
UNICORN_MMIO_DBG = ContextObject('unicorn_mmio_dbg', UnicornMmioDbg)
UNICORN_ARM_GENERIC_CORE = ContextObject('unicorn_arm_generic_core', UnicornArmGenericCore)
UNICORN_ARM_PL190 = ContextObject('unicorn_arm_pl190', UnicornArmPl190)
UNICORN_PL190_ROUND_ROBIN_INT_GENERATOR = ContextObject('unicorn_pl190_round_robin_int_generator', UnicornPl190RoundRobinIntGenerator)
FUNCTION_HOOKING_ENGINE = ContextObject('function_hooking_engine', UnicornFunctionHookingEngine)
FUNCTION_TRACER = ContextObject('function_tracer', UnicornFunctionTracer)
