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

from typing import Dict, Any, cast

import unicorn
from unicorn.unicorn_const import UC_HOOK_INTR

from fiit.emu.hw.pl190 import ArmPl190
from fiit.emu.emu_types import AddressSpace
from fiit.plugin import FiitPlugin, FiitPluginContext

from . import (
    CTX_UNICORN_UC, CTX_ARCH_ARM, CTX_EMULATOR_ADDRESS_SPACE,
    CTX_ARM_PL190
)


class PluginArmPl190(FiitPlugin):
    NAME = 'plugin_arm_pl190'
    REQUIREMENTS = [
        CTX_UNICORN_UC.as_require()]
    OPTIONAL_REQUIREMENTS = [
        CTX_ARCH_ARM.as_require(),
        CTX_EMULATOR_ADDRESS_SPACE.as_require()]
    OBJECTS_PROVIDED = [
        CTX_ARM_PL190]
    CONFIG_SCHEMA = {
        NAME: {
            'type': 'dict',
            'schema': {
                'base_address': 'DEF_INT64',
            }
        }
    }

    def plugin_load(
        self,
        init_context: FiitPluginContext,
        plugin_config: dict,
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ):
        uc = cast(unicorn.Uc, requirements[CTX_UNICORN_UC.name])
        pl190_base_addr = plugin_config['base_address']
        auto_map = True

        for begin, end, _ in uc.mem_regions():
            if (pl190_base_addr >= begin
                    and pl190_base_addr+ArmPl190.MEM_MAP_SIZE-1 <= end):
                auto_map = False

        pl190 = ArmPl190(uc, pl190_base_addr, auto_map)
        uc.hook_add(UC_HOOK_INTR, pl190.reset_handler, begin=1, end=0)

        if cpu := optional_requirements.get(CTX_ARCH_ARM.name, None):
            pl190.set_nvicfiq_high_callback(cpu.set_fiq_mode)
            pl190.set_nvicirq_high_callback(cpu.set_irq_mode)

        if ((address_space := optional_requirements.get(CTX_EMULATOR_ADDRESS_SPACE.name))
                and auto_map):
            address_space = cast(AddressSpace, address_space)
            address_space.memory_regions.append(pl190.mem_region)

        init_context.add(CTX_ARM_PL190.name, pl190)
