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

from fiit.unicorn.arm.pl190_round_robin_int_gen import (
    UnicornPl190RoundRobinIntGenerator)
from fiit.unicorn.emulator import (
    UnicornEmulator, EXEC_QUANTUM_UNIT_INSN, EXEC_QUANTUM_UNIT_US,
    EXEC_QUANTUM_UNIT_BLOCK)
import fiit.plugins.context_config as ctx_conf
from fiit.core.plugin import FiitPlugin, FiitPluginContext


class PluginUnicornArmPl190IntGenerator(FiitPlugin):
    NAME = 'plugin_unicorn_arm_pl190_round_robin_int_generator'
    REQUIREMENTS = [
        ctx_conf.UNICORN_ARM_GENERIC_CORE.as_require(),
        ctx_conf.UNICORN_ARM_PL190.as_require()]
    OPTIONAL_REQUIREMENTS = [
        ctx_conf.UNICORN_EMULATOR.as_require()]
    OBJECTS_PROVIDED = [
        ctx_conf.UNICORN_PL190_ROUND_ROBIN_INT_GENERATOR]
    CONFIG_SCHEMA = {
        NAME: {
            'type': 'dict',
            'required': False,
            'schema': {
                'exec_quantum_unit': {
                    'type': 'string',
                    'allowed': ['instruction', 'block', 'us']
                },
                'exec_quantum': 'DEF_SIZE',
                'log': {'type': 'boolean', 'default': False}
            }
        }
    }

    _EXEC_QUANTUM_UNIT = {
        'instruction': EXEC_QUANTUM_UNIT_INSN,
        'us': EXEC_QUANTUM_UNIT_US,
        'block': EXEC_QUANTUM_UNIT_BLOCK
    }

    def plugin_load(
        self,
        init_context: FiitPluginContext,
        plugin_config: dict,
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ):
        rrig = UnicornPl190RoundRobinIntGenerator(
            requirements[ctx_conf.UNICORN_ARM_GENERIC_CORE.name],
            requirements[ctx_conf.UNICORN_ARM_PL190.name])

        if emu := optional_requirements.get(ctx_conf.UNICORN_EMULATOR.name):
            emu = cast(UnicornEmulator, emu)
            emu.set_interrupts(
                rrig.gen_interrupt,
                self._EXEC_QUANTUM_UNIT[plugin_config['exec_quantum_unit']],
                plugin_config['exec_quantum'])
        # else:
        #     rrig.install_standalone_round_robin_loop(
        #         self._EXEC_QUANTUM_UNIT[plugin_config['exec_quantum_unit']],
        #         plugin_config['exec_quantum'])

        init_context.add(ctx_conf.UNICORN_PL190_ROUND_ROBIN_INT_GENERATOR.name, rrig)
