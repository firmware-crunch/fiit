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

from typing import Dict, Any

from fiit.unicorn.arm.arm_generic_core import UnicornArmGenericCore
from fiit.unicorn.arm.pl190 import UnicornArmPl190
from fiit.unicorn.arm.pl190_round_robin_int_gen import (
    UnicornPl190RoundRobinIntGenerator)
from fiit.unicorn.emulator import (
    UnicornEmulator, EXEC_QUANTUM_UNIT_INSN, EXEC_QUANTUM_UNIT_US,
    EXEC_QUANTUM_UNIT_BLOCK)
from fiit.core.plugin import (
    FiitPlugin, FiitPluginContext, Requirement,
    PLUGIN_PRIORITY_LEVEL_BUILTIN_L4)


class PluginUnicornArmPl190IntGenerator(FiitPlugin):
    NAME = 'plugin_unicorn_arm_pl190_round_robin_int_generator'
    LOADING_PRIORITY = PLUGIN_PRIORITY_LEVEL_BUILTIN_L4
    REQUIREMENTS = [
        Requirement('unicorn_arm_generic_core', UnicornArmGenericCore),
        Requirement('unicorn_arm_pl190', UnicornArmPl190)
    ]
    OPTIONAL_REQUIREMENTS = [
        Requirement('unicorn_emulator', UnicornEmulator),
    ]
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
            requirements['unicorn_arm_generic_core'],
            requirements['unicorn_arm_pl190'])

        if emu := optional_requirements.get('unicorn_emulator'):
            emu.set_interrupts(
                rrig.gen_interrupt,
                self._EXEC_QUANTUM_UNIT[plugin_config['exec_quantum_unit']],
                plugin_config['exec_quantum'])
        # else:
        #     rrig.install_standalone_round_robin_loop(
        #         self._EXEC_QUANTUM_UNIT[plugin_config['exec_quantum_unit']],
        #         plugin_config['exec_quantum'])

        init_context.add('unicorn_pl190_round_robin_int_generator', rrig)
