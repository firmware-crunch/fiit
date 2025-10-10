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
    'PluginDebugger'
]

from typing import List, cast, Any, Dict

from fiit.machine import Machine
from fiit.dbg import DebuggerFactory, Debugger
from fiit.plugin import FiitPluginContext, FiitPlugin

from . import CTX_REQ_MACHINE, CTX_MACHINE, CTX_DBG

# ==============================================================================


class PluginDebugger(FiitPlugin):
    NAME = 'plugin_debugger'
    REQUIREMENTS = [CTX_REQ_MACHINE]
    OBJECTS_PROVIDED = [CTX_DBG]
    CONFIG_SCHEMA = {
        NAME: {
            'type': 'dict',
            'keysrules': {'type': 'string'},
            'valuesrules': {
                'type': 'dict',
                'schema': {}
            }
        }
    }

    def plugin_load(
        self,
        plugins_context: FiitPluginContext,
        plugin_config: dict,
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ):
        dbg_list: List[Debugger] = []
        machine = cast(Machine, requirements[CTX_MACHINE.name])

        for cpu_name, config in plugin_config.items():
            cpu = machine.get_device_cpu(cpu_name)
            dbg = DebuggerFactory.get(cpu)
            dbg_list.append(dbg)
            self.log.info(f'Attach new debugger instance to dev@{cpu.dev_name}')

        plugins_context.add(CTX_DBG.name, dbg_list)
