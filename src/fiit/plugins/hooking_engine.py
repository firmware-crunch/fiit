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

from typing import Any, Dict, cast, List

from fiit.machine import Machine
from fiit.arch_ctypes import CTYPES_TRANSLATOR_FLAVOR
from fiit.hooking_engine.engine import HookingEngine
from fiit.plugin import FiitPlugin, FiitPluginContext

from . import CTX_REQ_MACHINE, CTX_HOOKING_ENGINE

# ==============================================================================


class PluginHookingEngine(FiitPlugin):
    NAME = 'plugin_hooking_engine'
    REQUIREMENTS = [CTX_REQ_MACHINE]
    OBJECTS_PROVIDED = [CTX_HOOKING_ENGINE]
    CONFIG_SCHEMA = {
        NAME: {
            'type': 'dict',
            'keysrules': {'type': 'string'},
            'valuesrules': {
                'type': 'dict',
                'schema': {
                    'function_data_files': {
                        'type': 'list',
                        'schema': {'type': 'string'}, 'default': []
                    },
                    'python_hook_files': {
                        'type': 'list',
                        'schema': {'type': 'string'}, 'default': []
                    },
                    'ctypes_options': {'type': 'dict', 'default': {}},
                    'ctypes_flavor': {
                        'type': 'string',
                        'allowed': ['pycparser', 'pycparserext_gnu'],
                        'default': 'pycparser'
                    },
                    'cdata_types_files': {
                        'type': 'list',
                        'schema': {'type': 'string'}, 'default': []
                    },
                    'default_cc_options': {'type': 'dict', 'default': {}},
                },
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
        engines: List[HookingEngine] = []
        machine = cast(Machine, requirements[CTX_REQ_MACHINE.name])

        for cpu_name, config in plugin_config.items():
            cpu = machine.get_device_cpu(cpu_name)

            ctypes_flavor = CTYPES_TRANSLATOR_FLAVOR[config['ctypes_flavor']]

            he = HookingEngine(
                cpu,
                ctypes_options=config['ctypes_options'],
                ctypes_flavor=ctypes_flavor,
                default_cc_options=config['default_cc_options'],
                context_user_data={'plugins_context': plugins_context}
            )

            for cdata_type_file in config['cdata_types_files']:
                he.register_cdata_types_file(cdata_type_file)

            for function_data_file in config.get('function_data_files'):
                he.register_function_file(function_data_file)

            for python_hook_file in config.get('python_hook_files'):
                he.register_hook_functions_from_file(python_hook_file)
                he.register_hook_handler_from_file(python_hook_file)

            engines.append(he)

        plugins_context.add(CTX_HOOKING_ENGINE.name, engines)
