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

from typing import Any,  Dict

from fiit.core.ctypes import CTYPES_TRANSLATOR_FLAVOR
from fiit.unicorn.function_hooking_engine import UnicornFunctionHookingEngine
import fiit.plugins.context_config as ctx_conf
from fiit.core.plugin import FiitPlugin, FiitPluginContext


class PluginUnicornFunctionHookingEngine(FiitPlugin):
    NAME = 'plugin_unicorn_function_hooking_engine'
    REQUIREMENTS = [
        ctx_conf.UNICORN_UC.as_require()]
    OBJECTS_PROVIDED = [
        ctx_conf.FUNCTION_HOOKING_ENGINE]
    CONFIG_SCHEMA = {
        NAME: {
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

    def plugin_load(
        self,
        plugins_context: FiitPluginContext,
        plugin_config: dict,
        requirements: Dict[str, Any],
        optional_requirements: Dict[str, Any]
    ):
        ctypes_flavor = CTYPES_TRANSLATOR_FLAVOR[plugin_config['ctypes_flavor']]

        he = UnicornFunctionHookingEngine(
            requirements[ctx_conf.UNICORN_UC.name],
            ctypes_options=plugin_config['ctypes_options'],
            ctypes_flavor=ctypes_flavor,
            default_cc_options=plugin_config['default_cc_options'],
            context_user_data={'plugins_context': plugins_context})

        for cdata_type_file in plugin_config['cdata_types_files']:
            he.register_cdata_types_file(cdata_type_file)

        for function_data_file in plugin_config.get('function_data_files'):
            he.register_function_file(function_data_file)

        for python_hook_file in plugin_config.get('python_hook_files'):
            he.register_hook_functions_from_file(python_hook_file)
            he.register_hook_handler_from_file(python_hook_file)

        plugins_context.add(ctx_conf.FUNCTION_HOOKING_ENGINE.name, he)
