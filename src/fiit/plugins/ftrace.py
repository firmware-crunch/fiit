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

from fiit.ctypesarch import CDataMemMapper
from fiit.hooking import HookingEngine
from fiit.plugin import FiitPlugin, FiitPluginContext
from fiit.utils import pkg_object_loader
from fiit.ftrace import (
    Ftrace, predicate_is_func_trace_ext, predicate_is_log_format_ext,
    FUNC_TRACER_EXT_DIR, FUNC_TRACE_LOG_BIN, FUNC_TRACE_LOG_PYTHON
)

from . import CTX_REQ_HOOKING, CTX_FTRACER, CTX_REQ_CDATA


def _get_filter_ext_conf_schema() -> dict:
    schema = dict()
    for ext in pkg_object_loader(FUNC_TRACER_EXT_DIR,
                                 predicate_is_func_trace_ext):
        schema.update(getattr(ext, 'FILTER_CONFIG_SCHEMA'))
    return schema


def _get_log_format_ext_conf_schema() -> dict:
    schema = dict()
    for ext in pkg_object_loader(FUNC_TRACER_EXT_DIR,
                                 predicate_is_log_format_ext):
        schema.update(getattr(ext, 'FORMATTER_CONFIG_SCHEMA'))
    return schema


_log_output_value_mapping = {
    'python_logging': FUNC_TRACE_LOG_PYTHON,
    'binary': FUNC_TRACE_LOG_BIN
}


def normalize_log_output_type(value: dict) -> int:
    return _log_output_value_mapping[value]


class PluginFtrace(FiitPlugin):
    NAME = 'plugin_ftrace'
    REQUIREMENTS = [CTX_REQ_HOOKING]
    OPTIONAL_REQUIREMENTS = [CTX_REQ_CDATA]
    OBJECTS_PROVIDED = [CTX_FTRACER]
    CONFIG_SCHEMA = {
        NAME: {
            'type': 'dict',
            'keysrules': {'type': 'string'},
            'valuesrules': {
                'type': 'dict',
                'schema': {
                    'cdata_types_files': {
                        'type': 'list',
                        'schema': {'type': 'string'},
                        'required': False
                    },
                    'function_data_files': {
                        'type': 'list',
                        'schema': {'type': 'string'},
                        'required': False
                    },
                    'log_output_type': {
                        'type': 'string',
                        'allowed': list(_log_output_value_mapping.keys()),
                        'coerce': normalize_log_output_type,
                        'required': False
                    },
                    'log_return_value': {
                        'type': 'boolean', 'required': False},

                    'format_include_arguments': {
                        'type': 'boolean', 'required': False},
                    'format_arg_ptr_dereference': {
                        'type': 'boolean', 'required': False},
                    'format_arg_char_ptr_as_string': {
                        'type': 'boolean', 'required': False},
                    'format_arg_char_ptr_as_string_decoder': {
                        'type': 'string', 'allowed': ['ascii'], 'required': False},
                    'format_arg_char_ptr_as_string_with_fixed_len': {
                        'type': 'boolean', 'required': False},
                    'format_arg_char_ptr_as_string_fixed_len': {
                        'type': 'integer', 'required': False},
                    'format_extensions': {
                        'type': 'dict',
                        'schema': _get_log_format_ext_conf_schema(),
                        'required': False
                    },

                    'filter_include_function': {
                        'type': 'list', 'schema': {'type': 'list'}, 'required': False},
                    'filter_exclude_function': {
                        'type': 'list', 'schema': {'type': 'list'}, 'required': False},
                    'filter_include_return_address': {
                        'type': 'list', 'schema': {'type': 'list'}, 'required': False},
                    'filter_exclude_return_address': {
                        'type': 'list', 'schema': {'type': 'list'}, 'required': False},
                    'filter_extensions': {
                        'type': 'dict',
                        'schema': _get_filter_ext_conf_schema(),
                        'required': False
                    },
                }
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
        tracer: List[Ftrace] = []
        hook_engines = cast(
            List[HookingEngine], requirements[CTX_REQ_HOOKING.name]
        )
        cdata_mappers: List[CDataMemMapper] = optional_requirements.get(
            CTX_REQ_CDATA.name, []
        )

        for cpu_name, config in plugin_config.items():
            hook_engine_found = False

            for engine in hook_engines:
                if engine.cpu.dev_name == cpu_name:
                    data = {
                        'cpu': engine.cpu,
                        'hooking_engine': engine,
                        'plugin_context': plugins_context.context
                    }

                    for cdata_mmap in cdata_mappers:
                        if cdata_mmap.mem is engine.cpu.mem:
                            data['cdata'] = cdata_mmap

                    ftracer = Ftrace(engine, **config, data=data)
                    tracer.append(ftracer)
                    hook_engine_found = True

            if not hook_engine_found:
                raise RuntimeError(
                    f'hooking engine not found for cpu "{cpu_name}"'
                )

        plugins_context.add(CTX_FTRACER.name, tracer)
