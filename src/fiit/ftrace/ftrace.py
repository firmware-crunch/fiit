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

import logging
import os
from typing import Any, Dict, Union, List, Tuple

from ..hooking_engine.cc_base import FuncArg, ReturnValue
from ..hooking_engine.engine import (
    HookingEngine, FuncHookMeta, HookingContext
)

from .log_formatter import FtraceLogFormatter
from .filter import FunctionRuntimeFilter

FUNC_TRACER_EXT_DIR = os.path.abspath(
    f'{os.path.dirname(os.path.realpath(__file__))}/ext'
)


FUNC_TRACE_LOG_PYTHON = 1
FUNC_TRACE_LOG_BIN = 2


class Ftrace:

    def __init__(
        self,
        hooking_engine: HookingEngine,

        cdata_types_files: List[str] = None,
        function_data_files: List[str] = None,

        log_output_type: int = FUNC_TRACE_LOG_PYTHON,
        log_calling_arguments: bool = True,
        log_return_value: bool = True,
        log_return: bool = True,

        format_include_arguments: bool = True,
        format_include_return_value: bool = True,
        format_arg_ptr_dereference: bool = True,
        format_arg_char_ptr_as_string: bool = True,
        format_arg_char_ptr_as_string_decoder: str = 'ascii',
        format_arg_char_ptr_as_string_with_fixed_len: bool = False,
        format_arg_char_ptr_as_string_fixed_len: int = 64,
        format_extensions: Dict[str, Any] = None,

        filter_include_function: List[Union[str, int]] = None,
        filter_exclude_function: List[Union[str, int]] = None,

        filter_include_return_address: List[int] = None,
        filter_exclude_return_address: List[int] = None,
        filter_extensions: List[Tuple[str, Dict[str, Any]]] = None,

        data: Dict[str, Any] = None
    ):
        logger_name = f'fiit.ftrace.dev@{hooking_engine.cpu.dev_name}'
        self._log = logging.getLogger(logger_name)

        ########################################################################
        # Hooking engine
        ########################################################################
        self._hooking_engine = hooking_engine

        ########################################################################
        # C data file type registration
        ########################################################################
        if cdata_types_files:
            for file in cdata_types_files:
                self._hooking_engine.register_cdata_types_file(file)

        ########################################################################
        # Function file registration
        ########################################################################
        if function_data_files:
            for file in function_data_files:
                self._hooking_engine.register_function_file(file)

        ########################################################################
        # Log configuration
        ########################################################################
        if log_output_type == FUNC_TRACE_LOG_PYTHON:
            self._pre_hook_logger = self._pre_hook_log_py
            self._post_hook_logger = self._post_hook_log_py
        elif log_output_type == FUNC_TRACE_LOG_BIN:
            self._pre_hook_logger = self._pre_hook_log_bin
            self._post_hook_logger = self._post_hook_log_bin

        self._py_log_formatter = FtraceLogFormatter(
            format_include_arguments,
            format_include_return_value,
            format_arg_ptr_dereference,
            format_arg_char_ptr_as_string,
            format_arg_char_ptr_as_string_decoder,
            format_arg_char_ptr_as_string_with_fixed_len,
            format_arg_char_ptr_as_string_fixed_len,
            format_extensions,
            data)

        ########################################################################
        # Pre Function filter
        ########################################################################
        for func_spec in self._hooking_engine.func_spec:
            if (filter_exclude_function
                    and (func_spec.name in filter_exclude_function
                         or func_spec.address in filter_exclude_function)):
                continue

            elif (filter_include_function
                    and (func_spec.name in filter_include_function
                         or func_spec.address in filter_include_function)):
                self._hooking_engine.register_hook_meta(
                    FuncHookMeta(
                        'pre', self._pre_hook, func_spec.address,
                        cc_get_args=(True if log_calling_arguments else False)))

                if log_return:
                    self._hooking_engine.register_hook_meta(
                        FuncHookMeta(
                            'post', self._post_hook, func_spec.address,
                            cc_get_ret_val=(True if log_return_value else False)
                        ))

            elif not filter_include_function:
                self._hooking_engine.register_hook_meta(
                    FuncHookMeta(
                        'pre', self._pre_hook, func_spec.address,
                        cc_get_args=(True if log_calling_arguments else False)))

                if log_return:
                    self._hooking_engine.register_hook_meta(
                        FuncHookMeta(
                            'post', self._post_hook, func_spec.address,
                            cc_get_ret_val=(True if log_return_value else False)
                        ))

        ########################################################################
        # Runtime function filter
        ########################################################################
        self._function_runtime_filter = FunctionRuntimeFilter(
            filter_include_return_address,
            filter_exclude_return_address,
            filter_extensions,
            data)

    def _pre_hook_log_py(
        self, ctx: HookingContext, *args: Union[FuncArg, None]
    ):
        self._log.info(self._py_log_formatter.pre_log(ctx, *args))

    def _post_hook_log_py(
        self, ctx: HookingContext, return_value: Union[ReturnValue, None]
    ):
        self._log.info(self._py_log_formatter.post_log(ctx, return_value))

    def _pre_hook_log_bin(
        self, ctx: HookingContext, *args: Union[FuncArg, None]
    ):
        pass

    def _post_hook_log_bin(
        self, ctx: HookingContext, return_value: Union[ReturnValue, None]
    ):
        pass

    def _pre_hook(self, ctx: HookingContext, *args: Union[FuncArg, None]):
        if self._function_runtime_filter.predicate(ctx):
            self._pre_hook_logger(ctx, *args)

    def _post_hook(
        self, ctx: HookingContext, return_value: Union[ReturnValue, None]
    ):
        if self._function_runtime_filter.predicate(ctx):
            self._post_hook_logger(ctx, return_value)
