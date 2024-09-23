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

import inspect
import ctypes
import logging
import os
from typing import Any, Dict, Union, List, Tuple, cast

from unicorn import Uc

from fiit.core.dev_utils import pkg_object_loader, inherits_from
from fiit.core.ctypes.ctypes_base import (
    CBaseType, DataPointerBase, CodePointerBase, IntegralType, FloatType,
    Char, Bool, _Bool)
from fiit.core.cc_base import FuncArg, ReturnValue
from .function_hooking_engine import (
    UnicornFunctionHookingEngine, FuncHookMeta, HookingContext)


FUNC_TRACER_EXT_DIR = os.path.abspath(
    f'{os.path.dirname(os.path.realpath(__file__))}'
    f'/function_tracer_ext')


################################################################################
# Runtime Function Filter
################################################################################


class FunctionFilterExtBase:
    FILTER_NAME: str
    FILTER_CONFIG_SCHEMA: dict

    def filter_ext_load(self, ext_ctx: Dict[str, Any], ext_config: dict):
        raise NotImplementedError('fixme')

    def ext_filter(self, ctx: HookingContext) -> bool:
        raise NotImplementedError('fixme')


def predicate_is_func_trace_ext(obj: any) -> bool:
    return (True if (inspect.isclass(obj)
                     and inherits_from(obj, FunctionFilterExtBase))
            else False)


class FilterExt:
    pass


class FunctionRuntimeFilter:
    FILTER_LAMBDA_WRAPPER = 'lambda self, ctx: '
    FILTER_EXP_INCLUDE_RET_ADDR = \
        '(ctx.return_address in self._filter_include_return_address)'
    FILTER_EXP_EXCLUDE_RET_ADDR = \
        '(ctx.return_address not in self._filter_exclude_return_address)'
    FILTER_EXP_EXT = '(self.filter_ext.{filter_ext_func}(ctx))'

    def __init__(
        self,
        filter_include_return_address: List[int] = None,
        filter_exclude_return_address: List[int] = None,
        filter_extensions: Dict[str, Dict[str, Any]] = None,
        data: Dict[str, Any] = None
    ):
        self._filter_include_return_address = filter_include_return_address
        self._filter_exclude_return_address = filter_exclude_return_address

        runtime_filter = []

        if filter_include_return_address:
            runtime_filter.append(self.FILTER_EXP_INCLUDE_RET_ADDR)

        if filter_exclude_return_address:
            runtime_filter.append(self.FILTER_EXP_EXCLUDE_RET_ADDR)

        if filter_extensions:
            ext_path = os.path.abspath(
                f'{os.path.dirname(os.path.realpath(__file__))}'
                f'/function_tracer_ext')
            filter_ext_load = pkg_object_loader(ext_path,
                                                predicate_is_func_trace_ext)
            filter_ext_load = cast(List[FunctionFilterExtBase], filter_ext_load)
            filter_ext_load = {c.FILTER_NAME: c for c in filter_ext_load}

            self.filter_ext = FilterExt()

            for ext_name, ext_conf in filter_extensions.items():
                filter_ext_class = filter_ext_load[ext_name]
                filter_ext_inst = cast(FunctionFilterExtBase, filter_ext_class())
                filter_ext_inst.filter_ext_load(data, ext_conf)
                setattr(self.filter_ext, filter_ext_inst.FILTER_NAME,
                        filter_ext_inst.ext_filter)
                filter_ext_exp = self.FILTER_EXP_EXT.format(
                    filter_ext_func=filter_ext_inst.FILTER_NAME)
                runtime_filter.append(filter_ext_exp)

        if not runtime_filter:
            self._runtime_filter_predicate = eval(
                f'{self.FILTER_LAMBDA_WRAPPER} {"True"}')
        else:
            self._runtime_filter_predicate = eval(
                f'{self.FILTER_LAMBDA_WRAPPER} {" and ".join(runtime_filter)}')

    def predicate(self, ctx: HookingContext) -> bool:
        return self._runtime_filter_predicate(self, ctx)


################################################################################
# Python log formatter
################################################################################

class LogFormatterExtBase:
    FORMATTER_NAME: str
    FORMATTER_CONFIG_SCHEMA: dict

    def formatter_ext_load(self, ext_ctx: Dict[str, Any], ext_config: dict):
        raise NotImplementedError('fixme')

    def ext_python_log(self, ctx: HookingContext, log: str) -> str:
        raise NotImplementedError('fixme')


def predicate_is_log_format_ext(obj: any) -> bool:
    return (True if (inspect.isclass(obj)
                     and inherits_from(obj, LogFormatterExtBase))
            else False)


class PythonLogFormatter:
    def __init__(
        self,
        include_arguments: bool = True,
        include_return_value: bool = True,
        arg_ptr_dereference: bool = True,
        arg_char_ptr_as_string: bool = True,
        arg_char_ptr_as_string_decoder: str = 'ascii',
        arg_char_ptr_as_string_with_fixed_len: bool = False,
        arg_char_ptr_as_string_fixed_len: int = 64,
        # arg_struct_ptr_field_recursive: bool = True,
        # arg_struct_ptr_field_recursive_depth: int = 1,
        format_extensions: Dict[str, Any] = None,
        data: Dict[str, Any] = None
    ):
        self._include_arguments = include_arguments
        self._include_return_value = include_return_value
        self._cdata_to_str_args = (
            arg_ptr_dereference,
            arg_char_ptr_as_string,
            arg_char_ptr_as_string_decoder,
            arg_char_ptr_as_string_with_fixed_len,
            arg_char_ptr_as_string_fixed_len)

        self._format_extensions: List[LogFormatterExtBase] = []
        if format_extensions:
            ext_path = os.path.abspath(
                f'{os.path.dirname(os.path.realpath(__file__))}'
                f'/function_tracer_ext')
            format_ext_load = pkg_object_loader(ext_path,
                                                predicate_is_log_format_ext)
            format_ext_load = cast(List[LogFormatterExtBase], format_ext_load)
            format_ext_load = {c.FORMATTER_NAME: c for c in format_ext_load}

            for ext_name, ext_conf in format_extensions.items():
                filter_ext_class = format_ext_load[ext_name]
                filter_ext_inst = cast(LogFormatterExtBase, filter_ext_class())
                filter_ext_inst.formatter_ext_load(data, ext_conf)
                self._format_extensions.append(filter_ext_inst)

    @staticmethod
    def _get_str_ascii(
        uc: Uc, address: int, max_terminator_search=512
    ) -> Union[str, None]:
        for i in range(0, max_terminator_search-1):
            if bytes(uc.mem_read(address+i, 1)) == b'\x00':
                return bytes(uc.mem_read(address, i)).decode('ascii')
        return None

    def cdata_to_str(
        self,
        uc: Uc,
        cdata: CBaseType,
        ptr_dereference: bool = True,
        char_ptr_as_string: bool = True,
        char_ptr_as_string_decoder: str = 'ascii',
        char_ptr_as_string_with_fixed_len: bool = False,
        char_ptr_as_string_fixed_len: int = 64,

    ) -> str:
        if (issubclass(type(cdata), IntegralType)
                or issubclass(type(cdata), FloatType)):
            if (issubclass(type(cdata), _Bool)
                    or issubclass(type(cdata), Bool)):
                return 'TRUE' if cdata.value == 1 else 'FALSE'
            else:
                return f'{cdata.value:#x}'

        elif issubclass(type(cdata), DataPointerBase):
            if (char_ptr_as_string and issubclass(cdata.type, Char)
                    and cdata.target_address):
                c_string = ''

                if char_ptr_as_string_with_fixed_len:
                    if char_ptr_as_string_decoder == 'ascii':
                        c_string = str(bytes(self._he._uc.mem_read(
                            cdata.target_address, char_ptr_as_string_fixed_len)
                        ).split(b'\x00')[0])

                else:
                    if char_ptr_as_string_decoder == 'ascii':
                        c_string = self._get_str_ascii(uc, cdata.target_address)

                if c_string:
                    c_string = c_string.replace('\n', '\\n')
                    c_string = c_string.replace('\r', '\\r')
                    return f'{cdata.target_address:#x} ' \
                           f'=> (size={len(c_string)+1}) "{c_string}"'

            elif not cdata.is_null():
                reference_str = ''
                if (ptr_dereference
                        and (issubclass(type(cdata), IntegralType)
                             or issubclass(type(cdata), FloatType))):
                    reference = cdata.type()
                    reference.raw = uc.mem_read(
                        cdata.target_address, ctypes.sizeof(cdata.type))
                    reference_str = f' = {reference.value:#x}'

                return f'{cdata.target_address:#x}{reference_str}'

            else:
                return '<null>'

        elif issubclass(type(cdata), CodePointerBase):
            if cdata.target_address:
                return f'{cdata.target_address:#x}'
            else:
                return '<null>'

        return ''

    def pre_log(self, ctx: HookingContext, *args: Union[FuncArg, None]) -> str:
        args_string = ''
        if self._include_arguments and args:
            args_string = '\n'.join([
                f'    arg {i}: '
                f'{self.cdata_to_str(ctx.uc, a.value, *self._cdata_to_str_args)}'
                f' ({a.value._name_}{" " if a.name else ""}'
                f'{a.name if a.name else ""})'
                for i, a in enumerate(args)])
            args_string = f'\n{args_string}'

        log_str = (
            f'{ctx.func_spec.name}@{ctx.func_spec.address:#x} '
            f'from {ctx.return_address:#x} {args_string}')

        for ext_class in self._format_extensions:
            log_str = ext_class.ext_python_log(ctx, log_str)

        return log_str

    def post_log(
            self, ctx: HookingContext, return_value: Union[ReturnValue, None]
    ) -> str:
        ret_val_str = ''
        if return_value and self._include_return_value:
            ret_val_str = self.cdata_to_str(
                ctx.uc, return_value.value, *self._cdata_to_str_args)

        if ret_val_str:
            ret_val_str = f' : return value = {ret_val_str}'

        log_str = (
            f'{ctx.func_spec.name}@{ctx.func_spec.address:#x} '
            f'return to {ctx.return_address:#x}{ret_val_str}')

        for ext_handler in self._format_extensions:
            log_str = ext_handler.ext_python_log(ctx, log_str)

        return log_str


################################################################################
# Function Tracer
################################################################################

FUNC_TRACER_LOG_PYTHON = 1
FUNC_TRACER_LOG_BIN = 2


class UnicornFunctionTracer:
    LOGGER_NAME = 'fiit.unicorn_function_tracer'

    def __init__(
        self,
        hooking_engine: UnicornFunctionHookingEngine,

        cdata_types_files: List[str] = None,
        function_data_files: List[str] = None,

        log_output_type: int = FUNC_TRACER_LOG_PYTHON,
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
        self._log = logging.getLogger(self.LOGGER_NAME)

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
        if log_output_type == FUNC_TRACER_LOG_PYTHON:
            self._pre_hook_logger = self._pre_hook_log_py
            self._post_hook_logger = self._post_hook_log_py
        elif log_output_type == FUNC_TRACER_LOG_BIN:
            self._pre_hook_logger = self._pre_hook_log_bin
            self._post_hook_logger = self._post_hook_log_bin

        self._py_log_formatter = PythonLogFormatter(
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
