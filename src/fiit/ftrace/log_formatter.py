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
import os
from typing import Any, Dict, Union, List, cast

from ..machine import DeviceCpu
from ..dev_utils import pkg_object_loader, inherits_from
from ..arch_ctypes.base_types import (
    CBaseType, DataPointerBase, CodePointerBase, IntegralType, FloatType,
    Char, Bool, _Bool
)
from ..hooking.cc import FuncArg, ReturnValue
from ..hooking.engine import HookingContext


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


class FtraceLogFormatter:
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
                f'{os.path.dirname(os.path.realpath(__file__))}/ext'
            )
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
        cpu: DeviceCpu, address: int, max_terminator_search=512
    ) -> Union[str, None]:
        for i in range(0, max_terminator_search-1):
            if bytes(cpu.mem.read(address+i, 1)) == b'\x00':
                return bytes(cpu.mem.read(address, i)).decode('ascii')
        return None

    def cdata_to_str(
        self,
        cpu: DeviceCpu,
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
                        c_string = str(bytes(cpu.mem.read(
                            cdata.target_address, char_ptr_as_string_fixed_len)
                        ).split(b'\x00')[0])

                else:
                    if char_ptr_as_string_decoder == 'ascii':
                        c_string = self._get_str_ascii(cpu, cdata.target_address)

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
                    reference.raw = cpu.mem.read(
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
                f'{self.cdata_to_str(ctx.cpu, a.value, *self._cdata_to_str_args)}'
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
                ctx.cpu, return_value.value, *self._cdata_to_str_args)

        if ret_val_str:
            ret_val_str = f' : return value = {ret_val_str}'

        log_str = (
            f'{ctx.func_spec.name}@{ctx.func_spec.address:#x} '
            f'return to {ctx.return_address:#x}{ret_val_str}')

        for ext_handler in self._format_extensions:
            log_str = ext_handler.ext_python_log(ctx, log_str)

        return log_str
